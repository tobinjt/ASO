#!/usr/bin/env perl

# $Id$

package ASO::Parser;

use strict;
use warnings;
$| = 1;

use lib q{..};
use ASO::DB;
use Parse::Syslog;
use IO::File;
use Carp;
use Data::Dumper;
use Regexp::Common qw(Email::Address net);
use Storable qw(dclone);
use List::Util qw(shuffle);

# new takes a hash reference of options.
sub new {
    my ($package, $options) = @_;
    my %defaults = (
        sort_rules              => q{normal},
        discard_compiled_regex  => 0,
    );

    if (not exists $options->{data_source}) {
        croak qq{${package}->new: you must provide a data_source\n};
    }

    my $self = {
        %defaults,
        %{$options},
    };

    $self->{dbix} = ASO::DB->connect(
        $self->{data_source},
        {AutoCommit => 0},
    );

    bless $self, $package;
    $self->init_globals();
    return $self;
}

sub init_globals {
    my ($self) = @_;

    # Used in $self->my_warn() and $self->my_die() to report the logfile we're
    # currently parsing.
    $self->{current_logfile}  = q{INITIALISATION};
    $.                        = 0;

    $self->{queueid_regex}    = $self->filter_regex(q{__QUEUEID__});
    $self->{queueid_regex}    = qr/$self->{queueid_regex}/;

    # All mail starts off in %connections, unless submitted locally by
    # sendmail/postgrop, and then moves into %queueids if it gets a queueid.
    $self->{connections}      = {};
    $self->{queueids}         = {};

    # Skip inserting results into the db, because it quadrouples the run time.
    $self->{skip_inserting_results}      = 1;
    # Keep track of the number of inserts uncommitted.
    $self->{num_connections_uncommitted} = 0;

    # Return values for actions
    $self->{ACTION_SUCCESS} = 1;
    $self->{ACTION_FAILURE} = 0;
    # This one returns the new text to be parsed.
    $self->{ACTION_REPARSE} = 2;

    # Actions available to rules.
    $self->{actions} = {
        IGNORE                      => 1,
        CONNECT                     => 1,
        DISCONNECT                  => 1,
        SAVE_BY_PID                 => 1,
        SAVE_BY_QUEUEID             => 1,
        COMMIT                      => 1,
        TRACK                       => 1,
        RESTRICTION_START           => 1,
        MAIL_PICKED_FOR_DELIVERY    => 1,
        PICKUP                      => 1,
        CLONE                       => 1,
    };


    # Used in fixup_connection() to verify data.
    my $mock_result         = $self->get_mock_object(q{Result});
    my $mock_connection     = $self->get_mock_object(q{Connection});
    $self->{required_connection_cols}   = $mock_connection->required_columns();
    $self->{required_result_cols}       = $mock_result->required_columns();
    $self->{nochange_result_cols}       = $mock_result->nochange_columns();

    # Used in save().
    $self->{c_cols_silent_overwrite}    =
        $mock_connection->silent_overwrite_columns();
    $self->{c_cols_silent_discard}      =
        $mock_connection->silent_discard_columns();

    # Used in parse_result_cols().
    $self->{NUMBER_REQUIRED} = 1;
    $self->{result_cols_names}          = $mock_result->result_cols_columns();
    $self->{connection_cols_names}
        = $mock_connection->connection_cols_columns();
    # XXX: Hack!  Figure out how to do this properly.
    $self->{result_cols_names}->{child} = 1;
    # Load the rules, and collate them by program, so that later we'll only try
    # rules for the program that logged the line.
    $self->{rules}            = [$self->load_rules()];
    my %rules_by_program;
    map {        $rules_by_program{$_->{program}} = []; }   @{$self->{rules}};
    map { push @{$rules_by_program{$_->{program}}}, $_; }   @{$self->{rules}};
    $self->{rules_by_program} = \%rules_by_program;
}

# The main loop: most of it is really in parse_line(), to make profiling easier.
sub parse {
    my ($self, $logfile) = @_;
    $self->{current_logfile} = $logfile;
    my $syslog = Parse::Syslog->new($logfile, year => 2006);
    if (not $syslog) {
        croak qq{Failed creating syslog parser for $logfile: $@\n};
    }

    LINE:
    while (my $line = $syslog->next()) {
        if (not exists $self->{rules_by_program}->{$line->{program}}) {
            # It's not from a program we're interested in, skip it.
            next LINE;
        }
        $self->parse_line($line);
    }

    # We bundle database inserts into transactions and commit them in bunches;
    # this gives us a major speed improvement - I think there's a factor of 25
    # runtime increase without this.  If we have an uncommitted bunch remaining
    # we commit them here.
    if ($self->{num_connections_uncommitted}) {
        $self->{dbix}->txn_commit();
    }
}

# Update the rule order in the database so that more frequently hit rules will
# be tried earlier on the next run.
sub update_check_order {
    my ($self) = @_;

    my (%id_map) = map { ($_->{id}, $_) } @{$self->{rules}};
    foreach my $rule ($self->{dbix}->resultset(q{Rule})->search()) {
        # Sometimes a rule won't have been hit; just use the next value
        # in the sequence.
        my $id = $rule->id();
        if (not exists $id_map{$id}) {
            $self->my_warn(qq{update_check_order: Missing rule:},
                dump_rule_from_db($rule));
        } else {
            $rule->rule_order($id_map{$id}->{count});
            $rule->update();
        }
    }
}

# This is how we extract the matched fields from the regex in the rule:
# result_cols and connection_cols specify fields to go in the result and
# connection table respectively.  The format is:
#   hostname = 1; helo = 2; sender = 4;
# i.e. semi-colon seperated assignment statements, with the column name on the
# left and the match from the regex ($1, $2 etc) on the right hand side (no $).
# This is also used to parse result_data and connection_data, hence the relaxed
# regex (.* instead of \d+).
sub parse_result_cols {
    my ($self, $spec, $rule, $number_required, $column_names) = @_;

    my $assignments = {};
    ASSIGNMENT:
    foreach my $assign (split /\s*,\s*/, $spec) {
        if (not length $assign) {
            $self->my_warn(qq{parse_result_cols: empty assignment found in: \n},
                dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        if ($assign !~ m/^\s*(\w+)\s*=\s*(.+)\s*/) {
            $self->my_warn(qq{parse_result_cols: bad assignment found in: \n},
                dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        my ($key, $value) = ($1, $2);
        if ($number_required and $value !~ m/^\d+$/) {
            $self->my_warn(qq{parse_result_cols: $value: not a number in: \n},
                dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        if (not exists $column_names->{$key}) {
            $self->my_die(qq{parse_result_cols: $key: unknown variable in: \n},
                dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        $assignments->{$key} = $value;
    }
    return $assignments;
}


# parse_line() tries each regex against the line until it finds a match, then
# performs the associated action.  That's about it, really - the devil is in the
# details.  This should be rewritten as a proper dispatch system.
sub parse_line {
    my ($self, $line) = @_;
    # Parse::Syslog handles "last line repeated n times" by returning the 
    # same hash as it did on the last call, so any changes we make to the 
    # contents of the hash will be propogated, thus we need to work on a
    # copy of the text of the line from now on.
    my $text = $line->{text};

    RULE:
    foreach my $rule (@{$self->{rules_by_program}->{$line->{program}}}) {
        if ($text !~ m/$rule->{regex}/) {
            next RULE;
        }
        $rule->{count}++;

        # TODO: is there a way I can do this without matching twice??
        my @matches = ($text =~ m/$rule->{regex}/);
        # regex matches start at one, but array indices start at 0.
        # shift the array forward so they're aligned
        unshift @matches, undef;

        if (not exists $self->{actions}->{$rule->{action}}) {
            $self->my_warn(qq{unknown action $rule->{action}\n},
                dump_rule($rule));
            next LINE;
        }

        # Hmmm, I can't figure out how to combine the next two lines.
        my $action = $rule->{action};
        my ($result, @more) = $self->$action($rule, $line, \@matches);

        if ($result eq $self->{ACTION_SUCCESS}) {
            return;
        }
        if ($result eq $self->{ACTION_FAILURE}) {
            $self->my_die(qq{ACTION FAILURE: }, dump_rule($rule),
                dump_line($line), qq{EXTRA INFORMATION: }, @more);
        }
        if ($result eq $self->{ACTION_REPARSE}) {
            $text = $more[0];
            next RULE;
        }
        $self->my_warn(qq{parse_line: unknown action result: $result},
            dump_rule($rule), dump_line($line), qq{EXTRA INFORMATION: }, @more);
    }

    # Last ditch: complain to the user
    print qq{$self->{current_logfile}: $.: $line->{program}: $text\n};
}

# A line we want to ignore
sub IGNORE {
    my ($self, $rule, $line, $matches) = @_;
    return $self->{ACTION_SUCCESS};
}

# Someone has connected to us
sub CONNECT {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->make_connection_by_pid($line);
    delete $connection->{faked};
    # We also want to save the hostname/ip info
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

# Someone has disconnected
sub DISCONNECT {
    my ($self, $rule, $line, $matches) = @_;
    $self->disconnection($line);
    return $self->{ACTION_SUCCESS};
}

# We want to save some information
sub SAVE_BY_PID {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->get_connection_by_pid($line);
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

# We want to save some information
sub SAVE_BY_QUEUEID {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($line, $queueid);
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

# We want to create db entries with the information we've saved.
sub COMMIT {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($line, $queueid);

    $self->save($connection, $line, $rule, $matches);
    $connection->{connection}->{end} = $line->{timestamp};
    $connection->{end} = localtime $line->{timestamp};
    $self->maybe_remove_faked($connection);
    if (exists $connection->{faked}) {
        # I'm assuming that anything marked as faked is waiting to be
        # track()ed, and will be dealt with by committing tracked
        # connections later; mark it so we know it's reached commitment
        # and can be tried again.
        $connection->{commit_reached} = 1;
        return $self->{ACTION_SUCCESS};
    }
    $self->fixup_connection($connection);
    $self->commit_connection($connection);
    $self->delete_by_queueid($connection, $line, $rule);

    return $self->{ACTION_SUCCESS};
}

# We need to track a mail across queueids, typically when mail
# goes through amavisd-new.
sub TRACK {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($line, $queueid);
    $self->save($connection, $line, $rule, $matches);
    $self->track($line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

# We match the start of every restriction line with the same regex,
# to make restriction rules easier to write.
# NOTE: we now try the remainder of the rules too, we don't move
# on to the next line.
sub RESTRICTION_START {
    my ($self, $rule, $line, $matches) = @_;
    my $text = $line->{text};
    $text =~ s/$rule->{regex}//;
    my $connection = $self->get_connection_by_pid($line);
    $self->save($connection, $line, $rule, $matches);
    return ($self->{ACTION_REPARSE}, $text);
}

sub MAIL_PICKED_FOR_DELIVERY {
    my ($self, $rule, $line, $matches) = @_;
    my $connection;
    my $queueid = $self->get_queueid($line, $rule, $matches);
    # Sometimes I need to create connections here because there are
    # tracked connections where the child shows up before the parent
    # logs the tracking line; there's a similar requirement in track().
    if (not exists $self->{queueids}->{$queueid}) {
        $connection = $self->make_connection_by_queueid($line, $queueid);
    } else {
        $connection = $self->get_connection_by_queueid($line, $queueid);
    }
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

sub PICKUP {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid($line, $rule, $matches);
    my $connection = $self->make_connection_by_queueid($line, $queueid);
    $self->save($connection, $line, $rule, $matches);
    delete $connection->{faked};
    return $self->{ACTION_SUCCESS};
}

# Create a deep copy of the connection and save it by queueid so that
# subsequent mails sent on this connection don't clobber each other.
sub CLONE {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->get_connection_by_pid($line);
    my $clone = dclone($connection);
    $self->save($clone, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

sub delete_by_queueid {
    my ($self, $connection, $line, $rule) = @_;

    if (exists $connection->{faked}) {
        $self->my_warn(qq{delete_by_queueid: faked connection: \n},
            dump_connection($connection)
        );
        delete $self->{queueids}->{$connection->{queueid}};
        return;
    }
    if (not exists $connection->{fixuped}) {
        $self->my_warn(qq{delete_by_queueid: non-fixuped connection: \n},
            dump_connection($connection)
        );
        delete $self->{queueids}->{$connection->{queueid}};
        return;
    }
    if (not exists $connection->{committed}) {
        $self->my_warn(qq{delete_by_queueid: uncommitted connection: \n},
            dump_connection($connection)
        );
        delete $self->{queueids}->{$connection->{queueid}};
        return;
    }

    # Let the parent know we're being deleted
    if (exists $connection->{parent}) {
        $self->delete_child_from_parent($connection, $line, $rule);
    }

    # Try to commit any children we can.
    if (exists $connection->{children}) {
        $self->maybe_commit_children($connection, $line, $rule);
    }

    delete $self->{queueids}->{$connection->{queueid}};
}

sub maybe_commit_children {
    my ($self, $parent, $line, $rule) = @_;

    # We check for this in delete_child_from_parent(), so that we don't trample
    # over ourselves in the sequence
    # maybe_commit_children() -> delete_by_queueid() -> delete_child_from_parent()
    $parent->{committing_children} = 1;

    CHILD:
    foreach my $child_queueid (keys %{$parent->{children}}) {
        my $child = $parent->{children}->{$child_queueid};
        if (exists $child->{commit_reached}) {
            # We deliberately don't check for success here; there's nothing we
            # can do at this stage.  These are children which weren't being
            # tracked when they reached commit, so they were still faked - see
            # the check in the COMMIT action.
            $self->fixup_connection($child);
            $self->commit_connection($child);
            $self->delete_by_queueid($child, $line, $rule);
            # This is safe: see perldoc -f each for the guarantee.
            delete $parent->{children}->{$child_queueid};
        }

        # We don't do anything with other children, they'll reach committal by
        # themselves later,
    }

    delete $parent->{committing_children};
}

sub delete_child_from_parent {
    my ($self, $child, $line, $rule) = @_;
    my $child_queueid = $child->{queueid};

    if (not exists $child->{parent}) {
        $self->my_warn(qq{delete_child_from_parent: missing parent:\n},
            dump_connection($child));
        return;
    }

    my $parent = $child->{parent};
    if (not defined $parent) {
        $self->my_warn(qq{delete_child_from_parent: missing parent:\n},
            dump_connection($child));
        return;
    }

    # maybe_commit_children() -> delete_by_queueid() -> delete_child_from_parent()
    # We don't want to trample over maybe_commit_children().
    if (exists $parent->{committing_children}) {
        return;
    }

    if (not exists $parent->{children}
            or not exists $parent->{children}->{$child_queueid}) {
        $self->my_warn(qq{delete_child_from_parent: $child_queueid }
            . qq{not found in \%children:\n},
            qq{parent: },
            dump_connection($parent),
            qq{child: },
            dump_connection($child));
        return;
    }

    delete $parent->{children}->{$child_queueid};
}

sub get_queueid {
    my ($self, $line, $rule, $matches) = @_;

    if (not $rule->{queueid}) {
        $self->my_die(qq{get_queueid: no queueid defined by: } . dump_rule($rule));
    }
    my $queueid     = $matches->[$rule->{queueid}];
    if (not defined $queueid or not $queueid) {
        $self->my_die(qq{get_queueid: no queueid found in: },
            dump_line($line),
            qq{using: },
            dump_rule($rule)
        );
    }
    if ($queueid !~ m/^$self->{queueid_regex}$/o) {
        $self->my_die(qq{get_queueid: queueid $queueid doesn't match __QUEUEID__;\n},
            dump_line($line),
            qq{using: },
            dump_rule($rule)
        );
    }

    return $queueid;
}

sub get_connection_by_queueid {
    my ($self, $line, $queueid, $dont_fake, @extra_messages) = @_;
    if (not exists $self->{queueids}->{$queueid}) {
        $self->my_warn(@extra_messages,
            qq{get_connection_by_queueid: no connection for: },
            dump_line($line)
        );
        if ($dont_fake) {
            return;
        }
        return $self->make_connection_by_queueid($line, $queueid);
    }
    return $self->{queueids}->{$queueid};
}

sub get_connection_by_pid {
    my ($self, $line) = @_;
    if (not exists $self->{connections}->{$line->{pid}}) {
        $self->my_warn(qq{get_connection_by_pid: no connection for: },
            dump_line($line)
        );
        return $self->make_connection_by_pid($line);
    }
    return $self->{connections}->{$line->{pid}};
}

sub load_rules {
    my ($self) = @_;
    my @results;

    foreach my $rule ($self->{dbix}->resultset(q{Rule})->search()) {
        my $rule_hash = {
            id               => $rule->id(),
            name             => $rule->name(),
            description      => $rule->description(),
            rule_order       => $rule->rule_order(),
            priority         => $rule->priority(),
            postfix_action   => $rule->postfix_action(),
            action           => $rule->action(),
            program          => $rule->program(),
            queueid          => $rule->queueid(),
            result_cols      => $self->parse_result_cols($rule->result_cols(),
                                    $rule, $self->{NUMBER_REQUIRED},
                                    $self->{result_cols_names}),
            connection_cols  => $self->parse_result_cols($rule->connection_cols(),
                                    $rule, $self->{NUMBER_REQUIRED},
                                    $self->{connection_cols_names}),
            result_data      => $self->parse_result_cols($rule->result_data(),
                                    $rule, 0,
                                    $self->{result_cols_names}),
            connection_data  => $self->parse_result_cols($rule->connection_data(),
                                    $rule, 0,
                                    $self->{connection_cols_names}),
            count            => 0,
        };

        if (not exists $self->{actions}->{$rule_hash->{action}}) {
            $self->my_die(qq{load_rules: unknown action $rule_hash->{action}},
                dump_rule_from_db($rule));
        }

        # Compile the regex for efficiency, otherwise it'll be recompiled every
        # time it's used.
        my $regex = $self->filter_regex($rule->regex());
        eval {
            $rule_hash->{regex} = qr/$regex/;
        };
        if ($@) {
            croak qq{$0: failed to compile regex $regex: $@\n} .
                dump_rule_from_db($rule);
        }
        if ($self->{discard_compiled_regex}) {
            $rule_hash->{regex} = $regex;
        }

        push @results, $rule_hash;
    }

    $self->{sort_rules} = lc $self->{sort_rules};
    if ($self->{sort_rules} eq q{normal}) {
        # Normal, most efficient order.
        @results = sort { $b->{rule_order} <=> $a->{rule_order} } @results;
    } elsif ($self->{sort_rules} eq q{reverse}) {
        # Reverse order - should be least efficient.
        @results = sort { $a->{rule_order} <=> $b->{rule_order} } @results;
    } elsif ($self->{sort_rules} eq q{shuffle}) {
        # Shuffle the results.
        @results = shuffle(@results);
    } else {
        croak qq{load_rules: unknown sort_rules value: $self->{sort_rules}\n},
            qq{Valid values: normal, reverse, shuffle\n};
    }

    # Regardless of the sort order we always respect priority; not doing so
    # would break the rule set.
    return sort { $b->{priority} <=> $a->{priority} } @results;
}

sub dump_connection {
    my ($connection) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$connection], [q{connection}]);
}

sub dump_line {
    my ($line) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$line], [q{line}]);
}

sub dump_rule {
    my ($rule) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$rule], [q{rule}]);
}

sub dump_rule_from_db {
    my ($rule) = @_;

    local $Data::Dumper::Sortkeys = 1;
    my %columns = $rule->get_columns();
    return Data::Dumper->Dump([\%columns], [q{rule}]);
}

# I used to use Data::Dumper on the entire hash, but it's horrendously slow once
# the number of connections remaining grows, so . . . 
sub dump_state {
    my ($self) = @_;
    my $state = q{};
    my %tracked;

    local $Data::Dumper::Sortkeys = 1;
    $state = <<'PREAMBLE';
## vim: set foldmethod=marker :
sub reload_state {
    my %queueids;
    my %connections;

PREAMBLE

    foreach my $data_source (qw(queueids connections)) {
        $state .= qq{## Starting dump of $data_source\n};
        $state .= qq{## } . localtime() . qq{\n};
        my $untracked = q{};
        foreach my $queueid (sort keys %{$self->{$data_source}}) {
            my $connection = $self->{$data_source}->{$queueid};
            if (exists $connection->{tracked}) {
                $tracked{$queueid} = $connection;
            } else {
                # This is pretty ugly looking, but should result in 
                #   $queueids{q{38C1F4493}}
                # or similar.
                my $var = qq{\$${data_source}{q{$queueid}}};
                $untracked .= qq(## $var {{{\n);
                $untracked .= Data::Dumper->Dump([$connection], [$var]);
                $untracked .= qq(## }}}\n);
            }
        }
        $state .= qq{## Starting dump of tracked $data_source data\n};
        $state .= qq{## } . localtime() . qq( {{{\n);
        $state .= Data::Dumper->Dump([\%tracked], [qq{*$data_source}]);
        $state .= qq(## }}}\n);
        $state .= qq{## Appending dump of untracked $data_source data\n};
        $state .= qq{## } . localtime() . qq{\n};
        $state .= $untracked;
    }

    $state .= <<'POSTAMBLE';

    return (\%queueids, \%connections);
}

1;
POSTAMBLE
    return $state;
}

sub filter_regex {
    my ($self, $regex) = @_;

    # I'm deliberately allowing a trailing .
    my $hostname_re = qr/(?:unknown|(?:[-_a-zA-Z0-9.]+))/;

    $regex =~ s/__SENDER__      /__EMAIL__/gx;
    $regex =~ s/__RECIPIENT__   /__EMAIL__/gx;
    $regex =~ s/__MESSAGE_ID__  /.*/gx;
    # We see some pretty screwey hostnames in HELO commands.
    $regex =~ s/__HELO__        /__HOSTNAME__|(?:\\[)__IP__(?:\\])|(.*?)/gx;
#   This doesn't work, as it matches valid addresses, not real world addresses.
#   $regex =~ s/__EMAIL__       /$RE{Email}{Address}/gx;
#   The empty alternative below is to allow for <> as the sender address
#   We also allow up to 7 @ signs in the address . . . I have seen that many :(
    $regex =~ s/__EMAIL__       /(?:|[^@]+(?:\@(?:__HOSTNAME__|\\[__IP__\\])){0,7})/gx;
    # This doesn't match, for varous reason - I think numeric subnets are one.
    #$regex =~ s/__HOSTNAME__    /$RE{net}{domain}{-nospace}/gx;
    $regex =~ s/__HOSTNAME__    /$hostname_re/gx;
    $regex =~ s/__IP__          /$RE{net}{IPv4}/gx;
    $regex =~ s/__SMTP_CODE__   /\\d{3}/gx;
    # 3-9 is a guess.
    $regex =~ s/__QUEUEID__     /(?:NOQUEUE|[\\dA-F]{3,9})/gx;
    $regex =~ s/__COMMAND__     /(?:MAIL FROM|RCPT TO|DATA(?: command)?|message body|end of DATA)/gx;
#   $regex =~ s/____/$RE{}{}/gx;

    return $regex;
}

sub make_connection_by_queueid {
    my ($self, $line, $queueid) = @_;
    if (exists $self->{queueids}->{$queueid}) {
        $self->my_warn(qq{make_connection_by_queueid: $queueid already exists},
            dump_line($line)
        );
        return $self->{queueids}->{$queueid};
    }

    # NOTE: We don't clear the faked flag here, that's up to the caller.
    my $connection = $self->make_connection($line);
    $connection->{queueid} = $queueid;
    $self->{queueids}->{$queueid} = $connection;
    return $connection;
}

sub make_connection_by_pid {
    my ($self, $line) = @_;
    # NOTE: We don't clear the faked flag here, that's up to the caller.
    my $connection = $self->make_connection($line);
    $self->{connections}->{$line->{pid}} = $connection;
    return $connection;
}

sub make_connection {
    my ($self, $line) = @_;

    return {
        logfile         => $self->{current_logfile},
        line_number     => $.,
        faked           => $line,
        start           => scalar localtime $line->{timestamp},
        programs        => {},
        # TODO: fix this.
        # We'll always start with client = localhost, because I can't figure 
        # out which rule should set these initially without clobbering 
        # something else.
        connection      => {
            client_hostname => q{localhost},
            client_ip       => q{127.0.0.1},
            start           => $line->{timestamp},
        },
    };
}

sub disconnection {
    my ($self, $line) = @_;

    # NOTE: We deliberately don't use $self->get_connection_by_pid() here
    # because we don't want a new connection returned, we need more control.
    if (not exists $self->{connections}->{$line->{pid}}) {
        $self->my_warn(qq{disconnection: no connection found for pid }
            . qq{$line->{pid} - perhaps the connect line is in a }
            . qq{previous log file?\n},
            dump_line($line));
        return;
    }

    my $connection = $self->{connections}->{$line->{pid}};
    # This is quite common - it happens every time we reject at SMTP time.
    if (not exists $connection->{queueid} and exists $connection->{results}) {
        $connection->{connection}->{end} = $line->{timestamp};
        $self->fixup_connection($connection);
        $self->commit_connection($connection);
    }

    delete $self->{connections}->{$line->{pid}};
}

sub get_mock_object {
    my ($self, $table) = @_;
    return $self->{dbix}->resultset($table)->new_result({});
}

# Update the values in a hash, complaining if we change existing values, unless
# the existing (key, value) is found in silent_overwrite.
sub update_hash {
    my ($self, $hash, $silent_overwrite, $updates, $silent_discard, $rule, $line,
        $connection, $name) = @_;
    my $conflicts = 0;
    my $template = <<'TEMPLATE';
__NAME__: new value for __KEY__ (__NEW_VALUE__) differs from existing value (__ORIG_VALUE__)
TEMPLATE

    UPDATE:
    while (my ($key, $value) = each %{$updates}) {
        if (exists $hash->{$key} 
            and exists $silent_discard->{$key}
            and (not defined $silent_discard->{$key}
                 or (defined $silent_discard->{$key}
                        and exists $silent_discard->{$key}->{$value}
                    )
                )
            ) {
            # The update is a default value, and shouldn't clobber the existing
            # value: skip it.
            next UPDATE;
        }

        if (exists $hash->{$key} and $hash->{$key} ne $value) {
            my $orig_value = $hash->{$key};
            my $skip_warning = 0;
            # If $key exists, and there are no restrictions on values which can
            # be overwritten, then don't warn.
            if (exists $silent_overwrite->{$key}
                    and not defined $silent_overwrite->{$key}) {
                $skip_warning++;
            }
            # If the existing value can be silently overwritten (i.e. is a
            # default value) then silently overwrite it.
            if (exists $silent_overwrite->{$key}
                    and defined $silent_overwrite->{$key}
                    and exists $silent_overwrite->{$key}->{$orig_value}) {
                $skip_warning++;
            }
            if (not $skip_warning) {
                my $warning = $template;
                $warning =~ s/__NAME__/$name/;
                $warning =~ s/__KEY__/$key/;
                $warning =~ s/__ORIG_VALUE__/$orig_value/;
                $warning =~ s/__NEW_VALUE__/$value/;
                $self->my_warn($warning);
                $conflicts++;
            }
        }

        $hash->{$key} = $value;
    }

    if ($conflicts) {
        $self->my_warn(qq{This rule produced conflicts: \n},
            dump_rule($rule),
            qq{in this line:\n},
            dump_line($line),
            qq{for this connection:\n},
            dump_connection($connection),
            Data::Dumper->Dump([$silent_overwrite], [q{silent_overwrite}]),
            Data::Dumper->Dump([$silent_discard], [q{silent_discard}]),
        );
    }

    return $conflicts;
}

sub fixup_connection {
    my ($self, $connection)         = @_;
    my $results                     = $connection->{results};

    # Don't even try if it's faked; faked more or less (I hope) means that it's
    # the latter part of a tracked connection which hasn't been tracked yet, so
    # it should be retried later with the faked flag cleared.
    if (exists $connection->{faked}) {
        $self->my_warn(qq{fixup_connection: faked connection: \n},
            dump_connection($connection)
        );
        return;
    }

    my $parent = $connection->{parent};

    my $failure = 0;
    my %data;
    # Populate %data.
    foreach my $result (@{$results}) {
        foreach my $key (keys %{$result}) {
            if (exists $self->{nochange_result_cols}->{$key}
                    and exists $data{$key}
                    and $data{$key} ne $result->{$key}) {
                $self->my_warn(qq{fixup_connection: Different values for $key: \n}
                    . qq{\told: $data{$key}\n}
                    . qq{\tnew: $result->{$key}\n}
                );
            }
            $data{$key} = $result->{$key};
        }
    }

    # Check that we have everything we need; we can't pull any of this from the
    # parent, I think.  Maybe I can?  I don't need to, at least at this stage.
    RESULT:
    foreach my $result (@{$results}) {
        if (uc $result->{postfix_action} eq q{INFO}) {
            next RESULT;
        }
        foreach my $rcol (keys %{$self->{required_result_cols}}) {
            if (not exists $result->{$rcol}) {
                if (exists $data{$rcol}) {
                    $result->{$rcol} = $data{$rcol};
                } else {
                    $self->my_warn(qq{fixup_connection: missing result col: $rcol\n},
                        dump_connection($connection),
                    );
                    $failure++;
                }
            }
        }
    }

    foreach my $ccol (keys %{$self->{required_connection_cols}}) {
        # NOTE: I'm assuming that anything we're going to require from the
        # parent connection has already been saved there; if not I'll need to
        # revisit this and complicate it much further.
        if (not exists $connection->{connection}->{$ccol}
                and defined $parent
                and exists $parent->{connection}->{$ccol}) {
            $connection->{connection}->{$ccol} = $parent->{connection}->{$ccol};
        }
        if (not exists $connection->{connection}->{$ccol}) {
            $self->my_warn(qq{fixup_connection: missing connection col: $ccol\n},
                dump_connection($connection),
            );
            $failure++;
        }
    }

    if ($failure) {
        $self->my_warn(qq{fixup_connection: fixup failed\n});
    } else {
        $connection->{fixuped} = 1;
    }
}

sub save {
    my ($self, $connection, $line, $rule, $matches) = @_;

    $connection->{programs}->{$line->{program}}++;

    if ($rule->{queueid}) {
        my $queueid = $matches->[$rule->{queueid}];
        if (exists $connection->{queueid}
                and $connection->{queueid} ne $queueid) {
            $self->my_warn(qq{queueid change: was $connection->{queueid}; }
                . qq{now $queueid\n});
        }
        $connection->{queueid} = $queueid;
    }

    # Save the new result in $connection.
    # RESULT_DATA
    my %result = (
        rule_id         => $rule->{id},
        postfix_action  => $rule->{postfix_action},
        line            => $line,
        # Sneakily inline result_data here
        %{$rule->{result_data}},
    );
    if (not exists $connection->{results}) {
        $connection->{results} = [];
    }
    push @{$connection->{results}}, \%result;

    # We do use $self->update_hash() for result_cols, just in case a rule has
    # internal conflicts between result_cols and result_data.
    # RESULT_COLS
    my %r_cols_updates;
    foreach my $r_col (keys %{$rule->{result_cols}}) {
        $r_cols_updates{$r_col} = $matches->[$rule->{result_cols}->{$r_col}];
    }
    $self->update_hash(\%result, {}, \%r_cols_updates, {}, $rule, $line,
        $connection, q{save: result_cols});


    # Populate connection.
    # CONNECTION_DATA
    $self->update_hash($connection->{connection},
        $self->{c_cols_silent_overwrite},
        $rule->{connection_data}, $self->{c_cols_silent_discard},
        $rule, $line, $connection, q{save: connection_data});


    # CONNECTION_COLS
    my %c_cols_updates;
    foreach my $c_col (keys %{$rule->{connection_cols}}) {
        $c_cols_updates{$c_col}
            = $matches->[$rule->{connection_cols}->{$c_col}];
    }
    $self->update_hash($connection->{connection},
        $self->{c_cols_silent_overwrite},
        \%c_cols_updates, {}, $rule, $line, $connection,
        q{save: connection_cols});


    # Check for a queueid change.
    if (exists $connection->{queueid}
            and exists $self->{queueids}->{$connection->{queueid}}
            and $connection ne $self->{queueids}->{$connection->{queueid}}) {
        $self->my_warn(qq{save: queueid clash:\n},
            qq{old:\n},
            dump_connection($self->{queueids}->{$connection->{queueid}}),
            qq{new:\n},
            dump_connection($connection),
        );
    }
    # Ensure we save the connection by queueid; this allows us to tie the whole
    # lot together.
    if (exists $connection->{queueid}
            and not exists $self->{queueids}->{$connection->{queueid}}) {
        $self->{queueids}->{$connection->{queueid}} = $connection;
    }
}

sub track {
    my ($self, $line, $rule, $matches) = @_;

    my $queueid         = $self->get_queueid($line, $rule, $matches);
    my $parent          = $self->get_connection_by_queueid($line, $queueid);

    my $child_queueid   = $parent->{results}->[-1]->{child};
    if (not exists $parent->{children}) {
        $parent->{children} = {};
    }
    if (exists $parent->{children}->{$child_queueid}) {
        $self->my_warn(qq{track: tracking $child_queueid for a second time:\n});
    }

    my $child;
    if (exists $self->{queueids}->{$child_queueid}) {
        $child = $self->{queueids}->{$child_queueid};
    } else {
        $child = $self->make_connection_by_queueid($line, $child_queueid);
    }
    # Clear the faked flag; we should never have committed a connection before
    # tracking now.
    delete $child->{faked};
    $parent->{children}->{$child_queueid} = $child;

    # Mark both connections as tracked.
    $parent->{tracked} = 1;
    $child->{tracked}  = 1;

    if (exists $child->{parent}
        and $child->{parent} ne $parent) {
        $self->my_warn(qq{Trying to track for a second time!\n},
            qq{\tnew parent     => $queueid\n},
            qq{\tchild          => $child\n},
            qq{\told parent     => $child->{parent}\n},
            qq{\t$line->{program}: $line->{text}\n},
        );
    }

    $child->{parent}            = $parent;
    $child->{parent_queueid}    = $parent->{queueid};
}

# We commit unfaked, fixuped connections, regardless of parent/children -
# commit_connection() has nothing to do with that stuff.
sub commit_connection {
    my ($self, $connection) = @_;

    if (exists $connection->{faked}) {
        $self->my_warn(qq{commit_connection: faked connection: \n},
            dump_connection($connection)
        );
        return;
    }
    if (not exists $connection->{fixuped}) {
        $self->my_warn(qq{commit_connection: non-fixuped connection: \n},
            dump_connection($connection)
        );
        return;
    }
    if (exists $connection->{committed}) {
        $self->my_warn(qq{commit_connection: previously committed connection: \n},
            dump_connection($connection)
        );
        return;
    }

    # Occasionally we want to test without committing to the database, because 
    # committing roughly quadrouples the run time.
    if ($self->{skip_inserting_results}) {
        $connection->{committed} = 1;
        return;
    }

    if ($self->{num_connections_uncommitted} == 0) {
        $self->{dbix}->txn_begin();
    }

    my $connection_in_db = $self->{dbix}->resultset(q{Connection})->new_result(
            $connection->{connection});
    if (exists $connection->{queueid}) {
        $connection_in_db->queueid($connection->{queueid});
    }
    $connection_in_db->insert();
    $self->{num_connections_uncommitted}++;
    $connection->{committed} = 1;

    my $connection_id = $connection_in_db->id();
    RESULT:
    foreach my $result (@{$connection->{results}}) {
        if (uc $result->{postfix_action} eq q{INFO}) {
            next RESULT;
        }

        my $result_in_db = $self->{dbix}->resultset(q{Result})->new_result({
                connection_id   => $connection_id,
                rule_id         => $result->{rule_id},
                postfix_action  => $result->{postfix_action},
                #warning         => $result->{warning},
                smtp_code       => $result->{smtp_code},
                sender          => $result->{sender},
                recipient       => $result->{recipient},
                data            => $result->{data},
            });
        $result_in_db->insert();
    }

    if ($self->{num_connections_uncommitted} > 1000) {
        $self->{dbix}->txn_commit();
        $self->{num_connections_uncommitted} = 0;
    }
}

sub maybe_remove_faked {
    my ($self, $connection) = @_;

    # First try to identify bounced notification mails.
    # If it didn't come from either smtpd or pickup then it must have been
    # generated internally by postfix.  We check that it's not a tracked mail,
    # because those are internally generated too.
    if (not exists $connection->{programs}->{q{postfix/smtpd}}
            and not exists $connection->{programs}->{q{postfix/pickup}}
            and not exists $connection->{tracked}) {
        my $sender_found = 0;
        my $bounce_message_id = 0;
        foreach my $result (@{$connection->{results}}) {
            # Bounces always have <> as the sender.
            if (exists $result->{sender} and $result->{sender} eq q{}) {
                $sender_found++;
            }
            # There'll always be a message-id; it _APPEARS_ that the message-id
            # is preserved when forwarding mail but is generated for bounce
            # notification.  The format for bounce notification is
            # datetime.queueid@, so check for that.
            if (exists $result->{message_id}
                    and $result->{message_id}
                        =~ m/^<\d{14}\.($self->{queueid_regex})\@/o
                    and $1 eq $connection->{queueid}) {
                $bounce_message_id++;
            }
        }
        if ($sender_found and $bounce_message_id) {
            delete $connection->{faked};
            $connection->{bounce_notification} = 1;
            return;
        }
    }
}

sub my_warn {
    my ($self, $first_line, @rest) = @_;
    my $prefix = qq{$0: $self->{current_logfile}: $.: };

    if (@rest) {
        # Make it easy to fold warnings
        my $newline = q{};
        if ($first_line =~ m/\n$/) {
            $newline = qq{\n};
            $first_line =~ s/\n$//;
        }
        warn $prefix, $first_line, q( {{{), $newline, @rest, qq(}}}\n);
    } else {
        warn $prefix, $first_line;
    }
}

sub my_die {
    my ($self) = shift @_;
    die qq{$0: $self->{current_logfile}: $.: }, @_;
}

1;
