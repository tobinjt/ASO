#!/usr/bin/env perl

# $Id$

package ASO::Parser;

=head1 NAME

ASO::Parser - Parse Postfix log messages and populate an SQL database with
data gathered.

=head1 VERSION

This documentation refers to ASO::Parser version $Id$

=head1 SYNOPSIS

    use ASO::Parser;
    my $parser = ASO::Parser->new({
            data_source => q{dbi:SQLite:dbname=../sql/db.sq3},
            sort_rules  => q{normal},
            discard_compiled_regex  => 0,
        });

    $parser->load_state($statefile);
    $parser->parse($logfile);

    $parser->update_check_order();
    my $statefile = IO::File->new($statefile);
    print $statefile $parser->dump_state();

=head1 DESCRIPTION

ASO::Parser parses Postfix 2.2.x and 2.3.x log messages, populating an SQL
database with the data extracted from the logs.

XXX ADD A WHOLE LOT MORE HERE.

=head1 SUBROUTINES/METHODS 

Most subroutines are for internal use only, and thus are not documented here.
See the ACTIONS section also.

=cut


use strict;
use warnings;
$| = 1;

use lib q{..};
use ASO::DB;
use Parse::Syslog;
use IO::File;
use Carp qw(cluck croak);
use Data::Dumper;
use Regexp::Common qw(net);
use List::Util qw(shuffle);

=over 4

=item new(\%options)

New creates an ASO::Parser object with the specified options.  There only 
required option is data_source; the rest are optional options.

=over 8

=item data_source

The SQL database to use: rules will be loaded from it and results saved to it.
If opening the database fails die will be called with an apropriate error
message.  There is no default value; one must be specified.

=item sort_rules

How to sort the rules returned from the database: normal (most effecient,
default), shuffle, or reverse (least effecient).  Useful for checking new rules;
you should obtain the same results regardless of the order the rules are tried
in; if not you have overlapping rules and need to rationalise your ruleset or
change the priority of one or more rules.

=item discard_copiled_regex

For effeciency the regex in each rule is compiled once and saved.  If you're
doing something extremely complicated, or want to drasticaly slow down
execution, set this option to true and the regexs will be recompiled each time
they're used.  Defaults to false.

=item skip_inserting_results

Inserting results into the database quadrouples the run time of the program,
because of the disk IO (this is based on using SQLite on Windows, other
databases and/or OSs may give different results).  For testing it can be very
helpful to disable insertion; everything else happens as normal.

=back

=back

=cut

sub new {
    my ($package, $options) = @_;
    my %defaults = (
        sort_rules              => q{normal},
        discard_compiled_regex  => 0,
        # Skip inserting results into the db, because it quadrouples run time.
        skip_inserting_results => 0,
    );

    if (not exists $options->{data_source}) {
        croak qq{${package}->new: you must provide a data_source\n};
    }

    foreach my $option (keys %$options) {
        if (not exists $defaults{$option} and $option ne q{data_source}) {
            croak qq{${package}::new(): unknown option $option\n};
        }
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

=begin internals

=over 4

=item $self->init_globals()

init_globals() sets up various data structures in $self which are used by the
remainder of the module.  It's called automatically by new(), and is separate
from new() to ease subclassing.

=back

=end internals

=cut

sub init_globals {
    my ($self) = @_;

    # Used in $self->my_warn() and $self->my_die() to report the logfile we're
    # currently parsing.
    $self->{current_logfile}  = q{INITIALISATION};
    $.                        = 0;

    # Used to validate queueids in get_queueid_from_matches() and in
    # maybe_remove_faked() to check if a message-id contains a queueid.
    $self->{queueid_regex}    = $self->filter_regex(q{__QUEUEID__});
    $self->{queueid_regex}    = qr/$self->{queueid_regex}/;
    # Used to set warning in REJECTION.
    $self->{reject_warning}   =
            $self->filter_regex(q{^__QUEUEID__: reject_warning:});
    $self->{reject_warning}   = qr/$self->{reject_warning}/;

    # The data to dump in dump_state()
    $self->{data_to_dump} = [qw(queueids connections timeout_queueids)];
    # All mail starts off in %connections, unless submitted locally by
    # sendmail/postgrop, and then moves into %queueids if it gets a queueid.
    $self->{connections}      = {};
    $self->{queueids}         = {};
    # When a connection with a sending client times out during the DATA phase,
    # Postfix will have allocated a queueid for the mail.  We need to discard
    # that mail, which is done in the TIMEOUT action.  Unfortunately, in maybe
    # 20% of cases, the cleanup line is logged after the timeout and
    # disconnection, leading to faked mails in the state table.  I'm going to
    # try to track those queueids where the timeout happens before cleanup logs,
    # and then discard the next cleanup line for that queueid.
    $self->{timeout_queueids} = {};
    # The timestamp of the last log line parsed.  Used for cleaning out
    # $self->{timeout_queueids}, and possibly other uses in future.
    $self->{last_timestamp}   = 0;

    # Keep track of the number of inserts uncommitted.
    $self->{num_connections_uncommitted} = 0;

    # Return values for actions
    $self->{ACTION_SUCCESS} = 1;
    $self->{ACTION_FAILURE} = 0;
    # This one returns the new text to be parsed.
    $self->{ACTION_REPARSE} = 2;

    # Actions available to rules.
    $self->{actions} = {};
    $self->add_actions(qw(
        IGNORE
        CONNECT
        DISCONNECT
        SAVE_BY_QUEUEID
        COMMIT
        TRACK
        REJECTION
        MAIL_PICKED_FOR_DELIVERY
        PICKUP
        CLONE
        TIMEOUT
        MAIL_TOO_LARGE
        POSTFIX_RELOAD
        SMTPD_DIED
        SMTPD_KILLED
        SMTPD_WATCHDOG
        BOUNCE
    ));

    # Used in fixup_connection() to verify data.
    my $mock_result = $self->{dbix}->resultset(q{Result})->new_result({});
    my $mock_conn   = $self->{dbix}->resultset(q{Connection})->new_result({});
    $self->{required_connection_cols} = $mock_conn->required_columns();
    $self->{required_result_cols}     = $mock_result->required_columns();
    $self->{nochange_result_cols}     = $mock_result->nochange_columns();

    # Used in update_hash(), via save(), when deciding whether to overwrite an
    # existing value or discard a new value.
    $self->{c_cols_silent_overwrite}  = $mock_conn->silent_overwrite_columns();
    $self->{c_cols_silent_discard}    = $mock_conn->silent_discard_columns();

    # Used in parse_result_cols().
    $self->{NUMBER_REQUIRED}          = 1;
    $self->{result_cols_names}        = $mock_result->result_cols_columns();
    $self->{connection_cols_names}    = $mock_conn->connection_cols_columns();
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

=over 4

=item $parser->parse($logfile)

Parses the logfile, ignoring any lines logged by programs the ruleset doesn't
contain rules for.  Lines which aren't parsed will be warned about; warnings may
also be generated for a myriad of other reasons, see DIAGNOSTICS for more
information.  Data gathered from the logs will be inserted into the database
(depending on the value of skip_inserting_results).

=back

=cut

sub parse {
    my ($self, $logfile) = @_;
    $self->{current_logfile} = $logfile;
    my $syslog = Parse::Syslog->new($logfile);
    if (not $syslog) {
        croak qq{parse: failed creating syslog parser for $logfile: $@\n};
    }

    LINE:
    while (my $line = $syslog->next()) {
        $self->{last_timestamp} = $line->{timestamp};
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

=over 4

=item $parser->update_check_order()

Update the rule order in the database so that more frequently hit rules will be
tried earlier on the next run.  The order rules are tried in does not change
during the lifetime of an ASO::Parser object, but the next object created will
hopefully have a more effecient ordering of rules.  The optimal rule ordering
is dependant on the contents of the logfile currently being parsed, so this
measure may not be 100% accurate.

=back

=cut

sub update_check_order {
    my ($self) = @_;

    # XXX Hang the original rule off the generated rule, or merge the rules
    # extracted from the db with the generated rules.
    my (%id_map) = map { ($_->{id}, $_) } @{$self->{rules}};
    foreach my $rule ($self->{dbix}->resultset(q{Rule})->search()) {
        # Sometimes a rule won't have been hit; the value will be set to zero.
        my $id = $rule->id();
        if (not exists $id_map{$id}) {
            $self->my_warn(qq{update_check_order: Missing rule:},
                dump_rule_from_db($rule));
        } else {
            $rule->hits($id_map{$id}->{count});
            $rule->hits_total($rule->hits_total() + $rule->hits());
            $rule->update();
        }
    }
}

=begin internals

See result_cols in ASO::DB::Rule for a description.

=over 4

=item $self->parse_result_cols($spec, $rule, $number_required, $column_names)

Parses an assignment list for result_cols, result_data, connection_cols or
connection_data.  Example list:
  hostname = 1; helo = 2, sender = 4
  client_ip = ::1; client_hostname = localhost, helo = unknown;

Either semi-colons or commas can separate assignments.  The variable on the left
hand side must be a key in %$column_names.  This is also used to parse
result_data and connection_data, hence the relaxed regex (.* instead of \d+); if
$number_required is true the right hand side is later required to match \d+.
There is no way to put a comma or semi-colon in the string.  Returns a hash
reference containing variable => value.

=back

=end internals

=cut

sub parse_result_cols {
    my ($self, $spec, $rule, $number_required, $column_names) = @_;

    my $assignments = {};
    ASSIGNMENT:
    foreach my $assign (split /\s*[,;]\s*/, $spec) {
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

=begin internals

=over 4

=item $self->parse_line($line)

Try each regex against the line until a match is found, then perform the
associated action.  If no match is found spew a warning.  $line is not a string,
it's the returned by Parse::Syslog.

=back

=end internals

=cut

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
    $self->my_warn(qq{unparsed line: $line->{program}: $text\n});
}

=head1 ACTIONS

When a rule successfully matches a line the action specified in the rule will be
performed; these are the subroutines implementing the actions.  All actions are
called in the same way:

  $self->ACTION($rule, $line, \@matches);

Most actions have more documentation, but it's only of interest to developers
digging into the internals.

=over  4

=item IGNORE

IGNORE just returns successfully; it is used when a line needs to be parsed for
completeness but doesn't either provide any useful data or require anything to
be done.

=back

=cut

sub IGNORE {
    my ($self, $rule, $line, $matches) = @_;
    return $self->{ACTION_SUCCESS};
}

=over  4

=item CONNECT

Handle a remote client connecting: create a new state table entry (indexed by
smtpd pid) and save both the client hostname and IP address.

=back

=cut

sub CONNECT {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->make_connection_by_pid($line->{pid});
    # We also want to save the hostname/ip info
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item DISCONNECT

Deal with the remote client disconnecting: enter the connection in the database,
perform any required cleanup, and delete the connection from the state tables.

=begin internals

Currently the main cleanup requirement is to delete any CLONE()d connections
which only have two smtpd entries so they don't hang around in the state tables
causing queueid clashes.  It appears from the logs that the remote client sends
MAIL FROM, RCPT TO, RSET and then starts over; this leaves a state table entry
which will never have any more log entries and wouldn't be disposed of in any
other way.  There are two problems resulting from this: memory is used, albeit
only a small amount, and more importantly when the parser has processed enough
log lines queueids sart being reused and these entries cause queueid clashes.

=end internals

=back

=cut

sub DISCONNECT {
    my ($self, $rule, $line, $matches) = @_;

    if (not $self->pid_exists($line->{pid})) {
        $self->my_warn(qq{disconnection: no connection found for pid }
            . qq{$line->{pid} - perhaps the connect line is in a }
            . qq{previous log file?\n},
            dump_line($line));
        # Does this make sense?  At the moment yes, there aren't any other rules
        # which will deal with these lines anyway.
        return $self->{ACTION_SUCCESS};
    }

    my $connection = $self->get_connection_by_pid($line->{pid});
    # There should NEVER be a queueid.
    if (exists $connection->{queueid}) {
        $self->my_warn(qq{disconnection: PANIC: found queueid: \n},
            dump_connection($connection));
        # Similarly there's no point in failing here.
        return $self->{ACTION_SUCCESS};
    }

    # Commit the connection.
    $connection->{connection}->{end} = $line->{timestamp};
    $self->fixup_connection($connection);
    $self->commit_connection($connection);
    $self->delete_connection_by_pid($line->{pid});

    if (not exists $connection->{cloned_mails}) {
        return $self->{ACTION_SUCCESS};
    }

    # Cleanup the mails accepted over this connection.
    CLONED_MAIL:
    foreach my $mail (@{$connection->{cloned_mails}}) {
        # Try to clear out those mails which only have two smtpd entries, so
        # they don't hang around, taking up memory uselessly and causing queueid
        # clashes occasionally.
        if (not exists $mail->{programs}->{q{postfix/cleanup}}
                and $mail->{programs}->{q{postfix/smtpd}} == 2
                and $self->queueid_exists($mail->{queueid})
                ) {
            my $mail_by_queueid = $self->get_connection_by_queueid(
                    $mail->{queueid});
            if ($mail eq $mail_by_queueid) {
                $self->delete_connection_by_queueid($mail->{queueid});
            } else {
                $self->my_warn(qq{missing cleanup, but connection }
                    . qq{found by queueid $mail->{queueid} differs:\n},
                    qq{found in cloned_mails:\n},
                    dump_connection($mail),
                    qq{found in queueids:\n},
                    dump_connection($mail_by_queueid),
                );
            }
            next CLONED_MAIL;
        }
        # Now try committing mails where the client disconnected after a
        # rejection.
        if (not exists $mail->{programs}->{q{postfix/cleanup}}
                and $mail->{programs}->{q{postfix/smtpd}} > 2
                and $mail->{results}->[-1]->{postfix_action} eq q{REJECTED}
                and $self->queueid_exists($mail->{queueid})
                ) {
            $mail->{connection}->{end} = $line->{timestamp};
            $self->fixup_connection($mail);
            $self->commit_connection($mail);
            $self->delete_connection_by_queueid($mail->{queueid});
            next CLONED_MAIL;
        }
    }

    # Ensure we don't have any circular data structures; it's unlikely to
    # happen, but just in case . . .
    delete $connection->{cloned_mails};
    return $self->{ACTION_SUCCESS};
}

=over  4

=item SAVE_BY_QUEUEID

Use the queueid from $rule and @matches to find the correct connection and call
$self->save() with the appropriate arguments - see save() in SUBROUTINES for
more details.  If the connection doesn't exist a connection marked faked will be
created and a warning issued.

=back

=cut

sub SAVE_BY_QUEUEID {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($queueid);
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item COMMIT

Enter the data into the database.  Entry may be postponed if the mail is a
child waiting to be tracked.

=begin internals

Find the correct connection using the queueid from $rule and @matches, then:

=over 8

=item *

Save the data from the rule in the connection.

=item *

Determine if the connection is a bounce message and remove the faked flag if it
is.

=item *

Postpone commitment if the connection is still marked faked: the connection is
either a child still waiting to be tracked (see TRACK later) or hasn't been
properly dealt with by the parser so shouldn't be entered in the database
anyway.

=item *

Fixup the connection - see fixup_connection() for details.

=item *

Enter the connection in the database.

=item *

Delete the connection from the state tables.

=back

=end internals

=back

=cut

sub COMMIT {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($queueid);

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

    # Let the parent know we're being deleted
    if (exists $connection->{parent}) {
        $self->delete_child_from_parent($connection, $line, $rule);
    }

    # Try to commit any children we can.
    if (exists $connection->{children}) {
        $self->maybe_commit_children($connection);
    }

    $self->delete_connection_by_queueid($queueid);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item TRACK

Track a mail when it is forwarded to another mail server; this happens when a
local address is aliased to a remote address.  TRACK will be called when dealing
with the parent mail, and will create the child mail if necessary.  TRACK checks
if the child has already been tracked, either with this parent or with another
parent, and issues appropriate warnings in either case.  Tracking children is
discussed extensively in the paper written about this parser; details about
obtaining the paper are given in the SEE ALSO section.

=back

=cut

sub TRACK {
    my ($self, $rule, $line, $matches) = @_;

    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    my $parent  = $self->get_connection_by_queueid($queueid);
    $self->save($parent, $line, $rule, $matches);

    my $child_queueid = $parent->{results}->[-1]->{child};
    if (not exists $parent->{children}) {
        $parent->{children} = {};
    }
    if (exists $parent->{children}->{$child_queueid}) {
        $self->my_warn(qq{track: tracking $child_queueid for a second time:\n});
    }

    my $child = $self->get_or_make_connection_by_queueid($child_queueid);
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

    return $self->{ACTION_SUCCESS};
}

=over  4

=item REJECTION

Deal with postfix rejecting an SMTP command from the remote client: log the
rejection with the accepted mail if there is one, otherwise log it with the
connection.

=back

=cut

sub REJECTION {
    my ($self, $rule, $line, $matches) = @_;
    my $connection;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    if ($queueid ne q{NOQUEUE}) {
        $connection = $self->get_connection_by_queueid($queueid);
    } else {
        $connection = $self->get_connection_by_pid($line->{pid});
    }
    $self->save($connection, $line, $rule, $matches);
    if ($line->{text} =~ m/$self->{reject_warning}/) {
        $connection->{results}->[-1]->{warning} = 1;
    }
    return $self->{ACTION_SUCCESS};
}

=over  4

=item MAIL_PICKED_FOR_DELIVERY

This action represents Postfix picking a mail from the queue to deliver.  This
action is used for both qmgr and cleanup due to out of order log lines.

=begin internals

There are some complications:

=over 8

=item *

Sometimes the state table entry needs to be created by this action, because the
mail is the result of forwarding or a bounce notification.

=item *

Sometimes cleanup lines need to be discarded, as they're a remnant of mails
discarded due to timeouts.  The cleanup line must have been logged within six
minutes of the mail being accepted, and the queueid must not be in the global
state tables yet - if it is then the queueid has been reused and this cleanup
line isn't for the discarded mail, so must be kept.

=back

This action handles the above complications and saves the data extracted from
the line.

=end internals

=back

=cut

sub MAIL_PICKED_FOR_DELIVERY {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);

    if ($line->{program} eq q{postfix/cleanup}
            and exists $self->{timeout_queueids}->{$queueid}) {
        # This MAY be a cleanup line for a connection which timed out during the
        # DATA phase, but which wasn't seen before smtpd finished logging, i.e.
        # the logging sequence was:
        #   smtpd connect
        #   smtpd queueid
        #   smtpd timeout
        #   smtpd disconnect
        #   cleanup queueid
        # If it is for a discarded mail we just ignore this line, otherwise we
        # continue on as normal because sometimes there isn't a cleanup line,
        # dunno why.  Maybe it isn't cleanup which allocates queueids?  If we
        # haven't seen a cleanup line before the queueid is reused (i.e. can be
        # found in %queueids) just remove the entry in %timeout_queueids and
        # continue as normal.

        # First check: the cleanup line should be logged pretty soon after the
        #   rest of the lines, in general it appears within a few lines in the
        #   log.  Timeouts happen after 5 minutes, but some data may have been
        #   transmitted, extending the delay, so we'll require the cleanup
        #   line to be seen within 10 minutes (NOTE: if this is changed
        #   prune_timeout_queueids() needs to change too).
        # Second check: the queueid shouldn't exist in %queueids: if it does it
        #   means the queueid is being reused so this line is for the new mail,
        #   rather than the discarded mail.  Obviously this is vulnerable to
        #   race conditions, but I'm doing the best I can.
        my $discarded_mail = delete $self->{timeout_queueids}->{$queueid};
        my $last_timestamp = $discarded_mail->{results}->[-1]->{timestamp};
        if ($line->{timestamp} - $last_timestamp <= (10 * 60)
                and not exists $self->{queueids}->{$queueid}) {
            return $self->{ACTION_SUCCESS};
        }
        # Otherwise we contine onwards as normal.
    }

    # Sometimes I need to create connections here because there are
    # tracked connections where the child shows up before the parent
    # logs the tracking line; there's a similar requirement in track().
    my $connection = $self->get_or_make_connection_by_queueid($queueid,
        faked => $line
    );
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item PICKUP

Pickup is the service which deals with mail submitted locally via
/usr/sbin/sendmail.  This action creates a new state table entry and saves data
to it, unless out of order logging has caused the cleanup line to be logged
first.  Lines are assumed to be out of order if the only program seen thus far
is cleanup and there is less than five seconds difference between the timestamps
of the two lines.

=back

=cut

sub PICKUP {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    # Sometimes the pickup line will be logged after the cleanup line :(
    # Try to handle that here.
    my $connection;
    if ($self->queueid_exists($queueid)) {
        $connection = $self->get_connection_by_queueid($queueid);
        # We'll assume the log lines are out of order if:
        # 1 There's only a 5 second or less difference in timestamps
        # 2 The only program seen so far is postfix/cleanup
        my $programs_seen = join q{}, sort keys %{$connection->{programs}};
        if ($line->{timestamp} - $connection->{connection}->{start} > 5
                or $programs_seen ne q{postfix/cleanup}) {
            # It doesn't meet the criteria, so don't use the existing
            # connection.  Let make_connection_by_queueid() do the logging.
            $connection = undef;
        } else {
            # Delete the faked flag added by MAIL_PICKED_FOR_DELIVERY.
            delete $connection->{faked};
        }
    }
    if (not defined $connection) {
        $connection = $self->make_connection_by_queueid($queueid);
    }
    $self->save($connection, $line, $rule, $matches);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item CLONE

Multiple mails may be accepted on a single connection, so each time a mail is
accepted the connection's state table entry must be cloned; if the original data
structure was used the second and subsequent mails would corrupt the data
structure.

=begin internals

The cloned data structure must have rejections prior to the mail's
acceptance cleared from it's results, otherwise rejections would be entered
twice in the database.  The cloned data structure will be added to the global
state tables but will also be added to the connection's list of accepted mails;
this is to enable detection of mails where the client gave the RSET commmand
after recipients were accepted - see the description in DISCONNECT.  The
last_clone_timestamp is also updated to enable timeout handling to determine
whether the timeout applies to an accepted mail or not.

=end internals

=back

=cut

sub CLONE {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->get_connection_by_pid($line->{pid});
    my $clone_queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    # dclone() no longer scales because of cloned_mails, so manually construct a
    # copy.
    my $clone = $self->make_connection_by_queueid($clone_queueid,
        start       => scalar localtime $line->{timestamp},
        # Dump anything after the first result (connect from . . ); they'll be 
        # rejections and shouldn't be part of the new result.
        results     => [ $connection->{results}->[0] ],
        # Similarly reset the list of programs which have touched the
        # connection.
        programs    => { q{postfix/smtpd} => 1 },
        connection  => { %{$connection->{connection}} },
        cloned_by   => $line->{pid},
    );
    $self->save($clone, $line, $rule, $matches);

    # Save the clone so that we can detect those weird mails that don't have a
    # post-smtpd entry.
    if (not exists $connection->{cloned_mails}) {
        $connection->{cloned_mails} = [];
    }
    push @{$connection->{cloned_mails}}, $clone;

    # Save the timestamp so that we can distinguish between accepted mails and
    # non-accepted, pipelined mails during timeout handling (in TIMEOUT action).
    $connection->{last_clone_timestamp} = $line->{timestamp};
    return $self->{ACTION_SUCCESS};
}

=over  4

=item MAIL_TOO_LARGE

Handle mails being discarded because the client tried to send a larger message
than the local server accepts.  See TIMEOUT for further discussion; the two are
handled in exactly the same way.

=back

=cut

sub MAIL_TOO_LARGE {
    my ($self, $rule, $line, $matches) = @_;
    return $self->TIMEOUT($rule, $line, $matches);
}

=over  4

=item TIMEOUT

The connection timed out so the mail currently being transferred must be
discarded.  The mail may have been accepted, in which case there's a data
structure to dispose of, or it may not in which case there's none.  The gory
details can be found in the internals documentation.

=begin internals

Timeout without an accepted mail happens very often, I think it might be due to
ESMTP pipelining where the conversation looks like:

  client:                         server:
  EHLO -->
                                  <-- PIPELINING
  MAIL FROM, RCPT TO, DATA -->
                                  <-- RCPT TO/MAIL FROM rejected.
  connection lost

There may or may not have been a mail accepted and fully trasnferred before the
timeout.

How to distinguish between a timeout affecting the last mail accepted versus a
timeout affecting a rejected mail?  This _seems_ to work: track the timesamp of
the last CLONE, i.e. accepted mail, and if there's a reject later than that
(skipping the timeout just saved at the start of this subroutine) then the
timeout applies to an unsucessful mail: don't delete anything, just save() and
finish.  Whew.

There's also the problem of stray cleanup lines being logged after the timeout
line.  This is dealt with by saving the queueid and discarded data structure in
a global state table which is checked in MAIL_PICKED_FOR_DELIVERY.

=end internals

=back

=cut

# The connection timed out so we need to discard the last mail accepted on this
# connection.
sub TIMEOUT {
    my ($self, $rule, $line, $matches) = @_;
    my $connection = $self->get_connection_by_pid($line->{pid});
    $self->save($connection, $line, $rule, $matches);
    return $self->tidy_after_timeout($connection);
}

=over  4

=item POSTFIX_RELOAD

Postfix has been stopped, started or reloaded; all active smtpds will have been
killed, so the parser needs to tidy up any outstanding connections.  Connections
with only one smtpd entry will be discarded; other connections will be
committed.

=back

=cut

sub POSTFIX_RELOAD {
    my ($self, $rule, $line, $matches) = @_;

    foreach my $connection ($self->get_all_connections_by_pid()) {
        $self->save($connection, $line, $rule, $matches);
        $self->tidy_after_timeout($connection);
        $self->delete_dead_smtpd($connection, $line);
    }

    return $self->{ACTION_SUCCESS};
}

=over  4

=item SMTPD_DIED

Sometimes an smtpd exits uncleanly; this cleans up the connection.

=back

=cut

sub SMTPD_DIED {
    my ($self, $rule, $line, $matches) = @_;

    if ($self->pid_exists($line->{pid})) {
        my $connection = $self->get_connection_by_pid($line->{pid});
        $self->save($connection, $line, $rule, $matches);
        $self->tidy_after_timeout($connection);
    }
    return $self->handle_dead_smtpd($line, q{SMTPD_DIED},
        qr/pid (\d+) exit status/);
}

=over  4

=item SMTPD_KILLED

When Postfix is reloaded or stopped the master daemon sometimes forcibly kills
an smtpd; this cleans up the connection.

=back

=cut

sub SMTPD_KILLED {
    my ($self, $rule, $line, $matches) = @_;

    if ($self->pid_exists($line->{pid})) {
        my $connection = $self->get_connection_by_pid($line->{pid});
        $self->save($connection, $line, $rule, $matches);
        $self->tidy_after_timeout($connection);
    }
    return $self->handle_dead_smtpd($line, q{SMTPD_KILLED},
        qr/pid (\d+) killed by signal/);
}

=over  4

=item SMTPD_WATCHDOG

Occasionally the watchdog timer in an smtpd runs out, and the smtpd exits.  This
cleans up the connection.

=back

=cut

sub SMTPD_WATCHDOG {
    my ($self, $rule, $line, $matches) = @_;

    my $connection = $self->get_connection_by_pid($line->{pid});
    $self->save($connection, $line, $rule, $matches);
    $self->tidy_after_timeout($connection);
    $self->delete_dead_smtpd($connection, $line);
    return $self->{ACTION_SUCCESS};
}

=over  4

=item BOUNCE

Postfix 2.3 logs the creation of bounce messages, which are handled by this
action.

=back

=cut

sub BOUNCE {
    my ($self, $rule, $line, $matches) = @_;

    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($queueid);
    $self->save($connection, $line, $rule, $matches);
    my $bounce_queueid = $connection->{results}->[-1]->{child};
    my $bounce_con = $self->get_or_make_connection_by_queueid($bounce_queueid);
    $bounce_con->{bounce_notification} = 1;
    delete $bounce_con->{faked};

    return $self->{ACTION_SUCCESS};
}

=over 4

=item $self->add_actions(@actions)

Add @actions to the list of available actions.  Currently actions cannot be
removed.  Nothing clever is done to @actions, so you must use the name of the
subroutine implementing the action.

=back

=cut

sub add_actions {
    my ($self, @actions) = @_;

    map { $self->{actions}->{$_} = 1 } @actions;
}

=over 4

=item $self->tidy_after_timeout($connection)

Deal with a timeout of some sort occuring: delete the last accepted mail if
required.

=back

=cut

sub tidy_after_timeout {
    my ($self, $connection) = @_;

    if (not exists $connection->{cloned_mails}) {
        # Nothing has been acccepted, so there's nothing to do.
        return $self->{ACTION_SUCCESS};
    }

    # Check the timestamps to see whether there's been a rejection since the
    # previous acceptance.
    if (scalar @{$connection->{results}} >= 2
            and $connection->{results}->[-2]->{timestamp}
                > $connection->{last_clone_timestamp}) {
        return $self->{ACTION_SUCCESS};
    }

    my $last_mail = $connection->{cloned_mails}->[-1];
    if (not $self->queueid_exists($last_mail->{queueid})) {
        return $self->{ACTION_SUCCESS};
    }
    if (not exists $last_mail->{programs}->{q{postfix/cleanup}}) {
        # We haven't seen a cleanup line yet; add this queueid to the list
        # of timed out connections.
        $self->{timeout_queueids}->{$last_mail->{queueid}} = $last_mail;
    }
    $self->delete_connection_by_queueid($last_mail->{queueid});
    delete $connection->{cloned_mails}->[-1];

    return $self->{ACTION_SUCCESS};
}

=begin internals

=over  4

=item $self->handle_dead_smtpd($line, $action, $regex)

Deals with an smtpd dying or being killed.  Matches $regex against $line->{text}
and uses $1 as the pid.  Uses $action in error messages.  Calls
delete_dead_smtpd() if the connection exists, returns silently otherwise.

=back

=end internals

=cut

sub handle_dead_smtpd {
    my ($self, $line, $action, $regex) = @_;

    if ($line->{text} !~ m/$regex/) {
        $self->my_warn(qq{$action: bad line: $line->{text}\n});
        return $self->{ACTION_FAILURE};
    }

    my $pid = $1;
    if (not $self->pid_exists($pid)) {
        return $self->{ACTION_SUCCESS};
    }
    my $connection = $self->get_connection_by_pid($pid);
    $self->delete_dead_smtpd($connection, $line);

    return $self->{ACTION_SUCCESS};
}

=over  4

=item $self->delete_dead_smtpd($connection, $line)

If there's only one
smtpd log line the connection will be discarded, otherwise it will be committed.

=back

=cut

sub delete_dead_smtpd {
    my ($self, $connection, $line) = @_;

    if ($connection->{programs}->{q{postfix/smtpd}} <= 2) {
        # Only the connect and/or killed lines, delete it.
        $self->delete_connection_by_pid($connection->{pid});
    } else {
        # Hopefully this will work, I'll refine it later if it doesn't.
        $connection->{connection}->{end} = $line->{timestamp};
        $self->fixup_connection($connection);
        $self->commit_connection($connection);
        $self->delete_connection_by_pid($connection->{pid});
    }

}

=over 4

=item $self->maybe_commit_children($parent)

This should be called after commit_connection() for any connection which has
children.  Children which reached COMMIT() before their parent reahced TRACK()
won't have been entered in the database; instead they will have been marked as
commit_ready and their database entry postponed.  maybe_commit_children() will
loop over all children and call both fixup_connection() and commit_connection()
on those marked commit_ready; those children will also be removed from the state
tables.  Children not marked commit_ready will be deferred and will reach
COMMIT() when their last log entry is parsed.

=back

=cut

sub maybe_commit_children {
    my ($self, $parent) = @_;

    # We check for this in delete_child_from_parent(), so that we don't trample
    # over ourselves in the sequence
    # maybe_commit_children() -> delete_child_from_parent()
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
            $self->delete_connection_by_queueid($child->{queueid});
            # This is safe: see perldoc -f each for the guarantee.
            delete $parent->{children}->{$child_queueid};
        }

        # We don't do anything with other children, they'll reach committal by
        # themselves later,
    }

    delete $parent->{committing_children};
}

=over 4

=item $self->delete_child_from_parent($child, $line, $rule)

Delete $child from its parent's list of children.  Co-operates with
maybe_commit_children() to ensure it doesn't do anything while
maybe_commit_children() is executing.  Should be called when a child is being
committed, not for non-child mails.

=back

=cut

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

    # maybe_commit_children() -> delete_child_from_parent()
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

=over 4

=item $self->load_rules()

Load the rules from the database:

=over 8

=item *

Sorting rules according to sort_rules

=item *

Expanding connection_cols and result_cols when __RESTRICTION_START__ is found in
a regex.

=item *

Passing regexs through filter_regex() and compiling them.

=item *

Checking for overlaps in result_cols and result_data; likewise in
connection_cols and connection_data.

=item *

Discarding the compiled regex if discard_compiled_regex is set.

=back

=back

=cut

sub load_rules {
    my ($self) = @_;
    my @results;

    # __RESTRICTION_START__ captures; we need to add to result_cols and
    # connection_cols whenever it's used.
    my $extra_rejection_cols = {
        connection_cols => $self->parse_result_cols(
            q{client_hostname = 2, client_ip = 3},
            undef, $self->{NUMBER_REQUIRED},
            $self->{connection_cols_names},
        ),
        result_cols     => $self->parse_result_cols(
            q{smtp_code = 4},
            undef, $self->{NUMBER_REQUIRED},
            $self->{result_cols_names},
        ),
    };


    foreach my $rule ($self->{dbix}->resultset(q{Rule})->search()) {
        my $rule_hash = {
            id               => $rule->id(),
            name             => $rule->name(),
            description      => $rule->description(),
            hits             => $rule->hits(),
            priority         => $rule->priority(),
            postfix_action   => $rule->postfix_action(),
            action           => $rule->action(),
            program          => $rule->program(),
            queueid          => $rule->queueid(),
            regex_orig       => $rule->regex(),
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

        if ($rule_hash->{action} eq q{REJECTION}) {
            foreach my $cols (qw(connection_cols result_cols)) {
                # Add the extra captures, but allow them to be overridden.
                $rule_hash->{$cols} = {
                    %{$extra_rejection_cols->{$cols}},
                    %{$rule_hash->{$cols}},
                };
            }
        }

        # Check for overlapping columns {result,connection}_{cols,data}.
        my $overlapping_cols = 0;
        foreach my $type (qw(connection result)) {
            my ($type_data, $type_cols) = (qq{${type}_data}, qq{${type}_cols});
            foreach my $col (keys %{$rule_hash->{$type_data}}) {
                if (exists $rule_hash->{$type_cols}->{$col}) {
                    $overlapping_cols++;
                    $self->my_warn(qq{Overlapping column in both }
                        . qq{$type_cols and $type_data: $col\n});
                }
            }
        }
        if ($overlapping_cols) {
            $self->my_die(qq{Exiting due to overlapping columns in rule:\n},
                dump_rule($rule_hash));
        }

        if (not exists $self->{actions}->{$rule_hash->{action}}) {
            $self->my_die(qq{load_rules: unknown action $rule_hash->{action}: },
                dump_rule_from_db($rule));
        }

        # Compile the regex for efficiency, otherwise it'll be recompiled every
        # time it's used.
        my $filtered_regex = $self->filter_regex($rule_hash->{regex_orig});
        eval {
            $rule_hash->{regex} = qr/$filtered_regex/;
        };
        if ($@) {
            $self->my_die(qq{$0: failed to compile regex:\n\n},
                $filtered_regex,
                qq{\n\nbecause: $@\n\n},
                dump_rule_from_db($rule),
                dump_rule($rule_hash),
            );
        }
        if ($self->{discard_compiled_regex}) {
            $rule_hash->{regex} = $filtered_regex;
        }

        push @results, $rule_hash;
    }

    $self->{sort_rules} = lc $self->{sort_rules};
    if ($self->{sort_rules} eq q{normal}) {
        # Normal, most efficient order.
        @results = sort { $b->{hits} <=> $a->{hits} } @results;
    } elsif ($self->{sort_rules} eq q{reverse}) {
        # Reverse order - should be least efficient.
        @results = sort { $a->{hits} <=> $b->{hits} } @results;
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

=over 4

=item $self->dump_state();

Returns a string which can be eval'd to restore the state tables.
To avoid overwriting existing data structures the string contains a subroutine
named reload_state() which returns the state tables when executed.

=back

=cut

# I used to use Data::Dumper on the entire hash, but it's horrendously slow once
# the number of connections remaining grows, so I now iterate over the elements,
# dumping anything untracked individually and creating a new hash for tracked
# connections because they're interlinked and need to be dumped all at once.
sub dump_state {
    my ($self) = @_;
    my $state = q{};

    $self->prune_timeout_queueids();

    local $Data::Dumper::Sortkeys = 1;
    $state = <<'PREAMBLE';
## vim: set foldmethod=marker :
no warnings q{redefine};
sub reload_state {
    my %queueids;
    my %connections;

PREAMBLE

    foreach my $data_source (@{$self->{data_to_dump}}) {
        my %tracked;
        my $num_keys = keys %{$self->{$data_source}};
        $state .= qq{## Starting dump of $data_source ($num_keys entries)\n};
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

    my $results = join q{, },
        map { qq{q($_) => \\\%$_} }
            @{$self->{data_to_dump}};
    $state .= <<"POSTAMBLE";

    return ($results);
}

use warnings q{redefine};

1;
POSTAMBLE
    return $state;
}

=over 4

=item $self->load_state($file)

Eval the code in $file and then run the resulting subroutine reload_state() to
reload state tables.

=back

=cut

sub load_state {
    my ($self, $file) = @_;

    $@ = $! = 0;
    my $result = do $file;
    if (not defined $result) {
        if ($@) {
            $self->my_warn(qq{Error while reloading state from "$file": $@\n});
        } elsif ($!) {
            $self->my_warn(qq{Error while reloading state from "$file": $!\n});
        }
        $self->my_die(qq{Error while reloading state from "$file", exiting.\n});
    }

    if (not $self->can(q{reload_state})) {
        $self->my_die(qq{reload_state() not defined by $file\n});
    }

    eval {
        my %data = $self->reload_state();
        foreach my $data_source (@{$self->{data_to_dump}}) {
            $self->{$data_source} = $data{$data_source};
        }
    };
    if ($@) {
        $self->my_die(qq{Fatal: error running reload_state(): $@\n});
    } else {
        $self->my_warn(qq{Loaded state from $file\n});
    }
}

=begin internals

=over 4

=item $self->reload_state()

The subroutine does not exist within the module; it must be defined in the file
passed as an argument to load_state().  When run it should return hash
references representing the saved state tables.  dump_state() returns a
subroutine which does exactly this, so in general the calling sequence will be:

  # First parser
  my $state = $parser->dump_state();
  print $state_file $state;

  # Second parser
  $parser->load_state($state_file);

=back

=end internals

=cut

=begin internals

=over 4

=item $self->prune_timeout_queueids()

Remove any connection in $self->{timeout_queueids} older than 7 minutes before
the timestamp of the last log line parsed, so they don't accumulate forever,
Called from dump_state() before dumping.

=back

=end internals

=cut

sub prune_timeout_queueids {
    my ($self) = @_;

    # This is dependant on the time difference used in MAIL_PICKED_FOR_DELIVERY.
    foreach my $queueid (keys %{$self->{timeout_queueids}}) {
        my $connection = $self->{timeout_queueids}->{$queueid};
        if ($connection->{results}->[-1]->{timestamp}
                < ($self->{last_timestamp} - (10 * 60))) {
            delete $self->{timeout_queueids}->{$queueid};
        }
    }
}

=over 4

=item $self->filter_regex($regex)

Substitutes certain keywords in the regex with regex snippets, e.g.
__SMTP_CODE__ is replaced with \d{3}.  Every regex loaded from the database will
be processed by filter_regex(), allowing each regex to be largely
self-documenting, be far simpler than it would otherwise have been, and allowing
bugs in the regex components to be fixed in one place only.

The full list of keywords which are expanded is:

__SENDER__, __RECIPIENT__, __MESSAGE_ID__, __HELO__, __EMAIL__, __HOSTNAME__,
__IP__, __IPv4__, __IPv6__, __SMTP_CODE__, __RESTRICTION_START__, __QUEUEID__,
__COMMAND__, __SHORT_CMD__, __DELAYS__, __DELAY__, __DSN__ and __CONN_USE__.

XXX TODO: document the matched fields in __RESTRICTION_START__

The names should be reasonably self-explanatory.

=back

=cut

sub filter_regex {
    my ($self, $regex) = @_;

    # I'm deliberately allowing a trailing . in $hostname_re.
    my $hostname_re = qr/(?:unknown|(?:[-_a-zA-Z0-9.]+))/;
    my $ipv6_chunk  = qr/(?:[0-9A-Fa-f]{1,4})/;
    my $ipv6_re = qr/(?:
 (?>(?:${ipv6_chunk}:){7}${ipv6_chunk})             # Full address
|(?>(?:${ipv6_chunk}:){1,6}(?::${ipv6_chunk}){1,6}) # Elided address, missing
                                                    # the middle but having both
                                                    # ends (e.g. 2001::1)
|(?>:(?::${ipv6_chunk}){1,7})                       # Elided address missing the
                                                    # start of the address (e.g.
                                                    # ::1)
|(?:${ipv6_chunk}:){1,7}:                           # Elided address missing the
                                                    # end of the address (e.g.
                                                    # 2001::)
)/x;

    $regex =~ s/__SENDER__              /__EMAIL__/gx;
    $regex =~ s/__RECIPIENT__           /__EMAIL__/gx;
    $regex =~ s/__RESTRICTION_START__   /(__QUEUEID__): reject(?:_warning)?: (?:RCPT|DATA) from (?>(__HOSTNAME__)\\[)(?>(__IP__)\\]): (__SMTP_CODE__)(?: __DSN__)?/gx;
    # message-ids initially look like email addresses, but really they can be
    # absolutely anything; just like email addresses in fact.
    $regex =~ s/__MESSAGE_ID__          /.*?/gx;
    # We see some pretty screwey hostnames in HELO commands; in fact just match
    # any damn thing, the hostnames are particularly weird when Postfix rejects
    # them.
    $regex =~ s/__HELO__                /.*?/gx;
#   This doesn't work, as it matches valid addresses, not real world addresses.
#   $regex =~ s/__EMAIL__               /$RE{Email}{Address}/gx;
#   Wibble: from=<<>@inprima.locaweb.com.br>; just match anything as an address.
    $regex =~ s/__EMAIL__               /.*?/gx;
    # This doesn't match, for varous reason - I think numeric subnets are one.
    #$regex =~ s/__HOSTNAME__           /$RE{net}{domain}{-nospace}/gx;
    $regex =~ s/__HOSTNAME__            /$hostname_re/gx;
    # Believe it or not, sometimes the IP address is unknown.
    $regex =~ s/__IP__                  /(?:__IPv4__|__IPv6__|unknown)/gx;
    $regex =~ s/__IPv4__                /(?:::ffff:)?$RE{net}{IPv4}/gx;
    $regex =~ s/__IPv6__                /$ipv6_re/gx;
    $regex =~ s/__SMTP_CODE__           /\\d{3}/gx;
    # 3-9 is a guess.
    $regex =~ s/__QUEUEID__             /(?:NOQUEUE|[\\dA-F]{3,9})/gx;
    $regex =~ s/__COMMAND__             /(?:MAIL FROM|RCPT TO|DATA(?: command)?|message body|end of DATA)/gx;
    # DATA is deliberately excluded here because there are more specific rules
    # for DATA.
    $regex =~ s/__SHORT_CMD__           /(?:CONNECT|HELO|EHLO|AUTH|MAIL|RCPT|VRFY|STARTTLS|RSET|NOOP|QUIT|END-OF-MESSAGE|UNKNOWN)/gx;
    $regex =~ s/__DELAYS__              /delays=(?:[\\d.]+\/){3}[\\d.]+, /gx;
    $regex =~ s/__DELAY__               /delay=\\d+(?:\\.\\d+)?, /gx;
    $regex =~ s/__DSN__                 /\\d\\.\\d\\.\\d/gx;
    $regex =~ s/__CONN_USE__            /conn_use=\\d+, /gx;
#   $regex =~ s/____/$RE{}{}/gx;

    return $regex;
}

=over 4

=item $self->update_hash($hash, $silent_overwrite, $updates, $silent_discard, $rule, $line, $connection, $name)

Update the values in $hash using $updates, warning if existing values are
changed, unless the conditions below are met.

If the key exists in $silent_discard and either the new value exists in
$silent_discard or the value in $silent_discard is undefined and a value for
that key already exists in $hash the change is silently skipped; i.e. anything
in $silent_discard is taken as a default value and will not overwrite a more
specific value.

$silent_overwrite functions similarly, but the values in $silent_overwrite are
taken as default values which will be silently overwritten by new values from
$updates.

$silent_overwrite and $silent_discard will frequently be one and the same.

$rule, $line, $connection and $name are used in warnings generated if existing
values change.

=back

=cut

sub update_hash {
    my ($self, $hash, $silent_overwrite, $updates, $silent_discard, $rule,
        $line, $connection, $name) = @_;
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

=over 4

=item $self->fixup_connection($connection)

Clean up the data in $connection before entering it in the database:

=over 8

=item *

Ensure all results have all the required attributes, by propogating attributes
between results if necessary.

=item *

Ensure that constant attributes don't change between results.

=item *

If any attributes are missing from the connection, copy them from the parent
connection if one exists.

=back

=back

Warnings will be logged if any result or connection attributes are missing, or
if constant attributes change between results.

=cut

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
                $self->my_warn(qq{fixup_connection: }
                    . qq{Different values for $key: \n}
                    . qq{\told: $data{$key}\n}
                    . qq{\tnew: $result->{$key}\n}
                );
            }
            $data{$key} = $result->{$key};
        }
    }

    my %missing_result;
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
                    $missing_result{$rcol}++;
                    $failure++;
                }
            }
        }
    }

    my %missing_connection;
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
            $missing_connection{$ccol}++;
            $failure++;
        }
    }

    my $error_message = q{};
    if (keys %missing_result) {
        $error_message .= qq{fixup_connection: missing result col(s): }
            . join(qq{, }, sort keys %missing_result)
            . qq{\n};
    }
    if (keys %missing_connection) {
        $error_message .= qq{fixup_connection: missing connection col(s): }
            . join(qq{, }, sort keys %missing_connection)
            . qq{\n};
    }
    if ($error_message ne q{}) {
        $self->my_warn($error_message, dump_connection($connection));
    }

    if ($failure) {
        $self->my_warn(qq{fixup_connection: fixup failed\n});
    } else {
        $connection->{fixuped} = 1;
    }
}

=over 4

=item $self->save($connection, $line, $rule, \@matches)

Save data extracted from $line, using $rule and \@matches, to $connection.
$connection->{connection} will be updated according to connection_data and
connection_cols - see update_hash() for full discussion.  The start time will be
saved if it is unset.  A new result will be created, containing the attributes
from result_data and result_cols plus the rule_id, postfix_action and timestamp.
If the rule matches a queueid (and the result is not NOQUEUE), the queueid will
be saved as $connection->{queueid}; if the queueid changes a warning will be
logged.

=back

=cut

sub save {
    my ($self, $connection, $line, $rule, $matches) = @_;

    $connection->{programs}->{$line->{program}}++;

    # Save the new result in $connection.
    # RESULT_DATA
    # NOTE: every time a new attribute is added here it needs to be stripped 
    # out in commit_connection().
    my %result = (
        rule_id         => $rule->{id},
        postfix_action  => $rule->{postfix_action},
        line            => $line,
        timestamp       => $line->{timestamp},
        date            => scalar localtime ($line->{timestamp}),
        logfile         => $self->{current_logfile},
        line_number     => $.,
        # Sneakily inline result_data here
        %{$rule->{result_data}},
    );
    push @{$connection->{results}}, \%result;

    # We don't use $self->update_hash() for result_cols, we check for internal
    # conflicts between result_cols and result_data in load_rules().
    # RESULT_COLS
    foreach my $r_col (keys %{$rule->{result_cols}}) {
        $result{$r_col} = $matches->[$rule->{result_cols}->{$r_col}];
    }


    # Populate connection.
    # CONNECTION_DATA
    $self->update_hash($connection->{connection},
        $self->{c_cols_silent_overwrite},
        $rule->{connection_data}, $self->{c_cols_silent_discard},
        $rule, $line, $connection, q{save: connection_data});
    if (not exists $connection->{start}) {
        $connection->{start} = localtime $line->{timestamp};
    }
    if (not exists $connection->{connection}->{start}) {
        $connection->{connection}->{start} = $line->{timestamp};
    }


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


    # queueid saving.
    if ($rule->{queueid}) {
        my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
        if ($queueid ne q{NOQUEUE}) {
            if (exists $connection->{queueid}
                    and $connection->{queueid} ne $queueid) {
                $self->my_warn(qq{queueid change: was $connection->{queueid}; }
                    . qq{now $queueid\n});
            }
            $connection->{queueid} = $queueid;
        }
    }

    # Check for a queueid change.
    if (exists $connection->{queueid}
            and $self->queueid_exists($connection->{queueid})) {
        my $other_con = $self->get_connection_by_queueid(
                $connection->{queueid});
        if ($connection ne $other_con) {
            $self->my_warn(qq{save: queueid clash: $connection->{queueid}\n},
                qq{old:\n},
                dump_connection($other_con),
                qq{new:\n},
                dump_connection($connection),
            );
        }
    }

    # Ensure we save the connection by queueid; this allows us to tie the whole
    # lot together.
    if (exists $connection->{queueid}) {
        $self->save_connection_by_queueid($connection, $connection->{queueid});
    }
}

=over 4

=item $self->commit_connection($commit_connection)

Enter the data from the connection into the database (unless
skip_inserting_results was specified).  If the connection is faked, hasn't
successfully completed fixup_connection(), or has already been commmitted an
appropriate error message wll be logged and commit_connection() will abort.  If
skip_inserting_results was specified commit_connection() will finish at this
point.  A new row will be entered in the connections table, and a new row in the
results table for each result where postfix_action is not INFO.

Database insertions are wrapped in transactions, and each transaction is
committed once there have been 1000 rows added to the connections table.  This
greatly speeds up execution as the database doesn't have to write to disk and
wait for the kernel to sync the disc until the transaction is committed.

=back

=cut

sub commit_connection {
    my ($self, $connection) = @_;

    if (exists $connection->{faked}) {
        $self->my_warn(qq{commit_connection: faked connection: \n},
            dump_connection($connection)
        );
        return;
    }
    if (not exists $connection->{fixuped}) {
        $self->my_warn(qq{commit_connection: non-fixuped connection\n});
        return;
    }
    if (exists $connection->{committed}) {
        $self->my_warn(qq{commit_connection: previously committed: \n},
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

        $result->{connection_id} = $connection_id;
        my @unwanted_attrs = qw(child date line line_number logfile
            postfix_action);
        foreach my $unwanted_attr (@unwanted_attrs) {
            delete $result->{$unwanted_attr};
        }
        my $result_in_db =
            $self->{dbix}->resultset(q{Result})->new_result($result);
        $result_in_db->insert();
    }

    if ($self->{num_connections_uncommitted} > 1000) {
        $self->{dbix}->txn_commit();
        $self->{num_connections_uncommitted} = 0;
    }
}

=over 4

=item $self->maybe_remove_faked($connection)

Faked connections won't be processed by either fixup_connection() (generally
there are attributes missing) or commit_connection() (faked connections should
not be entered in the database).  Sometimes the faked flag is unwarranted, e.g.
bounce notifications in Postfix 2.2.x will be marked as faked becausd their
origin is unclear.  maybe_remove_faked() should be called before
fixup_connection() or commit_connection() to identify mails which are
incorrectly marked as faked; it will remove the faked flag so the mail can be
entered in the database.

Currently bounce notifications are identified by passing the following checks:

=over 8

=item *

Neither smtpd nor pickup has logged any messages for this mail, i.e. the mail
was generated internally by Postfix rather than accepted from outside.

=item *

The sender address is <>.

=item *

The message-id matches the pattern /^<\d{14}\.(__QUEUEID__)\@/; the 14 digits
are the date in the format YYYYMMDDhhmmss.

=item *

The queueid matched by the regex above equals the queueid of the mail; this
ensures that the message is not an internally generated forwarded mail.

=back

The faked flag will be removed if all checks are successful.

=back

=cut

sub maybe_remove_faked {
    my ($self, $connection) = @_;

    # First try to identify bounced notification mails.
    # If it didn't come from either smtpd or pickup then it must have been
    # generated internally by postfix.
    if (not exists $connection->{programs}->{q{postfix/smtpd}}
            and not exists $connection->{programs}->{q{postfix/pickup}}) {
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

=over 4

=item $self->my_warn(@warnings)

Wrapper around warn which uses format_error() to provide helpful warnings.

=back

=cut

sub my_warn {
    my ($self, @warnings) = @_;

    warn $self->format_error(@warnings);
}

=over 4

=item $self->format_error($first_line, @further_lines)

Prepends the current time, filename and line number to $first_line.
@further_lines and a callstack will be wrapped with {{{ and }}}; these are the
default markers vim uses for folding blocks of text, so long error messages
(e.g. where a connection is dumped in the error message) can be folded, making
navigating through error output easier.

=back

=cut

sub format_error {
    my ($self, $first_line, @rest) = @_;

    my @message;
    my $timestamp = localtime;
    push @message, qq{$0: $timestamp: $self->{current_logfile}: $.: };

    chomp $first_line;
    push @message, $first_line;
    # Make it easy to fold warnings
    push @message, qq( {{{\n), @rest, Carp::longmess(q{}), qq(}}}\n);

    return join q{}, @message;
}

=over 4

=item $self->my_die(@messages)

Wrapper around die which uses format_error() to produce better errors.

=back

=cut

sub my_die {
    my ($self, @errors) = @_;

    die $self->format_error(@errors);
}

# Accessing mails/connections by queueid.

=over 4

=item $self->queueid_exists($queueid)

CHecks whether $queueid exists in the state table.

=back

=cut

sub queueid_exists {
    my ($self, $queueid) = @_;
    return exists $self->{queueids}->{$queueid};
}

=over 4

=item $self->get_connection_by_queueid($queueid)

Returns the connection for $queueid in the state tables, or creates a
connection marked faked and logs a warning if one doesn't exist.

=back

=cut

sub get_connection_by_queueid {
    my ($self, $queueid) = @_;
    if ($self->queueid_exists($queueid)) {
        return $self->{queueids}->{$queueid};
    }

    $self->my_warn(qq{get_connection_by_queueid: no connection for $queueid\n});
    return $self->make_connection_by_queueid($queueid, faked => 1);
}

=over 4

=item $self->make_connection_by_queueid($queueid, %attributes)

Creates and returns a new connection, saving it into the state table under
$queueid,  %attributes will be used to initialise the new connection; there are
no restrictions on what can be present in %attributes.

=back

=cut

sub make_connection_by_queueid {
    my ($self, $queueid, %attributes) = @_;

    if ($self->queueid_exists($queueid)) {
        $self->my_warn(qq{make_connection_by_queueid: $queueid exists\n},
            dump_connection($self->get_connection_by_queueid($queueid)));
    }
    my $connection = $self->make_connection(queueid => $queueid, %attributes);
    $self->{queueids}->{$queueid} = $connection;
    return $connection;
}

=over 4

=item $self->get_or_make_connection_by_queueid($queueid, %attributes)

If there's already a connection for $queueid it will be returned.  If not a new
connection will be created, initialised with %attributes (no checks are
performed on %attributes), saved in the state tables under $queueid and
returned.

=back

=cut

sub get_or_make_connection_by_queueid {
    my ($self, $queueid, %attributes) = @_;

    if ($self->queueid_exists($queueid)) {
        return $self->get_connection_by_queueid($queueid);
    } else {
        return $self->make_connection_by_queueid($queueid, %attributes);
    }
}

=over 4

=item $self->delete_connection_by_queueid($queueid)

Delete the connection saved under $queueid from the state tables.  The
connection won't be changed in any way, and will still be accessable through
other references.

=back

=cut

sub delete_connection_by_queueid {
    my ($self, $queueid) = @_;

    if (not $self->queueid_exists($queueid)) {
        $self->my_warn(qq{delete_connection_by_queueid: $queueid }
            . q{doesn't exist\n});
    }
    delete $self->{queueids}->{$queueid};
}

=over 4

=item $self->get_queueid_from_matches($line, $rule, \@matches)

Returns the queueid from $line, using $rule and \@matches.  Logs a warning if
there's anything wrong with the queueid, or it's not found.

=back

=cut

sub get_queueid_from_matches {
    my ($self, $line, $rule, $matches) = @_;

    if (not $rule->{queueid}) {
        $self->my_die(qq{get_queueid_from_matches: no queueid extracted by:\n},
            dump_rule($rule));
    }
    my $queueid     = $matches->[$rule->{queueid}];
    if (not defined $queueid or not $queueid) {
        $self->my_die(qq{get_queueid_from_matches: blank/undefined queueid\n},
            dump_line($line),
            qq{using: },
            dump_rule($rule)
        );
    }
    if ($queueid !~ m/^$self->{queueid_regex}$/o) {
        $self->my_die(qq{get_queueid_from_matches: $queueid !~ __QUEUEID__;\n},
            dump_line($line),
            qq{using: },
            dump_rule($rule)
        );
    }

    return $queueid;
}

=over 4

=item $self->save_connection_by_queueid($connection, $queueid)

Saves $connection into the state tables under $queueid.  Doesn't complain or
check anything; will happily clobber an existing connection - it's up to the
caller to check that with $self->queueid_exists($queueid).

=back

=cut

sub save_connection_by_queueid {
    my ($self, $connection, $queueid) = @_;

    $self->{queueids}->{$queueid} = $connection;
}

# Accessing mails/connections by pid

=over 4

=item $self->pid_exists($pid)

CHecks whether a connection is found for $pid in the state tables.

=back

=cut

sub pid_exists {
    my ($self, $pid) = @_;
    return exists $self->{connections}->{$pid};
}

=over 4

=item $self->get_connection_by_pid($pid)

Returns the connection for $pid in the state tables, or creates a
connection marked faked and logs a warning if one doesn't exist.

=back

=cut

sub get_connection_by_pid {
    my ($self, $pid) = @_;
    if ($self->pid_exists($pid)) {
        return $self->{connections}->{$pid};
    }

    $self->my_warn(qq{get_connection_by_pid: no connection for $pid\n});
    return $self->make_connection_by_pid($pid, faked => 1);
}

=over 4

=item $self->get_all_connections_by_pid()

Returns all connections saved by pid in the state tables.

=back

=cut

sub get_all_connections_by_pid {
    my ($self) = @_;
    return values %{$self->{connections}};
}

=over 4

=item $self->make_connection_by_pid($pid, %attributes)

Creates and returns a new connection, saving it into the state table under
$queueid,  %attributes will be used to initialise the new connection; there are
no restrictions on what can be present in %attributes.

=back

=cut

sub make_connection_by_pid {
    my ($self, $pid, %attributes) = @_;

    if ($self->pid_exists($pid)) {
        $self->my_warn(qq{make_connection_by_pid: $pid exists\n},
            dump_connection($self->get_connection_by_pid($pid)));
    }
    my $connection = $self->make_connection(pid => $pid, %attributes);
    $self->{connections}->{$pid} = $connection;
    return $connection;
}

=over 4

=item $self->get_or_make_connection_by_pid($pid, %attributes)

If there's already a connection for $pid it will be returned.  If not a new
connection will be created, initialised with %attributes (no checks are
performed on %attributes), saved in the state tables under $pid and returned.

=back

=cut

sub get_or_make_connection_by_pid {
    my ($self, $pid, %attributes) = @_;

    if ($self->pid_exists($pid)) {
        return $self->get_connection_by_pid($pid);
    } else {
        return $self->make_connection_by_pid($pid, %attributes);
    }
}

=over 4

=item $self->delete_connection_by_pid($pid)

Delete the connection saved under $pid from the state tables.  The connection
won't be changed in any way, and will still be accessable through other
references.

=back

=cut

sub delete_connection_by_pid {
    my ($self, $pid) = @_;

    if (not $self->pid_exists($pid)) {
        $self->my_warn(qq{delete_connection_by_pid: $pid doesn't exist\n});
    }
    delete $self->{connections}->{$pid};
}

=over 4

=item $self->make_connection(%attributes)

Creates a new connection initialised with the logfile and line number, required
data structures, and the contents of %attributes.  No checks are performed on
%attributes, so it can overwrite the default initialisation.

=back

=cut

sub make_connection {
    my ($self, %attributes) = @_;

    return {
        logfile         => $self->{current_logfile},
        line_number     => $.,
        programs        => {},
        connection      => {},
        results         => [],
        %attributes,
    };
}


=head1 DIAGNOSTICS

A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of each 
problem, one or more likely causes, and any suggested remedies.
(See also  QUOTE \" " INCLUDETEXT "13_ErrorHandling" "XREF83683_Documenting_Errors_"\! Documenting Errors QUOTE \" " QUOTE " in Chapter "  in Chapter  INCLUDETEXT "13_ErrorHandling" "XREF40477__"\! 13.)


=head1 CONFIGURATION AND ENVIRONMENT

A full explanation of any configuration system(s) used by the module,
including the names and locations of any configuration files, and the
meaning of any environment variables or properties that can be set. These
descriptions must also include details of any configuration language used.
(also see  QUOTE \" " INCLUDETEXT "19_Miscellanea" "XREF40334_Configuration_Files_"\! Configuration Files QUOTE \" " QUOTE " in Chapter "  in Chapter  INCLUDETEXT "19_Miscellanea" "XREF55683__"\! 19.)


=head1 DEPENDENCIES

Standard modules shipped with Perl: IO::File, Carp, Data::Dumper,
Regexp::Common, Storable, List::Util.

Modules packaged with ASO::Parser: ASO::DB.

External modules: Parse::Syslog, Regexp::Common::Email::Address, DBIx::Class
(which has many dependencies), DBI, DBD::whatever.

=head1 INCOMPATIBILITIES

None known thus far.

=head1 BUGS AND LIMITATIONS

A list of known problems with the module, together with some indication
whether they are likely to be fixed in an upcoming release.

Also a list of restrictions on the features the module does provide: 
data types that cannot be handled, performance issues and the circumstances
in which they may arise, practical limitations on the size of data sets, 
special cases that are not (yet) handled, etc.

The initial template usually just has:

There are no known bugs in this module. 
Please report problems to <Maintainer name(s)>  (<contact address>)
Patches are welcome.

=head1 SEE ALSO

XXX ADD INSTRUCTIONS FOR GETTING PAPER

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2007 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

Followed by whatever licence you wish to release it under. 
For Perl code that is often just:

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

1;
