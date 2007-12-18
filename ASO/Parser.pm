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
    # Create the parser, loading rules from and saving results to db.sq3.
    my $parser = ASO::Parser->new({
            data_source => q{dbi:SQLite:dbname=db.sq3},
            # other options if required
        });

    # Load previously saved state if there is any.
    $parser->load_state($statefilename);

    # Parse the log file.
    $parser->parse($logfile);
    # Do anything necessary after parsing each log.
    $parser->post_parsing();
    # Parse more files if you wish.

    # Update the order rules will be tried in, to improve efficiency.
    $parser->update_check_order();

    # Save the parser's current state to $statefile.
    my $statefile = IO::File->new($statefilename);
    $parser->dump_state($statefile);

=head1 DESCRIPTION

ASO::Parser parses Postfix 2.2.x and 2.3.x log messages, populating an SQL
database with the data extracted from the logs.  It deals with all the
complications and difficulties the author has encountered parsing Postfix logs,
providing a simple interface to the logs.  The difficulties encountered are
documented herein and at L<http://www.cs.tcd.ie/~tobinjt/>

=head1 SUBROUTINES/METHODS 

=cut


use strict;
use warnings;
$| = 1;

use lib q{..};
use ASO::DB;
use ASO::ProgressBar;
use Parse::Syslog;
use IO::File;
use Carp qw(cluck croak);
use Data::Dumper;
use Regexp::Common qw(net);
use List::Util qw(shuffle);
use Data::Compare;

=over 4

=item ASO::Parser->new(\%options)

New creates an ASO::Parser object with the specified options.  There only 
required option is data_source; the rest are optional options.

=over 8

=item data_source

The SQL database to use: rules will be loaded from it and results saved to it.
If opening the database fails die will be called with an appropriate error
message.  There is no default value; one must be specified.  This is a required,
non-boolean parameter.

=item sort_rules

How to sort the rules returned from the database: C<normal> (most efficient,
default), C<shuffle>, or C<reverse> (least efficient).  Useful for checking new
rules: you should obtain the same results regardless of the order the rules are
tried in; if not you have overlapping rules and need to rationalise your rule
set or change the priority of one or more rules.  This is an optional, boolean
parameter.

=item discard_copiled_regex

For efficiency the regex in each rule is compiled once and cached.  If you're
doing something extremely complicated, or want to drastically slow down
execution, set this option to true and the regexs will be recompiled each time
they're used.  Defaults to false.  This is an optional, boolean parameter.

=item skip_inserting_results

Inserting results into the database quadruples the run time of the program,
because of the disk IO (this is based on using SQLite on Windows, other
databases and/or OS's may give different results).  For testing it can be very
helpful to disable insertion; everything else happens as normal.  This is an
optional, boolean parameter.

=item parse_lines_only

Parse log lines but don't execute actions; useful when you want to test regexes
in new rules but don't want any new data saved to the database.  By defaults we
parse and execute actions.  This is an optional, boolean parameter.

=back

=back

=cut

sub new {
    my ($package, $options) = @_;

    my $self     = {};
    my $defaults = $package->options_for_new();

    # Ensure we have all required options
    foreach my $required_option (keys %{$defaults->{required_argument}},
            keys %{$defaults->{required_toggle}}) {
        if (not exists $options->{$required_option}) {
            croak qq{${package}->new: you must provide $required_option\n};
        }
    }

    # Copy the defaults
    foreach my $option_type (keys %$defaults) {
        $self = {
            %$self,
            %{$defaults->{$option_type}},
        };
    }

    # Ensure the options passed are valid
    OPTION_CHECK:
    foreach my $option (keys %$options) {
        foreach my $option_type (keys %$defaults) {
            if (exists $defaults->{$option_type}->{$option}) {
                $self->{$option} = $options->{$option};
                next OPTION_CHECK;
            }
        }
        croak qq{${package}::new(): unknown option $option\n};
    }

    $self->{dbix} = ASO::DB->connect(
        $self->{data_source},
        $self->{username},
        $self->{password},
        {AutoCommit => 1},
    );

    bless $self, $package;
    $self->init_globals();
    return $self;
}

=over 4

=item ASO::Parser->options_for_new()

Returns a hash of hashes containing the options which can be passed to
ASO::Parser->new().  The main reason is to avoid duplicating the option list in
programs which create ASO::Parser objects.  The hash returned has four entries
(at the moment, but more may be added in future):

=over 8

=item required_toggle

A hash listing required boolean parameters and their default values.  The actual
values passed are unimportant, only their truth value is used.

=item required_argument

A hash listing required non-boolean parameters and their default values.  The
values passed are important for these parameters (expected values are described
in new()).

=item optional_toggle

A hash listing optional boolean parameters and their default values.  The actual
values passed are unimportant, only their truth value is used.

=item optional_argument

A hash listing optional non-boolean parameters and their default values.  The
values passed are important for these parameters (expected values are described
in new()).

=back

=back

=cut

sub options_for_new {
    return {
        optional_argument   => {
            sort_rules              => q{normal},
            username                => undef,
            password                => undef,
            debug_results           => undef,
        },
        optional_toggle     => {
            discard_compiled_regex  => 0,
            # Skip inserting results into the database, because it quadruples
            # run time.
            skip_inserting_results  => 0,
            parse_lines_only        => 0,
        },
        required_argument   => {
            data_source             => undef,
        },
        required_toggle     => {
        },
    };
}

=over 4

=item $self->init_globals()

init_globals() sets up various data structures in $self which are used by the
remainder of the module.  It's called automatically by new(), and is separate
from new() to ease subclassing.

=back

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
    # sendmail/postdrop, and then moves into %queueids if it gets a queueid.
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
        EXPIRY
        MAIL_PICKED_FOR_DELIVERY
        PICKUP
        CLONE
        TIMEOUT
        MAIL_TOO_LARGE
        POSTFIX_RELOAD
        SMTPD_DIED
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

    # Used in is_valid_program_combination()
    # This list is embedded in the paper too.
    my @valid_combos = (
        # Local delivery of bounce notification, or local delivery of
        # forwarded/tracked mail.
        [qw(postfix/local                                          )],
        # Local pickup, local delivery.
        [qw(postfix/local postfix/pickup                           )],
        # Local pickup, local and remote delivery.
        [qw(postfix/local postfix/pickup postfix/smtp              )],
        # Sent from remote client, local and remote delivery.
        [qw(postfix/local                postfix/smtp postfix/smtpd)],
        # Sent from remote client, local delivery.
        [qw(postfix/local                             postfix/smtpd)],
        # Local pickup, remote delivery.
        [qw(              postfix/pickup postfix/smtp              )],
        # Remote delivery of forwarded mail.
        [qw(                             postfix/smtp              )],
        # Sent from remote client, remote delivery (relay for internal clients)
        [qw(                             postfix/smtp postfix/smtpd)],
    );

    # These two programs should be present for every mail.
    map { push @{$_}, qw(postfix/cleanup postfix/qmgr); } @valid_combos;
    # These are added to each of @valid_combos when populating
    # $self->{valid_combos}.
    my @extra_programs = (
        # Don't add anything
        [],
        # Pretty much any combo can generate a bounce
        [qw(postfix/bounce                     )],
        # Any mail can be deleted using postsuper.
        [qw(postfix/postsuper                  )],
        # Or they can both be present.
        [qw(postfix/bounce    postfix/postsuper)],
    );

    # Finally build the hash.
    $self->{valid_combos} = {};
    foreach my $combo (@valid_combos) {
        foreach my $extras (@extra_programs) {
            my %no_dups = map { $_ => 1 } @{$combo}, @{$extras};
            my $vc = join q{ }, sort keys %no_dups;
            $self->{valid_combos}->{$vc} = 0;
        }
    }

    # Used in parse_result_cols().
    $self->{NUMBER_REQUIRED}          = 1;
    $self->{result_cols_names}        = $mock_result->result_cols_columns();
    $self->{connection_cols_names}    = $mock_conn->connection_cols_columns();
    # Load the rules, and collate them by program, so that later we'll only try
    # rules for the program that logged the line.
    $self->{rules}            = [$self->load_rules()];
    my %rules_by_program;
    map {        $rules_by_program{$_->{program}} = []; }   @{$self->{rules}};
    map { push @{$rules_by_program{$_->{program}}}, $_; }   @{$self->{rules}};
    $self->{rules_by_program} = \%rules_by_program;
}

=over 4

=item $self->create_progress_bar($logfile, $logfile_fh)

Creates a progress bar if $logfile isn't STDIN, and STDOUT is a terminal.
Returns the progressbar and the value the progress bar will finish at if a
progress bar is created, or undef and undef if not.  $logfile_fh is used to find
the value the progress bar will finish at.

=back

=cut

sub create_progress_bar {
    my ($self, $logfile, $logfile_fh) = @_;

    # Term::ProgressBar::new doesn't finish if the output FH is not a tty;
    # dunno why that is, just working around it here.
    if (($logfile eq q{-}) or not -t STDOUT) {
        return (undef, undef);
    }

    my (@log_stat) = $logfile_fh->stat();
    if (not @log_stat) {
        $self->my_die(qq{parse: failed to stat $logfile: $!\n});
    }
    my $log_size = $log_stat[7];

    my $progress_bar = ASO::ProgressBar->new({
            name    => $logfile,
            count   => $log_size,
            ETA     => q{linear},
            fh      => \*STDOUT,
        });
    if (not $progress_bar) {
        $self->my_warn(qq{parse: creating progress bar failed\n});
        return (undef, undef);
    } else {
        # Disable the minor progress indicator, it's confusing.
        $progress_bar->minor(0);
        return ($progress_bar, $log_size);
    }
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
    my $logfile_fh = IO::File->new(q{< } . $logfile);
    if (not $logfile_fh) {
        $self->my_die(qq{parse: failed to open $logfile: $!\n});
    }
    my $syslog = Parse::Syslog->new($logfile_fh);
    if (not $syslog) {
        $self->my_die(qq{parse: failed creating syslog parser for }
            . qq{$logfile: $@\n});
    }

    my ($progress_bar, $log_size)
        = $self->create_progress_bar($logfile, $logfile_fh);
    my ($last_update, $next_update) = (0, 0);

    LINE:
    while (my $line = $syslog->next()) {
        $self->{last_timestamp} = $line->{timestamp};
        if (not exists $self->{rules_by_program}->{$line->{program}}) {
            # It's not from a program we're interested in, skip it.
            next LINE;
        }

        if ($progress_bar) {
            my $pos = tell $logfile_fh;
            if ($pos >= $next_update) {
                $last_update = $pos;
                $next_update = $progress_bar->update($pos);
            }
        }

        $self->parse_line($line);
    }

    if ($progress_bar) {
        if ($last_update < $log_size) {
            $progress_bar->update($log_size);
        }
        print qq{\n};
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

=item $parser->post_parsing()

Do anything that needs to be done after parsing: currently it just runs 
$self->prune_queueids().

=back

=cut

sub post_parsing {
    my ($self) = @_;

    $self->prune_queueids();
}

=over 4

=item $parser->update_check_order()

Update the rule order in the database so that more frequently hit rules will be
tried earlier on the next run.  The order rules are tried in does not change
during the lifetime of an ASO::Parser object, but the next object created will
hopefully have a more efficient ordering of rules.  The optimal rule ordering
is dependant on the contents of the logfile currently being parsed, so this
measure may not be 100% accurate.

=back

=cut

sub update_check_order {
    my ($self) = @_;

    $self->{dbix}->txn_begin();

    foreach my $rule (@{$self->{rules}}) {
        $rule->{rule}->hits($rule->{count});
        $rule->{rule}->hits_total($rule->{rule}->hits_total() + $rule->{count});
        $rule->{rule}->update();
    }

    $self->{dbix}->txn_commit();
}

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

See result_cols in ASO::DB::Rule for more details.

=back

=cut

sub parse_result_cols {
    my ($self, $spec, $rule, $number_required, $column_names) = @_;

    my $assignments = {};
    ASSIGNMENT:
    foreach my $assign (split /\s*[,;]\s*/, $spec) {
        if (not length $assign) {
            $self->my_warn(qq{parse_result_cols: empty assignment found in: \n},
                $self->dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        if ($assign !~ m/^\s*(\w+)\s*=\s*(.+)\s*/) {
            $self->my_warn(qq{parse_result_cols: bad assignment found in: \n},
                $self->dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        my ($key, $value) = ($1, $2);
        if ($number_required and $value !~ m/^\d+$/) {
            $self->my_warn(qq{parse_result_cols: $value: not a number in: \n},
                $self->dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        if (not exists $column_names->{$key}) {
            $self->my_die(qq{parse_result_cols: $key: unknown variable in: \n},
                $self->dump_rule_from_db($rule));
            next ASSIGNMENT;
        }
        $assignments->{$key} = $value;
    }
    return $assignments;
}

=over 4

=item $self->parse_line($line)

Try each regex against the line until a match is found, then perform the
associated action.  If no match is found spew a warning.  $line is not a string,
it's the hash returned by Parse::Syslog.  If the option parse_lines_only was
given to new(), the action will not be executed.

=back

=cut

sub parse_line {
    my ($self, $line) = @_;

    RULE:
    # Use the program specific rules first, then the generic rules.
    foreach my $rule (@{$self->{rules_by_program}->{$line->{program}}},
            @{$self->{rules_by_program}->{q{*}}}) {
        if ($line->{text} !~ m/$rule->{regex}/) {
            next RULE;
        }
        $rule->{count}++;

        # TODO: is there a way I can do this without matching twice??
        my @matches = ($line->{text} =~ m/$rule->{regex}/);
        # regex matches start at one, but array indices start at 0.
        # shift the array forward so they're aligned
        unshift @matches, undef;

        if ($self->{parse_lines_only}) {
            return;
        }
        # Hmmm, I can't figure out how to combine the next two lines.
        my $action = $rule->{action};
        return $self->$action($rule, $line, \@matches);
    }

    # Last ditch: complain to the user.  Notice that we deliberately don't 
    # use my_warn because it complicates and clutters the warning.
    warn qq{$0: $self->{current_logfile}: $.: }
        . qq{unparsed line: $line->{program}: $line->{text}\n};
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
    return;
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
    # We also want to save the hostname/IP info
    $self->save($connection, $line, $rule, $matches);
    return;
}

=over  4

=item DISCONNECT

Deal with the remote client disconnecting: enter the connection in the database,
perform any required cleanup, and delete the connection from the state tables.

Currently the main cleanup requirement is to delete any CLONE()d connections
which only have two smtpd entries so they don't hang around in the state tables
causing queueid clashes.  It appears from the logs that the remote client sends
MAIL FROM, RCPT TO, RSET and then starts over; this leaves a state table entry
which will never have any more log entries and wouldn't be disposed of in any
other way.  There are two problems resulting from this: memory is used, albeit
only a small amount, and more importantly when the parser has processed enough
log lines queueids start being reused and these entries cause queueid clashes.

=back

=cut

sub DISCONNECT {
    my ($self, $rule, $line, $matches) = @_;

    if (not $self->pid_exists($line->{pid})) {
        $self->my_warn(qq{disconnection: no connection found for pid }
            . qq{$line->{pid} - perhaps the connect line is in a }
            . qq{previous log file?\n},
            $self->dump_line($line));
        # Does this make sense?  At the moment yes, there aren't any other rules
        # which will deal with these lines anyway.
        return;
    }

    my $connection = $self->get_connection_by_pid($line->{pid});
    # There should NEVER be a queueid.
    if (exists $connection->{queueid}) {
        $self->my_warn(qq{disconnection: PANIC: found queueid: \n},
            $self->dump_connection($connection));
        # Similarly there's no point in failing here.
        return;
    }

    # Commit the connection.
    $connection->{connection}->{end} = $line->{timestamp};
    $connection->{end} = localtime $line->{timestamp};
    $self->fixup_connection($connection);
    $self->commit_connection($connection);
    $self->delete_connection_by_pid($line->{pid});

    if (not exists $connection->{cloned_mails}) {
        return;
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
                    $self->dump_connection($mail),
                    qq{found in queueids:\n},
                    $self->dump_connection($mail_by_queueid),
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
            $connection->{end} = localtime $line->{timestamp};
            $self->fixup_connection($mail);
            $self->commit_connection($mail);
            $self->delete_connection_by_queueid($mail->{queueid});
            next CLONED_MAIL;
        }
    }

    # Ensure we don't have any circular data structures; it's unlikely to
    # happen, but just in case . . .
    delete $connection->{cloned_mails};
    return;
}

=over  4

=item SAVE_BY_QUEUEID

Use the queueid from $rule and @matches to find the correct connection and call
$self->save() with the appropriate arguments - see save() in SUBROUTINES for
more details.  If the connection doesn't exist a connection marked faked will be
created and a warning issued.  If the connection has already reached COMMIT()
but failed is_valid_program_combination(), COMMIT() will be attempted again.

=back

=cut

sub SAVE_BY_QUEUEID {
    my ($self, $rule, $line, $matches) = @_;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    my $connection = $self->get_connection_by_queueid($queueid);

    if (exists $connection->{invalid_program_combination}) {
        return $self->COMMIT($rule, $line, $matches);
    }

    $self->save($connection, $line, $rule, $matches);
    return;
}

=over  4

=item COMMIT

Enter the data into the database.  Entry may be postponed if the mail is a
child waiting to be tracked.

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
        $connection->{commit_waiting_to_be_tracked} = 1;
        return;
    }
    if (not $self->is_valid_program_combination($connection)) {
        # This is generally due to out of order log lines; the next time
        # SAVE_BY_QUEUEID() is called it will try COMMIT() again.
        $connection->{invalid_program_combination}++;
        return;
    }

    # We're ready to commit now.
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
    return;
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

    return;
}

=over  4

=item EXPIRY

Deal with Postfix expiring a mail and returning it to the sender: set a flag
which will be checked later in is_valid_program_combination().

=back

=cut

sub EXPIRY {
    my ($self, $rule, $line, $matches) = @_;
    my $connection;
    my $queueid = $self->get_queueid_from_matches($line, $rule, $matches);
    $connection = $self->get_connection_by_queueid($queueid);
    $self->save($connection, $line, $rule, $matches);
    $connection->{expired} = 1;
    return;
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
    return;
}

=over  4

=item MAIL_PICKED_FOR_DELIVERY

This action represents Postfix picking a mail from the queue to deliver.  This
action is used for both qmgr and cleanup due to out of order log lines.

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
            return;
        }
        # Otherwise we continue onwards as normal.
    }

    # Sometimes I need to create connections here because there are
    # tracked connections where the child shows up before the parent
    # logs the tracking line; there's a similar requirement in track().
    my $connection = $self->get_or_make_connection_by_queueid($queueid,
        faked => $line
    );
    $self->save($connection, $line, $rule, $matches);
    return;
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
    return;
}

=over  4

=item CLONE

Multiple mails may be accepted on a single connection, so each time a mail is
accepted the connection's state table entry must be cloned; if the original data
structure was used the second and subsequent mails would corrupt the data
structure.

The cloned data structure must have rejections prior to the mail's acceptance
cleared from its results, otherwise rejections would be entered twice in the
database.  The cloned data structure will be added to the global state tables
but will also be added to the connection's list of accepted mails; this is to
enable detection of mails where the client gave the RSET command after
recipients were accepted - see the description in DISCONNECT.  The
last_clone_timestamp is also updated to enable timeout handling to determine
whether the timeout applies to an accepted mail or not.

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
    return;
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

Timeout without an accepted mail happens very often, I think it might be due to
ESMTP pipelining where the conversation looks like:

  client:                         server:
  EHLO -->
                                  <-- PIPELINING
  MAIL FROM, RCPT TO, DATA -->
                                  <-- RCPT TO/MAIL FROM rejected.
  connection lost

There may or may not have been a mail accepted and fully transferred before the
timeout.

How to distinguish between a timeout affecting the last mail accepted versus a
timeout affecting a rejected mail?  This _seems_ to work: track the timestamp of
the last CLONE, i.e. accepted mail, and if there's a reject later than that
(skipping the timeout just saved at the start of this subroutine) then the
timeout applies to an unsuccessful mail: don't delete anything, just save() and
finish.  Whew.

There's also the problem of stray cleanup lines being logged after the timeout
line.  This is dealt with by saving the queueid and discarded data structure in
a global state table which is checked in MAIL_PICKED_FOR_DELIVERY.

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

    return;
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
    my $regex = $self->get_result_col($rule, $matches, q{pid_regex});
    return $self->handle_dead_smtpd($line, q{SMTPD_DIED}, $regex);
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
    return;
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
    if ($self->queueid_exists($queueid)) {
        my $connection = $self->get_connection_by_queueid($queueid);
        $self->save($connection, $line, $rule, $matches);
    }
    my $bounce_queueid = $self->get_result_col($rule, $matches, q{child});
    my $bounce_con = $self->get_or_make_connection_by_queueid($bounce_queueid);
    $bounce_con->{bounce_notification} = 1;
    delete $bounce_con->{faked};

    return;
}

=over  4

=item $self->get_connection_col($rule, $matches, $column)

Get the value assigned to $column by connection_cols or connection_data in $rule
and $matches.  Calls my_die() if the column wasn't found; returns the value if
it was.

=back

=cut

sub get_connection_col {
    my ($self, $rule, $matches, $column) = @_;

    my $index;
    foreach my $source (qw(connection_cols connection_data)) {
        if (exists $rule->{$source}->{$column}) {
            $index = $rule->{$source}->{$column};
        }
    }

    if (not defined $index) {
        $self->my_die(qq{get_connection_col: Missing column $column});
    }
    return $matches->[$index];
}

=over  4

=item $self->get_result_col($rule, $matches, $column)

Get the value assigned to $column by result_cols or result_data in $rule and
$matches.  Calls my_die() if the column wasn't found; returns the value if it
was.

=back

=cut

sub get_result_col {
    my ($self, $rule, $matches, $column) = @_;

    my $index;
    foreach my $source (qw(result_cols result_data)) {
        if (exists $rule->{$source}->{$column}) {
            $index = $rule->{$source}->{$column};
        }
    }

    if (not defined $index) {
        $self->my_die(qq{get_result_col: Missing column $column});
    }
    return $matches->[$index];
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

Deal with a timeout of some sort occurring: delete the last accepted mail if
required.

=back

=cut

sub tidy_after_timeout {
    my ($self, $connection) = @_;

    if (not exists $connection->{cloned_mails}) {
        # Nothing has been accepted, so there's nothing to do.
        return;
    }

    # Check the timestamps to see whether there's been a rejection since the
    # previous acceptance.
    if (scalar @{$connection->{results}} >= 2
            and $connection->{results}->[-2]->{timestamp}
                > $connection->{last_clone_timestamp}) {
        return;
    }

    my $last_mail = $connection->{cloned_mails}->[-1];
    if (not $self->queueid_exists($last_mail->{queueid})) {
        return;
    }

    # If there's a qmgr line then the mail was successfully accepted.
    if (exists $last_mail->{programs}->{q{postfix/qmgr}}) {
        return;
    }

    if (not exists $last_mail->{programs}->{q{postfix/cleanup}}) {
        # We haven't seen a cleanup line yet; add this queueid to the list
        # of timed out connections.
        $self->{timeout_queueids}->{$last_mail->{queueid}} = $last_mail;
    }
    # Delete the mail, it's *almost* certainly not going to have any more log
    # entries.
    $self->delete_connection_by_queueid($last_mail->{queueid});
    delete $connection->{cloned_mails}->[-1];

    return;
}

=over  4

=item $self->handle_dead_smtpd($line, $action, $regex)

Deals with an smtpd dying or being killed.  Matches $regex against $line->{text}
and uses $1 as the pid.  Uses $action in error messages.  Calls
delete_dead_smtpd() if the connection exists, returns silently otherwise.

=back

=cut

sub handle_dead_smtpd {
    my ($self, $line, $action, $regex) = @_;

    if ($line->{text} !~ m/$regex/) {
        $self->my_warn(qq{$action: bad line: $line->{text}\n});
        return;
    }

    my $pid = $1;
    if (not $self->pid_exists($pid)) {
        return;
    }
    my $connection = $self->get_connection_by_pid($pid);
    $self->delete_dead_smtpd($connection, $line);

    return;
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
        $connection->{end} = localtime $line->{timestamp};
        $self->fixup_connection($connection);
        $self->commit_connection($connection);
        $self->delete_connection_by_pid($connection->{pid});
    }

}

=over 4

=item $self->maybe_commit_children($parent)

This should be called after commit_connection() for any connection which has
children.  Children which reached COMMIT() before their parent reached TRACK()
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
        if (exists $child->{commit_waiting_to_be_tracked}) {
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
            $self->dump_connection($child));
        return;
    }

    my $parent = $child->{parent};
    if (not defined $parent) {
        $self->my_warn(qq{delete_child_from_parent: missing parent:\n},
            $self->dump_connection($child));
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
            $self->dump_connection($parent),
            qq{child: },
            $self->dump_connection($child));
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
            rule             => $rule,
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
                $self->dump_rule($rule_hash));
        }

        if (not exists $self->{actions}->{$rule_hash->{action}}) {
            $self->my_die(qq{load_rules: unknown action $rule_hash->{action}: },
                $self->dump_rule_from_db($rule));
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
                $self->dump_rule_from_db($rule),
                $self->dump_rule($rule_hash),
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

=over 4

=item $self->dump_connection($connection)

Returns a dump of $connection in a human readable format (currently just uses
Data::Dumper->Dumper()).

=back

=cut

sub dump_connection {
    my ($self, $connection) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$connection], [q{connection}]);
}

=over 4

=item $self->dump_line($line)

Returns a dump of $line in a human readable format (currently just uses
Data::Dumper->Dumper()).

=back

=cut

sub dump_line {
    my ($self, $line) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$line], [q{line}]);
}

=over 4

=item $self->dump_rule($rule)

Returns a dump of $rule in a human readable format (currently just uses
Data::Dumper->Dumper()).  $rule should be a rule returned by load_rules(), not a
rule returned from the database.

=back

=cut

sub dump_rule {
    my ($self, $rule) = @_;

    local $Data::Dumper::Sortkeys = 1;
    return Data::Dumper->Dump([$rule], [q{rule}]);
}

=over 4

=item $self->dump_rule_from_db($rule_from_db)

Returns a dump of $rule_from_db in a human readable format (currently just uses
Data::Dumper->Dumper()).  $rule should be a rule returned from the database, not
a rule returned by load_rules().

=back

=cut

sub dump_rule_from_db {
    my ($self, $rule) = @_;

    local $Data::Dumper::Sortkeys = 1;
    my %columns = $rule->get_columns();
    return Data::Dumper->Dump([\%columns], [q{rule}]);
}

=over 4

=item $self->dump_state($filehandle);

Dumps the current state tables to $filehandle, in the form of a subroutine 
named reload_state() which returns the state tables when run.

=back

=cut

# I used to use Data::Dumper on the entire hash, but it's horrendously slow once
# the number of connections remaining grows, so I now iterate over the elements,
# dumping anything untracked individually and creating a new hash for tracked
# connections because they're interlinked and need to be dumped all at once.
sub dump_state {
    my ($self, $filehandle) = @_;
    my $state = q{};

    $self->prune_timeout_queueids();

    local $Data::Dumper::Sortkeys = 1;
    print $filehandle <<'PREAMBLE';
## vim: set foldmethod=marker :
no warnings q{redefine};
sub reload_state {

PREAMBLE

    foreach my $data_source (@{$self->{data_to_dump}}) {
        my (%tracked, %untracked);
        my $time= localtime;
        my $num_keys = keys %{$self->{$data_source}};
        print $filehandle <<"HEADER";
## Starting dump of $data_source ($num_keys entries)
## $time
    my \%$data_source;
HEADER

        foreach my $queueid (sort keys %{$self->{$data_source}}) {
            my $connection = $self->{$data_source}->{$queueid};
            if (exists $connection->{tracked}) {
                $tracked{$queueid} = $connection;
            } else {
                $untracked{$queueid} = $connection;
            }
        }

        # Print the tracked members
        $time = localtime;
        $num_keys = keys %tracked;
        print $filehandle <<"TRACKED_HEADER";
## Starting dump of tracked $data_source data ($num_keys entries) {{{
## $time
TRACKED_HEADER
        print $filehandle Data::Dumper->Dump([\%tracked], [qq{*$data_source}]);
        print $filehandle qq(## }}}\n);

        # Append the untracked members (usually the majority).
        $time = localtime;
        $num_keys = keys %tracked;
        print $filehandle <<"TRACKED_HEADER";
## Appending dump of untracked $data_source data ($num_keys entries)
## $time
TRACKED_HEADER
        foreach my $untracked_queueid (sort keys %untracked) {
            # This is pretty ugly looking, but should result in 
            #   $queueids{q{38C1F4493}}
            # or similar.
            my $var = qq{\$${data_source}{q{$untracked_queueid}}};
            my $connection = $self->{$data_source}->{$untracked_queueid};
            print $filehandle qq(## $var {{{\n);
            print $filehandle Data::Dumper->Dump([$connection], [$var]);
            print $filehandle qq(## }}}\n);
        }

        $time = localtime;
        print $filehandle <<"FOOTER";
## Finished dumping $data_source data
## $time



FOOTER
    }

    my $results = join q{, },
        map { qq{q($_) => \\\%$_} }
            @{$self->{data_to_dump}};
    print $filehandle <<"POSTAMBLE";

    return ($results);
}

use warnings q{redefine};

1;
POSTAMBLE
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

=cut

=over 4

=item $self->prune_timeout_queueids()

Remove any connection in $self->{timeout_queueids} more than 10 minutes older
than the timestamp of the last log line parsed, so they don't accumulate
forever.  Called from dump_state() before dumping.

=back

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

=item $self->prune_queueids()

Remove any connection in $self->{queueids} which doesn't have any entries after
the cleanup log line and is more than 12 hours older than the timestamp of the
last log line parsed.  These mails don't have any further logging after the
cleanup line, but there aren't any related log lines (e.g. smtpd dying, being
killed, postfix reloaded), so there's no way to identify these short of scanning
all mails periodically.  This will be called automatically by parse(), to stop
these mails accumulating.

=back

=cut

sub prune_queueids {
    my ($self) = @_;

    # Anything earlier this is old.
    my $old_timestamp = $self->{last_timestamp} - (12 * 60 * 60);
    # For a mail to match its programs must equal this.
    my %programs = (
        q{postfix/smtpd}    => 2,
        q{postfix/cleanup}  => 1,
    );

    QUEUEID:
    foreach my $connection ($self->get_all_connections_by_queueid()) {
        # Occasionally we have a connection with no results.  Weird.
        if (scalar @{$connection->{results}} == 0) {
            $self->my_warn(qq{prune_queueids: connection with zero results!},
                $self->dump_connection($connection));
            next QUEUEID;
        }
        # It must be old.
        if ($connection->{results}->[-1]->{timestamp} >= $old_timestamp) {
            next QUEUEID;
        }
        # And the programs which have logged must match.
        if (Compare(\%programs, $connection->{programs})) {
            $self->delete_connection_by_queueid($connection->{queueid});
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

__RESTRICTION_START__ matches:

    /(__QUEUEID__): reject(?:_warning)?: (?:RCPT|DATA) from (?>(__HOSTNAME__)\\[)(?>(__IP__)\\]): (__SMTP_CODE__)(?: __DSN__)?/gx;

__SHORT_CMD__ matches:

    /(?:CONNECT|HELO|EHLO|AUTH|MAIL|RCPT|VRFY|STARTTLS|RSET|NOOP|QUIT|END-OF-MESSAGE|UNKNOWN)/gx;

These are the short form of commands, and are used when Postfix logs a lost
connection or timeout.  It deliberately excludes DATA, because there are
separate rules matching lost connections or timeouts after DATA.

The other names should be reasonably self-explanatory.

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
    # E.g.  <%RND_DIGIT[10].%STATWORD@mail%SINGSTAT.%RND_FROM_DOMAIN>
    #       <45BA63320008E5FC@mail06.sc2.he.tucows.com> (added by postmaster@globo.com)
    #       <848511243547.G96470@flatland.vjopu.com (HELO chignon.gb-media.com [96.168.158.213])>
    $regex =~ s/__MESSAGE_ID__          /.*?/gx;
    # We see some pretty screwed hostnames in HELO commands; in fact just match
    # any damn thing, the hostnames are particularly weird when Postfix rejects
    # them.
    $regex =~ s/__HELO__                /.*?/gx;
#   This doesn't work, as it matches valid addresses, not real world addresses.
#   $regex =~ s/__EMAIL__               /$RE{Email}{Address}/gx;
#   Wibble: from=<<>@inprima.locaweb.com.br>; just match anything as an address.
    $regex =~ s/__EMAIL__               /[^>]*?/gx;
    # This doesn't match, for varous reason - I think numeric subnets are one.
    #$regex =~ s/__HOSTNAME__           /$RE{net}{domain}{-nospace}/gx;
    $regex =~ s/__HOSTNAME__            /$hostname_re/gx;
    # Believe it or not, sometimes the IP address is unknown.
    $regex =~ s/__IP__                  /(?:__IPv4__|__IPv6__|unknown)/gx;
    $regex =~ s/__IPv4__                /(?:::ffff:)?$RE{net}{IPv4}/gx;
    $regex =~ s/__IPv6__                /$ipv6_re/gx;
    $regex =~ s/__SMTP_CODE__           /\\d{3}/gx;
    # 3-9 is a guess.  Turns out that we need at least 10, might as well go to
    # 12 to be sure.
    $regex =~ s/__QUEUEID__             /(?:NOQUEUE|[\\dA-F]{3,12})/gx;
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
            $self->dump_rule($rule),
            qq{in this line:\n},
            $self->dump_line($line),
            qq{for this connection:\n},
            $self->dump_connection($connection),
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

Ensure all results have all the required attributes, by propagating attributes
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
            $self->dump_connection($connection)
        );
        return;
    }

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
    # Check that we have everything we need
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
        $self->my_warn($error_message, $self->dump_connection($connection));
    }

    if ($failure) {
        $self->my_warn(qq{fixup_connection: fixup failed\n});
    } else {
        $connection->{fixuped} = 1;
    }
}

=over 4

=item $self->is_valid_program_combination($connection)

Checks if the combination of programs seen in $connection is valid, i.e.
is a combination which would accept/create a mail and deliver it.  The purpose
is to identify incomplete mails before committing them, so their committal can
be postponed and retried later.  The bulk of the work is really done in
init_globals() when the validation data structure is set up.  There are some
exceptions made, e.g. the EXPIRY action sets a flag which is checked for here,
because otherwise expired mails would never be committed.

=back

=cut

sub is_valid_program_combination {
    my ($self, $connection) = @_;

    # Ensure that expired mails pass this check.
    if (exists $connection->{expired}) {
        return 1;
    }

    my @extra_programs;
    if (exists $connection->{bounce_notification}
            and not exists $connection->{programs}->{q{postfix/bounce}}) {
        # Fake this for the duration of this check.
        push @extra_programs, q{postfix/bounce};
    }
    my $programs_seen = join q{ }, sort keys %{$connection->{programs}},
        @extra_programs;
    if (exists $self->{valid_combos}->{$programs_seen}) {
        $self->{valid_combos}->{$programs_seen}++;
    }
    return exists $self->{valid_combos}->{$programs_seen};
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
        # postfix_action isn't saved in the database, but it is used elsewhere
        # to classify results, so we need to save it.
        postfix_action  => $rule->{postfix_action},
        rule_id         => $rule->{id},
        timestamp       => $line->{timestamp},
        # Sneakily in-line result_data here
        %{$rule->{result_data}},
    );
    if ($self->{debug_results}) {
        # NOTE: every time a new attribute is added here it needs to be stripped
        # out in commit_connection().
        %result = (
            date            => scalar localtime ($line->{timestamp}),
            line            => $line,
            line_number     => $.,
            logfile         => $self->{current_logfile},
            %result,
        );
    }
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
                $self->dump_connection($other_con),
                qq{new:\n},
                $self->dump_connection($connection),
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

=item $self->commit_connection($connection)

Enter the data from $connection into the database (unless skip_inserting_results
was specified).  If $connection is faked, hasn't successfully completed
fixup_connection(), or has already been committed an appropriate error message
will be logged and commit_connection() will abort.  If skip_inserting_results
was specified commit_connection() will finish at this point.  A new row will be
entered in the connections table, and a new row in the results table for each
result where postfix_action is not INFO.

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
            $self->dump_connection($connection)
        );
        return;
    }
    if (not exists $connection->{fixuped}) {
        $self->my_warn(qq{commit_connection: non-fixuped connection\n});
        return;
    }
    if (exists $connection->{committed}) {
        $self->my_warn(qq{commit_connection: previously committed: \n},
            $self->dump_connection($connection)
        );
        return;
    }

    # Occasionally we want to test without committing to the database, because 
    # committing roughly quadruples the run time.
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
        delete @{$result}{@unwanted_attrs};
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
bounce notifications in Postfix 2.2.x will be marked as faked because their
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
@further_lines and a call stack will be wrapped with {{{ and }}}; these are the
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

Checks whether $queueid exists in the state table.

=back

=cut

sub queueid_exists {
    my ($self, $queueid) = @_;
    return exists $self->{queueids}->{$queueid};
}

=over 4

=item $self->get_connection_by_queueid($queueid)

Returns the connection for $queueid in the state tables, or creates a
connection marked faked and logs a warning if one doesn't exist.  Warns if you
try to use NOQUEUE as the queueid.

=back

=cut

sub get_connection_by_queueid {
    my ($self, $queueid) = @_;

    if ($queueid eq q{NOQUEUE}) {
        $self->warn(qq{get_connection_by_queueid: }
            . q{inappropriate queueid $queueid});
    }

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
no restrictions on what can be present in %attributes.  Warns if you try to use
NOQUEUE as the queueid.

=back

=cut

sub make_connection_by_queueid {
    my ($self, $queueid, %attributes) = @_;

    if ($queueid eq q{NOQUEUE}) {
        $self->my_warn(qq{make_connection_by_queueid: }
            . q{inappropriate queueid $queueid});
    }

    if ($self->queueid_exists($queueid)) {
        $self->my_warn(qq{make_connection_by_queueid: $queueid exists\n},
            $self->dump_connection($self->get_connection_by_queueid($queueid)));
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
connection won't be changed in any way, and will still be accessible through
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

=over 4

=item $self->get_all_connections_by_queueid()

Returns all connections saved by queueid in the state tables.

=back

=cut

sub get_all_connections_by_queueid {
    my ($self) = @_;
    return values %{$self->{queueids}};
}

sub get_queueid_from_matches {
    my ($self, $line, $rule, $matches) = @_;

    if (not $rule->{queueid}) {
        $self->my_die(qq{get_queueid_from_matches: no queueid extracted by:\n},
            $self->dump_rule($rule));
    }
    my $queueid     = $matches->[$rule->{queueid}];
    if (not defined $queueid or not $queueid) {
        $self->my_die(qq{get_queueid_from_matches: blank/undefined queueid\n},
            $self->dump_line($line),
            qq{using: },
            $self->dump_rule($rule)
        );
    }
    if ($queueid !~ m/^$self->{queueid_regex}$/o) {
        $self->my_die(qq{get_queueid_from_matches: $queueid !~ __QUEUEID__;\n},
            $self->dump_line($line),
            qq{using: },
            $self->dump_rule($rule)
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

Checks whether a connection is found for $pid in the state tables.

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
            $self->dump_connection($self->get_connection_by_pid($pid)));
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
won't be changed in any way, and will still be accessible through other
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

XXX

A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of each 
problem, one or more likely causes, and any suggested remedies.
(See also  QUOTE \" " INCLUDETEXT "13_ErrorHandling" "XREF83683_Documenting_Errors_"\! Documenting Errors QUOTE \" " QUOTE " in Chapter "  in Chapter  INCLUDETEXT "13_ErrorHandling" "XREF40477__"\! 13.)


=head1 CONFIGURATION AND ENVIRONMENT

No configuration files or environment variables are used by ASO::Parser; all
rules are held in the database alongside the results.  Some modules used by
ASO::Parser may utilise configuration files or environment variables - see those
module's documentation for details.

=head1 DEPENDENCIES

Standard modules shipped with Perl: IO::File, Carp, Data::Dumper,
Regexp::Common, List::Util.

Modules packaged with ASO::Parser: ASO::DB, ASO::ProgressBar.

External modules: Parse::Syslog, Regexp::Common, DBIx::Class (which has many
dependencies), DBI, DBD::whatever, Data::Compare.

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

L<http://www.cs.tcd.ie/~tobinjt/>

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2007 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

1;
