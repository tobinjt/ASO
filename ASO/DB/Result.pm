#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::DB::Result - ORM module representing the connections table.

=head1 VERSION

This documentation refers to ASO::DB::Result version $Id$

=head1 SYNOPSIS

    use ASO::DB;

    my $dbix = ASO::DB->connect(
        q{dbi:SQLite:dbname=../sql/db.sq3},
        {AutoCommit => 1},
    );

    foreach my $result ($dbix->resultset(q{Result})->search()) {
        # Do something with $result
        print $result->recipient();
    }

    my $result = $dbix->resultset(q{Result})->new_result({
        recipient   => q{127.0.0.1}.
        # etc. etc.
    });

=head1 DESCRIPTION

ORM module representing the results table.  Refer to the L<DBIx::Class>
documentation for more details about what can be done with this class.

The entries in this table represent data extracted from log lines.  There should
be one entry for every action Postfix took when handling a mail or connection.

=head1 COLUMNS

The columns in this table are:

=over 4

=item connection_id

Refers to the entry in the connections table which this result is related to.

=item rule_id

Refers to the rule in the rules table which created this result.

=item postfix_action

The action Postfix would have taken to produce the log entry which generated
this result.

=item warning

Whether the rejection was real or not, i.e. was warn_if_reject used before the
restriction.

=item smtp_code

The SMTP code associated with the result; this is faked for many results where
Postfix doesn't log it.

=item sender

The sender address.

=item recipient

The recipient address.

=item message_id

The message-id of the mail.

=item timestamp

When the line was logged.

=item data

Any data not covered by the other columns.

=back

The columns will have accessor methods auto-generated by L<DBIx::Class>.  The
following columns can be used in result_cols and result_data (see
L<ASO::DB::Rule> for details): smtp_code, sender, recipient, message_id, data.

=cut

use strict;
use warnings;

package ASO::DB::Result;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

my %cols = (
    id              => {
        sql             => q{NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE},
        type            => q{integer},
    },
    # Reference to connections->id
    connection_id   => {
        sql             => q{NOT NULL},
        type            => q{integer},
    },
    # Reference to rules->id
    rule_id         => {
        required        => 1,
        sql             => q{NOT NULL},
        type            => q{integer},
    },
    # True if it was a warning, false if it took effect
    warning         => {
        sql             => q{NOT NULL DEFAULT 0},
        type            => q{integer},
    },
    # The SMTP code sent to the client
    smtp_code       => {
        required        => 1,
        result_cols     => 1,
        sql             => q{NOT NULL},
        type            => q{text},
    },
    # The MAIL FROM: <address>; may be <>, so can be null.
    # sender changes if the connection is reused.
    sender          => {
        required        => 1,
        result_cols     => 1,
        sql             => q{},
        type            => q{text},
    },
    # The size of delivered mails.  Will be null for rejection mails.
    size            => {
        result_cols     => 1,
        sql             => q{},
        type            => q{integer},
    },
    # The recipient; checks after DATA won't have a recipient, so allow it to
    # be null.
    recipient       => {
        required        => 1,
        result_cols     => 1,
        sql             => q{},
        type            => q{text},
    },
    # The message-id.  Useful when trying to figure whether the mail is a
    # bounce or not, I dunno if it's of any great use otherwise.  Will be NULL
    # for most results.
    message_id      => {
        result_cols    => 1,
        sql             => q{},
        type            => q{text},
    },
    # A place to plop anything not already covered.
    data            => {
        result_cols    => 1,
        sql             => q{},
        type            => q{text},
    },
    # The timestamp of the result
    timestamp       => {
        required        => 1,
        sql             => q{},
        type            => q{integer},
    },

    # Pseudo-columns which don't exist in the table but are used elsewhere.

    # child is used in TRACK and BOUNCE.
    child           => {
        result_cols     => 1,
    },
    # used in SMTPD_DIED
    pid             => {
        result_cols     => 1,
    },
);

=head1 SUBROUTINES/METHODS 

See L<DBIx::Class> for an idea of what is possible; this documentation only
covers the subroutines added by this module.  

=over 4

=item $self->get_cols()

Returns a hash reference giving the columns in the connections table and their
associated attributes.  Modifying the returned hash is a bad idea.

=back

=cut

sub get_cols {
    my ($self) = @_;
    return %cols;
}

=over 4

=item $self->result_cols_columns()

Returns a hash reference giving the columns which can be used in result_cols and
result_data.

=back

=cut

sub result_cols_columns {
    my ($self) = @_;
    return $self->col_grep(q{result_cols});
}

=over 4

=item $self->table_name()

Returns the name of the table in the database, "connections" in this case.

=back

=cut

sub table_name {
    my ($self) = @_;
    return q{results};
}

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(table_name());
__PACKAGE__->add_columns(
    grep { exists $cols{$_}->{sql} } keys %cols
);
__PACKAGE__->set_primary_key(qw(connection_id rule_id));

=head1 ADDITIONAL ACCESSORS

In addition to the columns described above the following accessors are provided:

=over 4

=item $result->rule()

Returns the rule corresponding to $result->rule_id().

=item $result->connection()

Returns the connection corresponding to $result->connection_id().

=back

=cut

# Foreign keys: this table references other tables.
# ->rule() is the accessor; it returns an ASO::DB::Rule based on the result's
# rule_id.
__PACKAGE__->belongs_to(q{connection}   => q{ASO::DB::Connection}
                                        => q{connection_id});
__PACKAGE__->belongs_to(q{rule}         => q{ASO::DB::Rule}
                                        => q{rule_id});
1;

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: L<Carp>.

Bundled modules: L<ASO::DB::Base>.

External modules: L<DBIx::Class>.

=head1 SEE ALSO

L<DBIx::Class>.

=head1 INCOMPATIBILITIES

None.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to John Tobin
<tobinjt@cs.tcd.ie>.  Patches are welcome.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2008 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

