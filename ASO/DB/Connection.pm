#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::DB::Connection - ORM module representing the connections table.

=head1 VERSION

This documentation refers to ASO::DB::Connection version $Id$

=head1 SYNOPSIS

    use ASO::DB;

    my $dbix = ASO::DB->connect(
        q{dbi:SQLite:dbname=../sql/db.sq3},
        {AutoCommit => 0},
    );

    foreach my $connection ($dbix->resultset(q{Connection})->search()) {
        # Do something with $connection
        print $connection->server_ip();
    }

    my $connection = $dbix->resultset(q{Connection})->new_result({
        server_ip   => q{127.0.0.1}.
        # etc. etc.
    });

=head1 DESCRIPTION

ORM module representing the connections table.  Refer to the DBIx::Class
documentation for more details about what can be done with this class.

The entries in this table represent either a connection or a mail delivery
attempt (successful or otherwise).  Essentially there should be an entry in this
table for every single connection (inbound or outbound), and every single mail
accepted, generated, delivered, bounced, or rejected.  There will be more
information about the mail/connection in the associated entries in the results
table: results.connection_id is a foreign key referencing this table.

=cut

use strict;
use warnings;

package ASO::DB::Connection;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

=head1 COLUMNS

The columns in this table are:

=over 4

=item id

Autogenerated primary key, uniquely identifying the row.

=item server_ip

The IP address of the server in the connection.  This will be the local mail
server if the mail was being delivered to us, or the remote mail server if the
mail was being delivered elsewhere.  It may be an IPv4 or IPv6 address.

=item server_hostname

The hostname of the server in the connection.  This will be the local mail
server if the mail was being delivered to us, or the remote mail server if the
mail was being delivered elsewhere.  It may be "unknown" if reverse DNS failed.

=item client_ip

The IP address of the client in the connection.  This will be the local mail
server if the mail was being delivered elsewhere, the remote mail server if the mail
was being delivered to us.  It may be an IPv4 or IPv6 address.

=item client_hostname

The hostname of the server in the connection.  This will be the local mail
server if the mail was being delivered to us, or the remote mail server if the
mail was being delivered elsewhere.  It may be "unknown" if reverse DNS failed.

=item helo

The hostname used in the HELO command.  It will only be non-empty if the local
mail server rejected at least one command.

=item start

The timestamp of the start of the connection.

=item end

The timestamp of the end of the connection.

=back

The columns will have accessor methods autogenerated by DBIx::Class.  The
following columns can be used in result_cols and result_data (see ASO::DB::Rule
for details): server_ip, server_hostname, client_ip, client_hostname, helo.

=cut

my %cols = (
    id                  => {
    },
    server_ip           => {
        required            => 1,
        nochange            => 1,
        silent_overwrite    => undef,
        silent_discard      => {
            q{127.0.0.1}        => 1,
            q{::1}              => 1,
        },
        connection_cols     => 1,
    },
    server_hostname     => {
        required            => 1,
        nochange            => 1,
        silent_overwrite    => undef,
        silent_discard      => {
            q{localhost}        => 1,
        },
        connection_cols     => 1,
    },
    client_ip           => {
        required            => 1,
        nochange            => 1,
        silent_overwrite    => {
            q{127.0.0.1}        => 1,
            q{::1}              => 1,
        },
        silent_discard      => {
            q{127.0.0.1}        => 1,
            q{::1}              => 1,
        },
        connection_cols     => 1,
    },
    client_hostname     => {
        required            => 1,
        nochange            => 1,
        silent_overwrite    => {
            q{localhost}        => 1,
        },
        silent_discard      => {
            q{localhost}        => 1,
        },
        connection_cols     => 1,
    },
    # Believe it or not, sometimes the helo changes.  I wonder if a policy
    # server would be good for this?
    helo                => {
        connection_cols     => 1,
        silent_overwrite    => undef,
    },
    queueid             => {
    },
    start               => {
    },
    end                 => {
    },
);

=head1 SUBROUTINES/METHODS 

See DBIx::Class for an idea of what is possible; this documentation only covers
the subroutines added by this module.

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

=item $self->connection_cols_columns()

Returns a hash reference giving the columns which can be used in connection_cols
and connection_data.

=back

=cut

sub connection_cols_columns {
    my ($self) = @_;
    return $self->col_grep(q{connection_cols});
}

=over 4

=item $self->silent_overwrite_columns()

Returns a hash reference giving the columns which can be silently overridden and
the values they can be overridden by.  Used in update_hash() when saving
connection_cols and connection_data.

=back

=cut

sub silent_overwrite_columns {
    my ($self) = @_;
    return $self->col_grep(q{silent_overwrite});
}

=over 4

=item $self->silent_discard_columns()

Returns a hash reference giving the columns and values which can be silently
discarded.  Used in update_hash() when saving connection_cols and
connection_data.

=back

=cut

sub silent_discard_columns {
    my ($self) = @_;
    return $self->col_grep(q{silent_discard});
}

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{connections});
__PACKAGE__->add_columns(
    keys %cols
);
__PACKAGE__->set_primary_key(q{id});

=over 4

=item $self->results()

Returns all entries in the results table which are part of this connection/mail.

=back

=cut

# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                            => q{connection_id});
1;

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: Carp.

Bundled modules: ASO::DB::Base.

External modules: DBIX::Class.

=head1 INCOMPATIBILITIES

None.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to John Tobin
<tobinjt@cs.tcd.ie>.  Patches are welcome.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2007 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

