#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Connection;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

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
    helo                => {
        nochange            => 1,
        connection_cols     => 1,
    },
    queueid             => {
    },
    start               => {
    },
    end                 => {
    },
);

sub get_cols {
    my ($self) = @_;
    return %cols;
}

sub connection_cols_columns {
    my ($self) = @_;
    return $self->col_grep(q{connection_cols});
}

sub silent_overwrite_columns {
    my ($self) = @_;
    return $self->col_grep(q{silent_overwrite});
}

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
# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                            => q{connection_id});
1;
