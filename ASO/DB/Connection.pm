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
    },
    server_hostname     => {
        required            => 1,
        nochange            => 1,
    },
    client_ip           => {
        required            => 1,
        nochange            => 1,
    },
    client_hostname     => {
        required            => 1,
        nochange            => 1,
    },
    helo                => {
        nochange            => 1,
    },
    queueid             => {
        nochange            => 1,
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
