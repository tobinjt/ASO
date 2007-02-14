#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Result;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

my %cols = (
    connection_id   => {
    },
    rule_id         => {
        required        => 1,
    },
    result          => {
        required        => 1,
    },
    warning         => {
    },
    smtp_code       => {
        required        => 1,
    },
    # sender changes if the connection is reused.
    sender          => {
        required        => 1,
    },
    recipient       => {
        required        => 1,
    },
    data            => {
    },
);

sub get_cols {
    my ($self) = @_;
    return %cols;
}

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{results});
__PACKAGE__->add_columns(
    keys %cols
);
__PACKAGE__->set_primary_key(qw(connection_id rule_id));
# Foreign keys: this table references other tables.
__PACKAGE__->belongs_to(q{connection_id}    => q{ASO::DB::Connection});
__PACKAGE__->belongs_to(q{rule_id}          => q{ASO::DB::Rule});
1;
