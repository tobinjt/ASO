#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::ParseRule;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{parse_rules});
__PACKAGE__->add_columns(
    qw(
        id
        name
        description
        regex
        action
        rule_order
    )
);
__PACKAGE__->set_primary_key(q{id});
1;
