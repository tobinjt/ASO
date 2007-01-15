#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Rule;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{rules});
__PACKAGE__->add_columns(
    qw(
        id
        name
        description
        program
        regex
        result_cols
        connection_cols
        action
        queueid
        rule_order
        priority
        result
        result_data
        connection_data
    )
);
__PACKAGE__->set_primary_key(q{id});
# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                            => q{rule_id});
1;
