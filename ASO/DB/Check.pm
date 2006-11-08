#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Check;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{checks});
__PACKAGE__->add_columns(
    qw(
        id
        name
        description
        regex
        result_cols
        connection_cols
    )
);
__PACKAGE__->set_primary_key(q{id});
# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Check::Result}
                                            => q{check_id});
1;
