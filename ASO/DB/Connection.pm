#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Connection;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{connections});
__PACKAGE__->add_columns(
    qw(
        id
        ip
        hostname
        helo
        queueid
        start
        end
    )
);
__PACKAGE__->set_primary_key(q{id});
# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                            => q{connection_id});
1;
