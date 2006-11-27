#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Check::Result;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(q{check_results});
__PACKAGE__->add_columns(
    qw(
        connection_id
        check_id
        result
        warning
        smtp_code
        sender
        recipient
        log_line
        data
    )
);
__PACKAGE__->set_primary_key(qw(connection_id check_id));
# Foreign keys: this table references other tables.
__PACKAGE__->belongs_to(q{connection_id}    => q{ASO::DB::Connection});
__PACKAGE__->belongs_to(q{check_id}         => q{ASO::DB::Check});
1;
