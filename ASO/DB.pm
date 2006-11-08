#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB;
use base qw(DBIx::Class::Schema);

my @classes = qw(
    Check
    Connection
    Check::Result
);

# load the various classes.
__PACKAGE__->load_classes(@classes);

1;
