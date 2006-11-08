#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

use lib q{.};
use ASO::DB;
my $dbix = ASO::DB->connect(
    q{dbi:SQLite:dbname=db.sq3},
    {AutoCommit => 0},
);

