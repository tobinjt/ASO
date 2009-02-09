#!/usr/bin/env perl
# vim: set textwidth=10000 :

# $Id$

use strict;
use warnings;

use lib q{..};
use Data::Dumper;
use ASO::Parser;

my $parser = ASO::Parser->new({
    data_source => q{dbi:SQLite:dbname=../sql/db.sq3}
});

my $line = q{NOQUEUE: reject_warning: RCPT from scan14.cs.tcd.ie[134.226.54.40]: 550 5.7.1 <134.226.54.40>: Helo command rejected: You are not in my network.  Go away.; from=<Niaz> to=<notredamean@gmail.com> proto=SMTP helo=<134.226.54.40>};
my $regex = q{^__RESTRICTION_START__ <__HELO__>: Helo command rejected: You are not in my network. +Go away.; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP helo=<(__HELO__)>$};
my $regex_filtered = ASO::Parser::filter_regex($parser, $regex);
warn $regex_filtered, qq{\n};
if ($line =~ m/$regex_filtered/) {
    warn qq{success\n};
    warn qq{\$`: $`\n};
    warn qq{\$&: $&\n};
    warn qq{\$': $'\n};
    warn q{%+: }, Dumper(\%+);
} else {
    warn qq{failure\n};
}
