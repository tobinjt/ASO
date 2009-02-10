#!/usr/bin/env perl
# vim: set textwidth=10000 :

# $Id$

use strict;
use warnings;

use lib q{..};
use Data::Dumper;
use feature qw(say);
use ASO::Parser;

my $parser = ASO::Parser->new({
    data_source => q{dbi:SQLite:dbname=../sql/db.sq3}
});

my ($left_arrow, $right_arrow) = qw(-->> <<--);

my $line = q{NOQUEUE: reject: RCPT from nc-71-48-219-106.dhcp.embarqhsd.net[71.48.219.106]: 504 5.5.2 <localhost>: Helo command rejected: need fully-qualified hostname; from=<enjoycool.com@nicecup.com> to=<walshj1@cs.tcd.ie> proto=SMTP helo=<localhost>};
my $regex = q{^__RESTRICTION_START__ (?><(__HELO__)>:) Helo command rejected: need fully-qualified hostname; from=<(__SENDER__)> to=<(__RECIPIENT__)> proto=E?SMTP };#helo=<\5>$};
my $regex_filtered = $parser->ASO::Parser::filter_regex($regex);
say $line;
say $regex;
say $regex_filtered;
if ($line =~ m/$regex_filtered/) {
    say qq{success};
    say qq{\$`: $left_arrow$`$right_arrow};
    say qq{\$&: $left_arrow$&$right_arrow};
    say qq{\$': $left_arrow$'$right_arrow};
    say q{%+: }, Dumper(\%+);
    foreach my $match (1 .. $#-) {
        my $message = qq{\$$match: $left_arrow};
        if (defined $-[$match]) {
            $message .= substr $line, $-[$match], $+[$match] - $-[$match];
        } else {
            $message .= q{undefined};
        }
        say $message . $right_arrow;
    }
} else {
    say qq{failure};
}
