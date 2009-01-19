#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

use Regexp::Common qw(number);

my $hms_re = qr/^($RE{num}{int}+):($RE{num}{int}+):($RE{num}{real}+)$/x;
my  $ms_re = qr/^                 ($RE{num}{int}+):($RE{num}{real}+)$/x;

sub time2secs {
    my ($time) = @_;
    my $secs;

    if ($time =~ m/$hms_re/) {
        my ($hour, $minute, $second) = ($1, $2, $3);
        $secs = ($hour * 60 * 60) + ($minute * 60) + $second;
    } elsif ($time =~ m/$ms_re/) {
        my ($minute, $second) = ($1, $2);
        $secs = ($minute * 60) + $second;
    } else {
        die qq{$0: time2secs: failed to parse $time\n};
    }

    return $secs;
}
