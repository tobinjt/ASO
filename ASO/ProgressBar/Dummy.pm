#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::ProgressBar::Dummy;

# A dummy implementation of the API we need from Term::ProgressBar.



sub new {
    my $self = {};
    bless $self;

    my ($arg) = @_;
    if (not ref $arg) {
        $self->{max} = $arg;
    } else {
        $self->{max} = $arg->{count};
    }

    return $self;
}

sub update {
    my ($self, $count) = @_;
    $self->{count} = $count;
    my $tithe = scalar $self->{max} / 10;
    my $next_count = ($count + $tithe);
    $next_count = $next_count - ($next_count % $tithe);
    return $next_count;
}

sub target {
    my ($self, $max) = @_;
    $self->{max} = $max;
}

1;
