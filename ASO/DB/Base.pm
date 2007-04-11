#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

package ASO::DB::Base;

use Carp;

# Keep DBIx::Class happy.
our $pointless_variable;
$pointless_variable = 1;

sub get_cols {
    confess qq{get_cols: must be implemented by derived class\n};
}

sub col_grep {
    my ($self, $tag) = @_;
    my %cols = $self->get_cols();
    my %results;
    foreach my $key (keys %cols) {
        if (exists $cols{$key}->{$tag}) {
            $results{$key} = $cols{$key}->{$tag};
        }
    }
    return \%results;
}

sub required_columns {
    my ($self) = @_;
    my %cols = $self->get_cols();
    return $self->col_grep(q{required});
}

sub nochange_columns {
    my ($self) = @_;
    my %cols = $self->get_cols();
    return $self->col_grep(q{nochange});
}

1;
