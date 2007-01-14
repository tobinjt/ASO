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
    my ($self, $key) = @_;
    my %cols = $self->get_cols();
    return grep { exists $cols{$_}->{$key} } keys %cols;
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
