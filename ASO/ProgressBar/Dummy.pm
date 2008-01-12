#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::ProgressBar::Dummy - implements a minimal subset of Term::ProgressBar's
API, but doesn't display a progress bar.

=head1 VERSION

This documentation refers to ASO::ProgressBar::Dummy version $Id$

=head1 SYNOPSIS

    # You shouldn't actually be using this module directly; use ASO::ProgressBar
    # instead.

=head1 DESCRIPTION

ASO::ProgressBar::Dummy implements a minimal subset of Term::ProgressBar's API.
This allows users who don't have Term::ProgressBar to use the parser without
problems, e.g. on Windows.

=head1 SUBROUTINES/METHODS 

=cut

use strict;
use warnings;

package ASO::ProgressBar::Dummy;

=over 4

=item ASO::ProgressBar::Dummy->new($max), ASO::ProgressBar::Dummy->new({count => $max})

Takes either a number specifying the hightest value in the progress bar, or a
hash of options - of those options, only count is used.

=back

=cut

sub new {
    my $self = {};
    my $class = shift @_;
    bless $self, $class;

    my ($arg) = @_;
    if (not ref $arg) {
        $self->{max} = $arg;
    } else {
        $self->{max} = $arg->{count};
    }

    return $self;
}

=over 4

=item $progressbar->minor($ignored)

Present only for compatibility with Term::ProgressBar.

=back

=cut

sub minor {
}

=over 4

=item $progressbar->update($current)

Change how far along the progress bar the caller has gotten, in the same units
as the maximum passed to new().  Returns the next value update() should be
called at.  No check is performed to ensure that it is less than the max value;
if it isn't, the return value will probably be weird.  This doesn't display a
progress bar, at all.

=back

=cut

sub update {
    my ($self, $count) = @_;
    $self->{count} = $count;
    my $tithe = scalar $self->{max} / 10;
    my $next_count = ($count + $tithe);
    $next_count = $next_count - ($next_count % $tithe);
    return $next_count;
}

=over 4

=item $progressbar->target($max)

Changes the highest value of the progress bar.  No check is performed to ensure
that it is greater than the current value.

=back

=cut

sub target {
    my ($self, $max) = @_;
    $self->{max} = $max;
}

=head1 DIAGNOSTICS

No intentional diagnotics, though it will probably spew warnings if you abuse
the arguments given to methods.  It may also die pass a zero to new(), so don't
do that.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

None.

=head1 INCOMPATIBILITIES

None known thus far.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module. 
Please report problems to John Tobin (<tobinjt@cs.tcd.ie>).
Patches are welcome.

=head1 SEE ALSO

Term::ProgressBar, ASO::ProgressBar.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2007 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

1;
