#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::ProgressBar - display a progress bar if Term::ProgressBar is available, do
nothing if it isn't.

=head1 VERSION

This documentation refers to ASO::ProgressBar version $Id$

=head1 SYNOPSIS

    use ASO::ProgressBar;
    my $progressbar = ASO::ProgressBar->new(100);
    foreach my $i (1 .. 100) {
        $progressbar->update($i);
    }

=head1 DESCRIPTION

ASO::ProgressBar wraps Term::ProgressBar if it's available, or
ASO::ProgressBar::Dummy if not.  This allows users who don't have
Term::ProgressBar to use the parser without problems, e.g. on Windows.

=head1 SUBROUTINES/METHODS 

See Term::ProgressBar for full details, ASO::ProgressBar::Dummy for the
guaranteed minimal interface.

=head1 DIAGNOSTICS

=over 4

=item __PACKAGE__: failed to load any of: <list of modules>

No usable module was found for this module to wrap.  This means your
installation is broken in some fashion, because ASO::ProgressBar::Dummy is
packaged with this module.

=item __PACKAGE__: 'use $module' succeeded, but 'use base $module' didn't: $@

For some reason there was no error from 'use $module;', but 'use base $module;'
failed.  This really shouldn't happen - hopefully there'll be some more
information in the error message.

=back

=head1 CONFIGURATION AND ENVIRONMENT

No configuration required.

ASO::ProgressBar::Dummy should be automatically installed, but it doesn't
provide a progress bar (it's a dummy implementation).

If Term::ProgressBar is available it will be used automatically.

=head1 DEPENDENCIES

Modules packaged with ASO: ASO::ProgressBar::Dummy.

Optional external modules: Term::ProgressBar.

=head1 INCOMPATIBILITIES

None known thus far.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module. 
Please report problems to John Tobin (<tobinjt@cs.tcd.ie>).
Patches are welcome.

=head1 SEE ALSO

Term::ProgressBar, ASO::ProgressBar::Dummy.

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

use strict;
use warnings;

# This is a wrapper around Term::ProgressBar and ASO::ProgressBar::Dummy; if 
# Term::ProgressBar is available it will be used, otherwise the dummy 
# implementation will.

package ASO::ProgressBar;

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

my $module_loaded = 0;
my @modules = qw(Term::ProgressBar ASO::ProgressBar::Dummy);

MODULE:
foreach my $module (@modules) {
    eval qq{use $module;};
    if ($@) {
        next MODULE;
    }
    eval qq{use base q($module);};
    if ($@) {
        die qq{__PACKAGE__: 'use $module' succeeded, }
            . qq{but 'use base $module' didn't: $@\n};
    }
    $module_loaded = 1;
    last MODULE;
}

if (not $module_loaded) {
    die q{__PACKAGE__: failed to load any of: }
        . join (q{, }, @modules)
        . qq{\n};
}

1;
