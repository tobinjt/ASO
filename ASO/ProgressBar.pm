#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

# This is a wrapper around Term::ProgressBar and ASO::ProgressBar::Dummy; if 
# Term::ProgressBar is available it will be used, otherwise the dummy 
# implementation will.

package ASO::ProgressBar;

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
            . qq{but 'use base $module' didn't.: $@\n};
    }
    $module_loaded = 1;
    last MODULE;
}

if (not $module_loaded) {
    die qq{__PACKAGE__: failed to load any of: }
        . join (q{, }, @modules)
        . qq{\n};
}

1;
