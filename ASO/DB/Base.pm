#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::DB::Base - Base class for ORM modules.

=head1 VERSION

Version $Id$

=head1 SYNOPSIS

    package ASO::DB::Something;
    use base q{DBIx::Class};
    use base q{ASO::DB::Base};

    my %cols = (
        # columns and attributes
    );

    sub get_cols {
        my ($self) = @_;
        return %cols;
    }

    # Add any other methods here.

    __PACKAGE__->load_components(qw(PK::Auto Core));
    __PACKAGE__->table(q{TABLE});
    __PACKAGE__->add_columns(
        keys %cols
    );
    __PACKAGE__->set_primary_key(q{PRIMARY KEY});
    # Foreign keys: other tables reference this one.
    __PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                                => q{connection_id});
    1;

=head1 DESCRIPTION

Base class for ORM modules containing some methods used by some or all
subclasses.

=head1 SUBROUTINES/METHODS 

=cut

use strict;
use warnings;

package ASO::DB::Base;

use Carp;

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

# Keep DBIx::Class happy.
our $pointless_variable;
$pointless_variable = 1;

=over 4

=item $self->get_cols()

In subclasses it returns the hash reference listing the columns in the table and
their attributes; it must be overridden as the base version just dies.  In
general the hash returned should not be modified.

=back

=cut

sub get_cols {
    confess qq{get_cols: must be implemented by derived class\n};
}

# Sneakily call get_cols() to improve coverage.
eval { get_cols(); };

=over 4

=item $self->col_grep($attribute)

Returns a hash reference containing the subset of the table columns which have
$attribute set.

=back

=cut

sub col_grep {
    my ($self, $attribute) = @_;
    my %cols = $self->get_cols();
    my %results;
    foreach my $key (keys %cols) {
        if (exists $cols{$key}->{$attribute}) {
            $results{$key} = $cols{$key}->{$attribute};
        }
    }
    return \%results;
}

=over 4

=item $self->required_columns()

Returns the columns which are required in the table, i.e. inserting a row
without missing any of these columns is an error.

=back

=cut

sub required_columns {
    my ($self) = @_;
    return $self->col_grep(q{required});
}

=over 4

=item $self->nochange_columns()

Returns the columns whose values, once set, should not change.

=back

=cut

sub nochange_columns {
    my ($self) = @_;
    return $self->col_grep(q{nochange});
}

1;

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: L<Carp>.

External modules: L<DBIx::Class>.

=head1 INCOMPATIBILITIES

None.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to John Tobin
<tobinjt@cs.tcd.ie>.  Patches are welcome.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2008 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

