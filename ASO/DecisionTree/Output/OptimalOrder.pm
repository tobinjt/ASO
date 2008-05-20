# $Id$

package ASO::DecisionTree::Output::OptimalOrder;

use warnings;
use strict;
use Carp;
use Data::Dumper;
use List::Util qw(sum);
use IO::File;

=head1 NAME

ASO::DecisionTree::Output::OptimalOrder - Perform Principal Component Analysis on a tree
built by ASO::DecisionTree to generate an optimal ordering of restrictions.

=head1 VERSION

Version $Id$

=cut

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 SYNOPSIS

    use ASO::DecisionTree::Output::OptimalOrder;
    my $tree = ...; # See ASO::DecisionTree.

    my $object = ASO::DecisionTree::Output::OptimalOrder->new();
    my @list = $object->optimal_order($tree);
    print map { qq{$_->{restriction_name}, # $_->{percentage}\n} } @list;
    # This produces similar output.
    $object->print_optimal_order($tree);

=head1 METHODS

=cut

=head2 my $object = ASO::DecisionTree::Output::OptimalOrder->new()

Create a new ASO::DecisionTree::Output::OptimalOrder object.  Takes no
arguments.

=cut

sub new {
    my ($package) = @_;

    if (@_ != 1) {
        my $num_args = @_ - 1;
        croak qq{new(): expecting zero arguments, not $num_args\n};
    }

    my $self = {};
    bless $self, $package;
    return $self;
}

=head2 my @list = $object->optimal_order($tree, %options)

Returns a list of hash references, optimally ordered to reject mail as soon as
possible, respecting cluster groups and the requirement to apply less stringent
restrictions to local clients.  Each hash contains the following:

=over 4

=item restriction_name

The name of the restriction to use.

=item percentage

The percentage of rejections attributed to this restriction.

=item count

The number of rejections attributed to this restriction.

=item total

The total number of rejections - this should be the same across all hashes.

=back

%options is optional and can contain the following:

=over 4

=item ignore_info_nodes => boolean (default false)

Info nodes represent restrictions which weren't useful in rejecting mail: if
this key is true info nodes will be excluded from the list; if it's false they
will be included.

=back

=cut

sub optimal_order {
    my ($self, $tree, %options) = @_;

    my %defaults = $self->get_oo_options();

    %options = $self->validate_options(\%defaults, \%options);
    # As far as I can see the optimal order is always going to be the rightmost
    # path down the tree, i.e. taking the true branch everywhere.
    my $total = $self->get_num_rows($tree);

    my @restrictions;
    my $node = $tree;
    NODE:
    while (1) {
        if ($options{ignore_info_nodes} and $node->is_info()) {
            $node = $node->info_branch();
            next NODE;
        }
        my %restriction = (
            total               => $total,
            restriction_name    => $node->label(),
        );
        if ($node->is_info()) {
            $restriction{count}      = 0;
            $restriction{percentage} = 0;
            push @restrictions, \%restriction;
            $node = $node->info_branch();
            next NODE;
        }
        if ($node->is_leaf()) {
            $restriction{count}      = $self->get_num_rows($node);
            $restriction{percentage} = $restriction{count} * 100 / $total;
            push @restrictions, \%restriction;
            last NODE;
        }
        if ($node->is_branch()) {
            my $true_child = $node->true_branch();
            $restriction{count}      =   $self->get_num_rows($node)
                                       - $self->get_num_rows($true_child);
            $restriction{percentage} = $restriction{count} * 100 / $total;
            push @restrictions, \%restriction;
            $node = $true_child;
            next NODE;
        }
        croak qq{optimal_order: cannot deal with node: } . Dumper($node);
    }

    return @restrictions;
}

=head2 $object->print_optimal_order($tree, %options)

Prints the results of optimal_order().  Each hash returned will be formatted as:

    $restriction_name, # $percentage%, $percentage_so_far

Takes the same arguments as optimal_order(), plus:

=over 4

=item filehandle

A filehandle to print to; takes precedence over C<filename>.

=item filename

A filename to open and print to; superseded by C<filehandle>.

=back

If neither C<filehandle> nor C<filename> are specified the default filehandle
will be used (C<STDOUT> unless changed by C<select>).

=cut

sub print_optimal_order {
    my ($self, $tree, %options) = @_;

    my %oo_options = $self->get_oo_options();
    my %defaults   = (
        %oo_options,
        filename            => undef,
        filehandle          => undef,
    );

    %options = $self->validate_options(\%defaults, \%options);
    %oo_options = map { $_ => $options{$_} } keys %oo_options;

    my @list = $self->optimal_order($tree, %oo_options);

    if (not defined $options{filehandle}) {
        if (defined $options{filename}) {
            # Add a > if necessary, but allow the caller to specify >> or | if
            # they desire.
            my $mode = $options{filename} =~ m/^\s*[>|]/ ? q{} : q{> };
            $options{filehandle} = IO::File->new($mode . $options{filename})
                or croak qq{Failed to open $options{filename}: $!\n};
        } else {
            # This should reopen the current default filehandle.
            # This should not be so hairy; filehandles should have been first
            # class types from the start.
            my $fileno = fileno select;
            $options{filehandle} = IO::File->new(qq{>&$fileno})
                or croak qq{Reopening file descriptor $fileno failed: $!\n};
        }
    }

    my $percentage_so_far = 0;
    foreach my $result (@list) {
        $percentage_so_far += $result->{percentage};
        printf { $options{filehandle} } qq{%s, # %.4f%%, %.4f\n},
                                            $result->{restriction_name},
                                            $result->{percentage},
                                            $percentage_so_far;
    }
    return;
}

=head1 HELPER METHODS

These are helper methods which shouldn't be called directly, they're used
internally.

=cut

=head2 $object->get_num_rows($tree)

Returns the number of rows in $tree.  Will C<croak> on failure.

=cut

sub get_num_rows {
    my ($self, $subtree) = @_;

    if ($subtree->is_info()) {
        return $self->get_num_rows($subtree->info_branch());
    }
    if ($subtree->is_leaf()) {
        return sum(map { $_->{count} } @{$subtree->leaf_branch()}) || 0;
    }
    if ($subtree->is_branch()) {
        return    $self->get_num_rows($subtree->true_branch())
                + $self->get_num_rows($subtree->false_branch());
    }
    croak qq{get_num_rows: unable to deal with tree: } . Dumper($subtree);
}

=head2 $object->validate_options(\%valid_options, \%passed_options)

Validate options passed to a subroutine.  Returns (%valid_options,
%passed_options) if valid, will C<croak> otherwise.  Usage example:

    my ($self, %options) = @_;
    my %defaults = (
        ...
    );
    %options = $self->validate_options(\%defaults, \%options);

=cut

sub validate_options {
    my ($package, $valid_options, $passed_options) = @_;

    my %options = %{$valid_options};
    foreach my $arg (keys %{$passed_options}) {
        if (not exists $valid_options->{$arg}) {
            croak qq{unknown option $arg\n};
        }
        $options{$arg} = $passed_options->{$arg};
    }
    return %options;
}

=head2 $object->get_oo_options()

Returns the options accepted by optimal_order(), so they don't have to be
repeated all over the place.

=cut

sub get_oo_options {
    my ($self) = @_;

    if (@_ != 1) {
        my $num_args = @_ - 1;
        croak qq{get_oo_options(): expecting zero arguments, not $num_args\n};
    }

    my %defaults = (
        ignore_info_nodes   => 0,
    );

    return %defaults;
}

=head1 AUTHOR

John Tobin, C<< <tobinjt at cs.tcd.ie> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-aso-decisiontree-output-pca at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ASO-DecisionTree-Output-OptimalOrder>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc ASO::DecisionTree::Output::OptimalOrder

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=ASO-DecisionTree-Output-OptimalOrder>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/ASO-DecisionTree-Output-OptimalOrder>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/ASO-DecisionTree-Output-OptimalOrder>

=item * Search CPAN

L<http://search.cpan.org/dist/ASO-DecisionTree-Output-OptimalOrder>

=back

=head1 DEPENDENCIES

Standard modules bundled with Perl: L<Carp>, L<Data::Dumper>, L<List::Util>,
L<IO::File>.

Modules bundled with ASO: none.

Other modules: none.

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Output::OptimalOrder
