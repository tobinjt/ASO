# $Id$

package ASO::DecisionTree::Output::OptimalOrder;

use warnings;
use strict;
use Carp;
use Data::Dumper;
use List::Util qw(sum);

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

    my @list = ASO::DecisionTree::Output::OptimalOrder->optimal_order($tree);
    print map { qq{$_->{restriction_name}, # $_->{percentage}\n} } @list;
    # This produces similar output.
    ASO::DecisionTree::Output::OptimalOrder->print_optimal_order($tree);

=head1 METHODS

=cut

=head2 my @list = ASO::DecisionTree::Output::OptimalOrder->optimal_order($tree, %options)

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
    my ($package, $tree, %options) = @_;

    %options = $package->validate_options(%options);
    # As far as I can see the optimal order is always going to be the rightmost
    # path down the tree, i.e. taking the true branch everywhere.
    my $total = $package->get_num_rows($tree);

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
            $restriction{count}      = $package->get_num_rows($node);
            $restriction{percentage} = $restriction{count} * 100 / $total;
            push @restrictions, \%restriction;
            last NODE;
        }
        if ($node->is_branch()) {
            my $true_child = $node->true_branch();
            $restriction{count}      =   $package->get_num_rows($node)
                                       - $package->get_num_rows($true_child);
            $restriction{percentage} = $restriction{count} * 100 / $total;
            push @restrictions, \%restriction;
            $node = $true_child;
            next NODE;
        }
        croak qq{optimal_order: cannot deal with node: } . Dumper($node);
    }

    return @restrictions;
}

=head2 ASO::DecisionTree::Output::OptimalOrder->print_optimal_order($tree, %options)

Prints the results of optimal_order() to the default print filehandle (C<STDOUT>
unless you've changed it with C<select>).  Each hash returned will be formatted
as:

    $restriction_name, # $percentage%, $percentage_so_far

=cut

sub print_optimal_order {
    my ($package, $tree, %options) = @_;

    my @list = $package->optimal_order($tree, %options);
    my $percentage_so_far = 0;
    foreach my $result (@list) {
        $percentage_so_far += $result->{percentage};
        printf qq{%s, # %.4f%%, %.4f\n},    $result->{restriction_name},
                                            $result->{percentage},
                                            $percentage_so_far;
    }
}

=head1 HELPER METHODS

These are helper methods which shouldn't be called directly, they're used
internally.

=cut

=head2 ASO::DecisionTree::Output::OptimalOrder->get_num_rows($tree)

Returns the number of rows in $tree.  Will C<croak> on failure.

=cut

sub get_num_rows {
    my ($package, $subtree) = @_;

    if ($subtree->is_info()) {
        return $package->get_num_rows($subtree->info_branch());
    }
    if ($subtree->is_leaf()) {
        return sum(map { $_->{count} } @{$subtree->leaf_branch()}) || 0;
    }
    if ($subtree->is_branch()) {
        return    $package->get_num_rows($subtree->true_branch())
                + $package->get_num_rows($subtree->false_branch());
    }
    croak qq{get_num_rows: unable to deal with tree: } . Dumper($subtree);
}

=head2 ASO::DecisionTree::Output::OptimalOrder->validate_options(%options)

Validate options passed to optimal_order() or print_optimal_order().  Returns
%options if valid, will C<croak> otherwise.

=cut

sub validate_options {
    my ($package, %options) = @_;

    my %defaults = (
        ignore_info_nodes   => 0,
    );

    foreach my $arg (keys %options) {
        if (not exists $defaults{$arg}) {
            croak qq{optimal_order: unknown option $arg\n};
        }
    }
    %options = (%defaults, %options);

    return %options;
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

Standard modules bundled with Perl: L<Carp>, L<Data::Dumper>, L<List::Util>.

Modules bundled with ASO: none.

Other modules: none.

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Output::OptimalOrder
