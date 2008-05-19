# $Id$

package ASO::DecisionTree::Output::OptimalOrder;

use warnings;
use strict;
use Carp;

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
    # This is equivalent to the previous two lines.
    ASO::DecisionTree::Output::OptimalOrder->print_optimal_order($tree);

=head1 METHODS

=head2 my @list = $ASO::DecisionTree::Output::OptimalOrder->optimal_order($tree, %options)

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

Standard modules bundled with Perl: L<Carp>.

Modules bundled with ASO: none.

Other modules: none.

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Output::OptimalOrder
