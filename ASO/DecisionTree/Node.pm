# $Id$

package ASO::DecisionTree::Node;

use warnings;
use strict;
use Data::Dumper;
use Carp;

=head1 NAME

ASO::DecisionTree::Node - Represents a single node in a Decision Tree created by
ASO::DecisionTree.

=head1 VERSION

Version $Id$

=cut

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 SYNOPSIS

Objects of this class represent nodes in a Decision Tree constructed by
ASO::DecisionTree.  Some sample code should give a feel for the class:

    sub print_tree {
        my ($tree, $indent) = @_;
        # Print the current node's label.
        print q{ } x ($indent * 4), $tree->label(), qq{\n};
        # If this is a leaf node we're finished.
        if ($tree->is_leaf()) {
            my $rows = $tree->leaf_branch();
            # Do something with the data if necessary.
            return;
        }
        # Info nodes only have one branch.
        if ($tree->is_info()) {
            print_tree($tree->info_branch(), $indent + 1);
            return;
        }
        # Branch nodes have two branches.
        if ($tree->is_branch()) {
            print_tree($tree->false_branch(), $indent + 1);
            print_tree($tree->true_branch(), $indent + 1);
            return;
        }
        # No further options now, but there may be in future.
    }

Currently nodes are read-only once created, though there's nothing stopping you
delving into their internals if you feel the need.

=cut

=head1 METHODS

=head2 my $node = ASO::DecisionTree::Node->new()

Create a new ASO::DecisionTree::Node object.  Takes the following arguments:

=over 4

=item label => string

The label to be displayed when displaying the tree.

=item column => integer

The column in each row which the decision is to be made on.

=item branch_node => boolean

True if this node is a branch node.

=item true_branch => $true_node

The branch to follow when the column in the row is true.  This should be an
ASO::DecisionTree::Node object.

=item false_branch => $false_node

The branch to follow when the column in the row is false.  This should be an
ASO::DecisionTree::Node object.

=item leaf_node => boolean

True if this node is a leaf node.

=item leaf_branch => \@rows

The data associated with the leaf node.  The format of @rows is described in
L<ASO::DecisionTree/DATA STRUCTURES>.

=item info_node => boolean

True if this node is a info node, i.e. it doesn't make a decision.  Info nodes
are used to retain information about columns which aren't useful in
classification.

=item info_branch => $info_node

The branch to follow when the info_node is true.  This should be an
ASO::DecisionTree::Node object.

=back

Required arguments: C<label>.

You must also specify one of the following groups of arguments:

=over 4

=item leaf_node, leaf_branch

=item column, branch_node, true_branch, false_branch

=item column, info_node, info_branch

=back

=cut

sub new {
    my ($package, %args) = @_;

    my %default_args = (
        label           => undef,
        column          => undef,
        branch_node     => 0,
        true_branch     => undef,
        false_branch    => undef,
        leaf_node       => 0,
        leaf_branch     => undef,
        info_node       => 0,
        info_branch     => undef,
    );

    foreach my $arg (keys %args) {
        if (not exists $default_args{$arg}) {
            croak qq{${package}::new(): unknown parameter $arg\n};
        }
    }

    my @required_args = qw(label);
    my %required_args;
    foreach my $required_arg (@required_args) {
        if (not exists $args{$required_arg}) {
            croak qq{${package}::new(): required parameter }
                . qq{$required_arg missing\n};
        }
        $required_args{$required_arg} = delete $args{$required_arg};
    }

    my @valid_groups = (
        [qw(leaf_node leaf_branch)],
        [qw(column branch_node true_branch false_branch)],
        [qw(column info_node info_branch)],
    );

    my $arg_keys = join q{,}, sort keys %args;
    my $is_valid_group = 0;
    VALID_GROUP:
    foreach my $valid_group (@valid_groups) {
        my $valid_keys = join q{,}, sort @{$valid_group};
        if ($valid_keys eq $arg_keys) {
            $is_valid_group = 1;
            last VALID_GROUP;
        }
    }
    if (not $is_valid_group) {
        local $Data::Dumper::Sortkeys = 1;
        croak qq{${package}::new(): bad combination of arguments:\n}
              . Data::Dumper->Dump([\%args], [q{*arguments}]);
    }

    %args = (%default_args, %required_args, %args);

    my $node = bless \%args, $package;

    return $node;
}


=head2 my $label = $node->label()

Returns the node's label.

=cut

sub label {
    my ($node) = @_;

    return $node->{label};
}

=head2 $node->leaf_branch()

Returns the leaf branch, or C<undef> if that branch doesn't exist.  You can use
$node->is_leaf() to check for existence.

=cut

sub leaf_branch {
    my ($node) = @_;

    return $node->{leaf_branch};
}

=head2 $node->info_branch()

Returns the info branch, or C<undef> if that branch doesn't exist.  You can use
$node->is_info() to check for existence.

=cut

sub info_branch {
    my ($node) = @_;

    return $node->{info_branch};
}

=head2 $node->true_branch()

Returns the true branch, or C<undef> if that branch doesn't exist.  You can use
$node->is_branch() to check for existence.

=cut

sub true_branch {
    my ($node) = @_;

    return $node->{true_branch};
}

=head2 $node->false_branch()

Returns the false branch, or C<undef> if that branch doesn't exist.  You can use
$node->is_branch() to check for existence.

=cut

sub false_branch {
    my ($node) = @_;

    return $node->{false_branch};
}

=head2 $node->is_info()

Returns true if $node is an info branch.

=cut

sub is_info {
    my ($node) = @_;

    return $node->{info_node};
}

=head2 $node->is_leaf()

Returns true if $node is an leaf branch.

=cut

sub is_leaf {
    my ($node) = @_;

    return $node->{leaf_node};
}

=head2 $node->is_branch()

Returns true if $node is a branch.

=cut

sub is_branch {
    my ($node) = @_;

    return $node->{branch_node};
}

=head1 AUTHOR

John Tobin, C<< <tobinjt at cs.tcd.ie> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-aso-decisiontree-node at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ASO-DecisionTree-Node>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc ASO::DecisionTree::Node

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=ASO-DecisionTree-Node>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/ASO-DecisionTree-Node>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/ASO-DecisionTree-Node>

=item * Search CPAN

L<http://search.cpan.org/dist/ASO-DecisionTree-Node>

=back

=head1 DEPENDENCIES

Standard modules bundled with Perl: L<Carp>, L<Data::Dumper>.

Modules bundled with ASO: none.

Other modules: none.

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Node
