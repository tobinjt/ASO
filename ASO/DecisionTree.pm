# $Id$

package ASO::DecisionTree;

use warnings;
use strict;
use Carp;
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
use Storable qw(dclone);

=head1 NAME

ASO::DecisionTree - A module implementing the Decision Tree algorithm.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

ASO::DecisionTree implements a modified form of the Decision Tree algorithm,
modified to work well with the data stored by L<ASO::Parser>.

    use ASO::DecisionTree;

    my $adt = ASO::DecisionTree->new();

=head1 METHODS

=cut

=head2 new()

Create a new ASO::DecisionTree object.  Takes the following arguments:

=over 4

=item column

The column in each row which the decision is to be made on.

=item true_branch

The branch to follow when the column in the row is true.

=item false_branch

The branch to follow when the column in the row is false.

=item leaf_node

True if this node is a leaf node.

=item leaf_branch

The data associated with the leaf node.

=item info_node

True if this node is a info node, i.e. it doesn't make a decision.  Info nodes
are used to retain information about columns which aren't useful in
classification.

=item info_branch

The branch to follow when the info_node is true.

=back

You must specify one of the following groups of arguments:

=over 4

=item leaf_node, leaf_branch

=item column, true_branch, false_branch

=item column, info_node, info_branch

=back

=cut

sub new {
    my ($package, %args) = @_;

    my %default_args = (
        column          => undef,
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

    my @valid_groups = (
        [qw(leaf_node leaf_branch)],
        [qw(column true_branch false_branch)],
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
        croak qq{${package}::new(): bad combination of arguments:\n}
              . Data::Dumper->Dump([\%args], [q{*arguments}]);
    }

    %args = (%default_args, %args);

    my $adt = bless \%args, $package;

    return $adt;
}

=head2 $adt->divideset(\@rows, $column)

Divides @rows into two sets, depending on the value of each row's $column
element.  Returns (\@true, \@false).

=cut

sub divideset {
    my ($self, $rows, $column) = @_;

    if (@_ != 3) {
        croak qq{divideset(): expecting three arguments, not } . @_ . qq{\n};
    }

    my @true  = grep {     $_->[$column] } @{$rows};
    my @false = grep { not $_->[$column] } @{$rows};

    return (\@true, \@false);
}

=head2 $adt->build_tree(\@rows, \@column_groups, \&score_function)

Recursively build a Decision Tree from @rows, using columns taken from
@column_groups.  XXX IMPROVE THIS.

=cut

sub build_tree {
    my ($self, $rows, $column_groups, $score_function) = @_;

    if (@_ != 4) {
        croak qq{build_tree(): expecting four arguments, not } . @_ . qq{\n};
    }

    if (not @{$rows}) {
        return ASO::DecisionTree->new(leaf_node => 1, leaf_branch => $rows);
    }

    if (not @{$column_groups}) {
        return ASO::DecisionTree->new(leaf_node => 1, leaf_branch => $rows);
    }

    my $current_score = $score_function->($rows);

    my ($best_score,    $best_column, $best_true_branch, $best_false_branch)
     = ($current_score, undef,        undef,             undef             );

    # Find the best column to divide the rows on.
    foreach my $column (@{$column_groups->[0]}) {
        my ($true_branch, $false_branch) = $self->divideset($rows, $column);
        # The probability that a random row will be in the true branch.
        my $true_probability = @{$true_branch} / @{$rows};
        # Weight the score of each branch by the probability of a row being in
        # that branch, and sum the weighted branch scores to get the new overall
        # score.
        my $new_score =
              ($true_probability       * $score_function->($true_branch))
            + ((1 - $true_probability) * $score_function->($false_branch));
        # A lower overall score is better - it means there's lower variation in
        # the branches after the split.
        if ($new_score < $best_score) {
            $best_score         = $new_score;
            $best_column        = $column;
            $best_true_branch   = $true_branch;
            $best_false_branch  = $false_branch;
        }
    }

    # If we found a column that's useful for dividing on we recursively divide
    # the true and false branches.
    if ($best_score < $current_score) {
        # Create a new column group structure, without the column we're
        # dividing the rows on now.
        my $reduced_column_groups = dclone($column_groups);
        my @new_column_group = grep { $_ != $best_column }
                                    @{$reduced_column_groups->[0]};
        if (not @new_column_group) {
            # We've exhausted the first column group, so drop it.
            shift @{$reduced_column_groups};
        } else {
            $reduced_column_groups->[0] = \@new_column_group;
        }

        my $true_branch  = $self->build_tree($best_true_branch,
                                             $reduced_column_groups,
                                             $score_function);
        my $false_branch = $self->build_tree($best_false_branch,
                                             $reduced_column_groups,
                                             $score_function);
        return ASO::DecisionTree->new(column        => $best_column,
                                      true_branch   => $true_branch,
                                      false_branch  => $false_branch);
    }

    # None of the columns in the current column group were helpful in dividing
    # the rows, so we add them as info nodes and continue with the next column
    # group.
    my $reduced_column_groups = dclone($column_groups);
    my $unused_columns = shift @{$reduced_column_groups};
    my $new_tree = $self->build_tree($rows,
                                     $reduced_column_groups,
                                     $score_function);
    foreach my $column (@{$unused_columns}) {
        $new_tree = ASO::DecisionTree->new(column       => $column,
                                           info_branch  => $new_tree,
                                           info_node    => 1);
    }
    return $new_tree;
}

# XXX I NEED A SCORE FUNCTION.  ENTROPY AND GINI IMPURITY WON'T WORK, BECAUSE
# NEARLY EVERY ROW WILL END IN A REJECTION.  I NEED REAL DATA TO LOOK AT FIRST.

=head1 AUTHOR

John Tobin, C<< <tobinjt at cs.tcd.ie> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-aso-decisiontree at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ASO-DecisionTree>.  I will be
notified, and then you'll automatically be notified of progress on your bug as I
make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc ASO::DecisionTree

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=ASO-DecisionTree>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/ASO-DecisionTree>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/ASO-DecisionTree>

=item * Search CPAN

L<http://search.cpan.org/dist/ASO-DecisionTree>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree
