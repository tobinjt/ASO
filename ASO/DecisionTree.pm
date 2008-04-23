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
        my $num_args = @_ - 1;
        croak qq{divideset(): expecting two arguments, not $num_args\n};
    }

    my @true  = grep {     $_->[$column] } @{$rows};
    my @false = grep { not $_->[$column] } @{$rows};

    return (\@true, \@false);
}

=head2 $adt->build_tree(\@rows, \@current_cg, \@original_cg, $current_score, \&score_function)

Recursively build a Decision Tree from @rows, using columns taken from
@column_groups.  XXX IMPROVE THIS.

=cut

sub build_tree {
    my ($self, $rows, $current_cg, $original_cg, $current_score, $score_function) = @_;

    if (@_ != 6) {
        my $num_args = @_ - 1;
        croak qq{build_tree(): expecting five arguments, not $num_args\n};
    }

    if (not @{$rows}) {
        return ASO::DecisionTree->new(leaf_node => 1, leaf_branch => $rows);
    }

    if (not @{$current_cg}) {
        return ASO::DecisionTree->new(leaf_node => 1, leaf_branch => $rows);
    }

    my ($best_score,    $best_column, $best_true_branch, $best_false_branch)
     = ($current_score, undef,        undef,             undef             );

    # Find the best column to divide the rows on.
    foreach my $column (@{$current_cg->[0]}) {
        my ($true_branch, $false_branch) = $self->divideset($rows, $column);
        # The probability that a random row will be in the true branch.
        my $probability = @{$true_branch} / @{$rows};
        # Weight the score of each branch by the probability of a row being in
        # that branch, and sum the weighted branch scores to get the new overall
        # score.
        my $true_score  = $self->$score_function($true_branch,
                                                 $column,
                                                 $current_cg,
                                                 $original_cg);
        my $false_score = $self->$score_function($false_branch,
                                                 $column,
                                                 $current_cg,
                                                 $original_cg);
        my $new_score =   ($probability       * $true_score)
                        + ((1 - $probability) * $false_score);
        # A higher overall score is better.  Scoring functions need to normalise
        # their functions so their results are between zero and one, with one
        # being better.
        if ($new_score > $best_score) {
            $best_score         = $new_score;
            $best_column        = $column;
            $best_true_branch   = $true_branch;
            $best_false_branch  = $false_branch;
        }
    }

    # If we found a column that's useful for dividing on we recursively divide
    # the true and false branches.
    if ($best_score > $current_score) {
        # Create a new column group structure, without the column we're
        # dividing the rows on now.
        my $reduced_cg = dclone($current_cg);
        my @new_column_group = grep { $_ != $best_column }
                                    @{$reduced_cg->[0]};
        if (not @new_column_group) {
            # We've exhausted the first column group, so drop it.
            shift @{$reduced_cg};
        } else {
            $reduced_cg->[0] = \@new_column_group;
        }

        my $true_branch  = $self->build_tree($best_true_branch,
                                             $reduced_cg,
                                             $original_cg,
                                             $best_score,
                                             $score_function);
        my $false_branch = $self->build_tree($best_false_branch,
                                             $reduced_cg,
                                             $original_cg,
                                             $best_score,
                                             $score_function);
        return ASO::DecisionTree->new(column        => $best_column,
                                      true_branch   => $true_branch,
                                      false_branch  => $false_branch);
    }

    # None of the columns in the current column group were helpful in dividing
    # the rows, so we add them as info nodes and continue with the next column
    # group.
    my $reduced_cg = dclone($current_cg);
    my $unused_columns = shift @{$reduced_cg};
    my $new_tree = $self->build_tree($rows,
                                     $reduced_cg,
                                     $original_cg,
                                     $current_score,
                                     $score_function);
    foreach my $column (@{$unused_columns}) {
        $new_tree = ASO::DecisionTree->new(column       => $column,
                                           info_branch  => $new_tree,
                                           info_node    => 1);
    }
    return $new_tree;
}

=head2 ASO::DecisionTree->load_data($dbi_dsn, $username, $password)

Connect to the database specified in $dbi_dsn using $username and $password (see
L<DBI> and L<DBD::foo>, where I<foo> is your database driver, for the format of
$dbi_dsn).  The database will be queried with something similar to

  SELECT results.connection_id, results.rule_id
    FROM results, rules
    WHERE   rules.action = "REJECTION"
        and results.warning = 1
        and rules.id = results.rule_id
    ORDER BY results.connection_id, results.rule_id;

The data for each connection will be accumulated into an array (referred to as
@row from now on).  Each element of @row represents the presence or absence of a
particular rule for that connection: the element will be one if the rule is
present, zero if not.  The index can be looked up in the mapping hashes
described shortly to determine which rule an element corresponds to.  The
mappings between array indices and rule ids are the same for every @row.  A rule
id, and thus a corresponding array index, will only be present if that rule id
was returned at least once from the search.

Every @row will be added to @rows to be returned; they'll I<probably> be ordered
by connection id, but that's not guaranteed.  @rows is suitable for passing to
$adt->build_tree(), $adt->divideset(), or the scoring functions.

Two hashes mapping between rule ids and array indices will be created:
C<%index_to_rule_id> and C<%rule_id_to_index>.  C<%index_to_rule_id> maps an
array index to a rule id, and C<rule_id_to_index> maps a rule id to an array
index.

Returns (\@rows, \%index_to_rule_id, \%rule_id_to_index).

An example will hopefully make things clearer:

    my $dbi_dsn = 'whatever your database requires';
    my ($username, $password) = qw(user pass);

    my ($rows, $index_to_rule_id, $rule_id_to_index)
        = ASO::DecisionTree->load_data($dbi_dsn, $username, $password);
    my $interesting_rule_id = 42;
    if (not exists $rule_id_to_index->{$interesting_rule_id}) {
        print "Rule $interesting_rule_id not in results\n";
    }
    # Print the first rule present for each connection.
    # NOTE: the rule orderings don't correspond to the order the rules matched.
    foreach my $row (@rows) {
        my $i = 0;
        # We don't need to check for falling off the end of the array: there
        # must be at least one rule present for each @row, otherwise the
        # wouldn't have been any results for that @row and it wouldn't have been
        # created.
        while (not $row->[$i]) {
            $i++;
        }
        print "First rule: $index_to_rule_id->{$i}\n";
    }

=cut

=head1 SCORE FUNCTIONS

All score function return a number between zero and one; zero is worse, one is
better.

=cut

=head2 $adt->rejection_ratio(\@rows, $column, $current_cg, $original_cg)

The fraction of @rows where $column is a rejection.

=cut

sub rejection_ratio {
    my ($self, $rows, $column, $current_cg, $original_cg) = @_;

    if (@_ != 5) {
        my $num_args = @_ - 1;
        croak qq{rejection_ratio(): expecting four arguments, not $num_args\n};
    }

    my @counts = (0, 0);
    map { $counts[$_->[$column]]++; } @{$rows};

    return $counts[1] / @{$rows};
}

=head2 $adt->subsequent_rejections(\@rows, $column, $current_cg, $original_cg)

How many other columns/restrictions in the current column group would reject
when this column/restriction rejects.

=cut

sub subsequent_rejections {
    my ($self, $rows, $column, $current_cg, $original_cg) = @_;

    if (@_ != 5) {
        my $num_args = @_ - 1;
        croak qq{subsequent_rejections(): expecting four arguments, not $num_args\n};
    }

    if (@{$current_cg->[0]} == 1) {
        # There's only one column left - this one.  Fall back ro
        # rejection_ratio();
        return $self->rejection_ratio($rows, $column, $current_cg, $original_cg);
    }

    my $num_other_restrictions = @{$current_cg->[0]} - 1;
    my ($num_subsequent_rejects, $num_possible_rejects) = (0, 0);
    ROW:
    foreach my $row (@{$rows}) {
        if (not $row->[$column]) {
            next ROW;
        }
        # The total number of possible rejections when this rejection took
        # effect.
        $num_possible_rejects += $num_other_restrictions;
        # The actual number of subsequent rejections in the current column group
        # when this rejection took effect.
        $num_subsequent_rejects += grep { $row->[$_]; } @{$current_cg->[0]};
        # The current column will always be included in the count returned by
        # grep, so reduce the count by one.
        $num_subsequent_rejects--;
    }

    if ($num_possible_rejects == 0) {
        # This restriction didn't take effect in this group of rows.
        return 0;
    }

    return $num_subsequent_rejects / $num_possible_rejects;
}

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
