# $Id$

package ASO::DecisionTree;

use warnings;
use strict;
use Carp;
use Data::Dumper;
use Storable qw(dclone);
use List::Util qw(sum);
use lib qw(..);
use ASO::DB;

=head1 NAME

ASO::DecisionTree - A module implementing the Decision Tree algorithm.

=head1 VERSION

Version $Id$

=cut

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 SYNOPSIS

ASO::DecisionTree implements a modified form of the Decision Tree algorithm,
modified to work well with the data stored by L<ASO::Parser>.

    use ASO::DecisionTree;

    my ($dbi_dsn, $username, $password) = qw(...);
    my ($rows, $index_to_rule_id, $rule_id_to_index)
        = ASO::DecisionTree->load_data($dbi_dsn, $username, $password);
    my $cluster_groups = ASO::DecisionTree->build_cluster_groups(
                $dbi_dsn, $username, $password, $rule_id_to_index);
    my $tree = ASO::DecisionTree->build_tree(
                $rows, $cluster_groups, $cluster_groups, q{rejection_ratio});

=head1 METHODS

=cut

=head2 my $adt = ASO::DecisionTree->new()

Create a new ASO::DecisionTree object.  Takes the following arguments:

=over 4

=item label => string

The label to be displayed when displaying the tree.

=item column => integer

The column in each row which the decision is to be made on.

=item true_branch => $true_adt

The branch to follow when the column in the row is true.  This should be an
ASO::DecisionTree object.

=item false_branch => $false_adt

The branch to follow when the column in the row is false.  This should be an
ASO::DecisionTree object.

=item leaf_node => boolean

True if this node is a leaf node.

=item leaf_branch => \@rows

The data associated with the leaf node.  The format of @rows is described in
L</DATA STRUCTURES>.

=item info_node => boolean

True if this node is a info node, i.e. it doesn't make a decision.  Info nodes
are used to retain information about columns which aren't useful in
classification.

=item info_branch => $info_adt

The branch to follow when the info_node is true.  This should be an
ASO::DecisionTree object.

=back

Required arguments: C<label>.

You must also specify one of the following groups of arguments:

=over 4

=item leaf_node, leaf_branch

=item column, true_branch, false_branch

=item column, info_node, info_branch

=back

=cut

sub new {
    my ($package, %args) = @_;

    my %default_args = (
        label           => undef,
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

    %args = (%default_args, %required_args, %args);

    my $adt = bless \%args, $package;

    return $adt;
}

=head2 my (\@true, \@false) = $adt->divideset(\@rows, $column)

Divides @rows into two sets, depending on the value of element $column in each
%row from @rows (formats described in L</DATA STRUCTURES>).  Returns (\@true,
\@false).

=cut

sub divideset {
    my ($package, $rows, $column) = @_;

    if (@_ != 3) {
        my $num_args = @_ - 1;
        croak qq{divideset(): expecting two arguments, not $num_args\n};
    }

    my @true  = grep {     $_->{results}->[$column] } @{$rows};
    my @false = grep { not $_->{results}->[$column] } @{$rows};

    return (\@true, \@false);
}

=head2 my $adt = ASO::DecisionTree->build_tree(\@rows, \@current_cg, \@original_cg, $score_function, $threshold)

Recursively build a Decision Tree from @rows, using columns taken from
@current_cg.  The format of @rows, @current_cg and @original_cg is described in
L</DATA STRUCTURES>.  $score_function is the name of a XXX IMPROVE THIS.

=cut

sub build_tree {
    my ($package, $rows, $current_cg, $original_cg, $score_function, $threshold) = @_;

    if (@_ != 6) {
        my $num_args = @_ - 1;
        croak qq{build_tree(): expecting five arguments, not $num_args\n};
    }

    if (not @{$rows}) {
        my $new_tree = $package->new(
            leaf_node      => 1,
            leaf_branch    => $rows, 
            label          => q{No rows}
        );
        foreach my $cluster_group (@{$current_cg}) {
            foreach my $cluster_element (@{$cluster_group}) {
                $new_tree = $package->new(
                    column       => $cluster_element->{column},
                    info_branch  => $new_tree,
                    info_node    => 1,
                    label        => $cluster_element->{restriction_name}
                );
            }
        }
        return $new_tree;
    }

    if (not @{$current_cg}) {
        return $package->new(leaf_node      => 1,
                             leaf_branch    => $rows,
                             label          => q{No cluster groups});
    }

    my ($best_score, $best_cg, $best_true_branch, $best_false_branch)
     = (0,           undef,    undef,             undef             );

    # Find the best column to divide the rows on.
    CLUSTER_ELEMENT:
    foreach my $cluster_element (@{$current_cg->[0]}) {
        # Skip required rules which don't have a column; they'll be dealt with
        # when this cluster group runs out of useful columns.
        if (not exists $cluster_element->{column}) {
            next CLUSTER_ELEMENT;
        }
        my ($true_branch, $false_branch)
            = $package->divideset($rows, $cluster_element->{column});

        my $true_count  = sum(map { $_->{count}; } @{$true_branch})  || 0;
        my $false_count = sum(map { $_->{count}; } @{$false_branch}) || 0;
        my $rows_count  = sum(map { $_->{count}; } @{$rows})         || 0;
        # The probability that a random row will be in the true branch.
        my $probability = $true_count / $rows_count;
        # Weight the score of each branch by the probability of a row being in
        # that branch, and sum the weighted branch scores to get the new overall
        # score.
        my $true_score  = $package->$score_function($true_branch,
                                                    $cluster_element->{column},
                                                    $current_cg,
                                                    $original_cg);
        my $false_score = $package->$score_function($false_branch,
                                                    $cluster_element->{column},
                                                    $current_cg,
                                                    $original_cg);
        my $new_score =   ($probability       * $true_score)
                        + ((1 - $probability) * $false_score);

        # A higher overall score is better.  Scoring functions need to normalise
        # their functions so their results are between zero and one, with one
        # being better.
        if ($new_score > $best_score) {
            $best_score         = $new_score;
            $best_cg            = $cluster_element;
            $best_true_branch   = $true_branch;
            $best_false_branch  = $false_branch;
        }
    }

    # If we found a column that's useful for dividing on we recursively divide
    # the true and false branches.
    if ($best_score > $threshold) {
        # Create a new column group structure, without the column we're
        # dividing the rows on now.
        my $reduced_cg = dclone($current_cg);
        my @new_column_group = grep { $_->{rule_id} != $best_cg->{rule_id} }
                                    @{$reduced_cg->[0]};
        if (not @new_column_group) {
            # We've exhausted the first column group, so drop it.
            shift @{$reduced_cg};
        } else {
            $reduced_cg->[0] = \@new_column_group;
        }

        my $true_branch  = $package->build_tree($best_true_branch,
                                                $reduced_cg,
                                                $original_cg,
                                                $score_function,
                                                $threshold);
        my $false_branch = $package->build_tree($best_false_branch,
                                                $reduced_cg,
                                                $original_cg,
                                                $score_function,
                                                $threshold);
        return $package->new(column        => $best_cg->{column},
                             true_branch   => $true_branch,
                             false_branch  => $false_branch,
                             label         => $best_cg->{restriction_name});
    }

    # None of the columns in the current column group were helpful in dividing
    # the rows, so we add them as info nodes and continue with the next column
    # group.
    my $reduced_cg = dclone($current_cg);
    my $unused_cgs = shift @{$reduced_cg};
    my $new_tree   = $package->build_tree($rows,
                                          $reduced_cg,
                                          $original_cg,
                                          $score_function,
                                          $threshold);
    foreach my $cluster_element (@{$unused_cgs}) {
        $new_tree = $package->new(
            column       => $cluster_element->{column},
            info_branch  => $new_tree,
            info_node    => 1,
            label        => $cluster_element->{restriction_name}
        );
    }
    return $new_tree;
}

=head2 my (\@rows, \%index_to_rule_id, \%rule_id_to_index) = ASO::DecisionTree->load_data($dbi_dsn, $username, $password)

Connect to the database specified in $dbi_dsn using $username and $password (see
L<DBI> and L<DBD::foo>, where I<foo> is your database driver, for the format of
$dbi_dsn).  The database will be queried with something similar to

  SELECT results.connection_id, results.rule_id
    FROM results, rules
    WHERE   rules.action    = "REJECTION"
        and results.warning = 1
        and rules.id        = results.rule_id
    ORDER BY results.connection_id, results.rule_id;

The data for each connection will be accumulated into an array (referred to as
@results from now on).  Each element of @results represents the presence or
absence of a particular rule for that connection: the element will be one if the
rule is present, zero if not.  The index can be looked up in the mapping hashes
described shortly to determine which rule an element corresponds to.  The
mappings between array indices and rule ids are the same for every @results
returned from a single call to load_data().  A rule id, and thus a corresponding
array index, will only be present if that rule id was returned at least once
from the search.

Every @results will be part of a %row; every %row will be added to @rows to be
returned; they'll I<probably> be ordered by connection id, but that's not
guaranteed.  @rows is suitable for passing to $adt->build_tree(),
$adt->divideset(), or the scoring functions, and the format is described in
L</DATA STRUCTURES>.

Two hashes mapping between rule ids and array indices will be created:
C<%index_to_rule_id> and C<%rule_id_to_index>.  C<%index_to_rule_id> maps an
array index to a rule id, and C<rule_id_to_index> maps a rule id to an array
index.

Returns (\@rows, \%index_to_rule_id, \%rule_id_to_index).  Dies if unable to
connect to the database.

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
        while (not $row->{results}->[$i]) {
            $i++;
        }
        print "First rule: $index_to_rule_id->{$i}\n";
    }

=cut

sub load_data {
    my ($package, $dbi_dsn, $username, $password) = @_;

    if (@_ != 4) {
        my $num_args = @_ - 1;
        croak qq{load_data(): expecting three arguments, not $num_args\n};
    }

    my $dbix = ASO::DB->connect(
        $dbi_dsn,
        $username,
        $password,
        {AutoCommit => 1},
    );

    # Just printing the columns is 2-3 times slower than the equivalent SQL;
    # this is a big improvement because it used to be about 250 times slower.
    # Paging might help.  To see the generated SQL:
    #   export DBIC_TRACE="1=/tmp/trace.out"

    my @columns = qw(connection_id rule_id);
    my $ordering = join q{, }, map { qq{$_ ASC} } @columns;
    my $search = $dbix->resultset(q{Result})->search(
        {
            q{warning}      => 1,
            q{rule.action}  => q{REJECTION},
        },
        {
            q{join}         => q{rule},
            q{order_by}     => $ordering,
            q{select}       => \@columns,
        },
    );

    my (@rows, %rule_id_to_index, %index_to_rule_id);
    my ($last_connection_id, $next_index) = (-1, 0);
    # This gets us raw results rather than objects; we must ensure that the
    # column order in the select line above matches the order here.
    my $cursor = $search->cursor();

    while (my ($connection_id, $rule_id) = $cursor->next()) {
        if ($last_connection_id != $connection_id) {
            $last_connection_id = $connection_id;
            push @rows, [];
        }
        if (not exists $rule_id_to_index{$rule_id}) {
            $rule_id_to_index{$rule_id} = $next_index;
            $index_to_rule_id{$next_index} = $rule_id;
            $next_index++;
        }
        $rows[-1]->[$rule_id_to_index{$rule_id}] = 1;
    }

    # Make Data::Dumper do as little work as possible when detecting duplicate
    # rows.
    local $Data::Dumper::Indent   = 0;
    local $Data::Dumper::Terse    = 1;
    local $Data::Dumper::Sortkeys = 1;
    # Instead of storing every row, including duplicates, store one of each row,
    # plus the number of times it occurs.  We'd save memory by doing this in the
    # while loop above, but the code got too convoluted, so we do it this way
    # instead.
    my %unique_rows;
    foreach my $row (@rows) {
        my $key = Dumper($row);
        if (not exists $unique_rows{$key}) {
            $unique_rows{$key} = {
                count   => 0,
                results => $row,
            };
        }
        $unique_rows{$key}->{count}++;
    }
    @rows = values %unique_rows;

    # Zero-fill the rows.
    my $row_length = $next_index;
    foreach my $row (@rows) {
        # undef -> 0
        @{$row->{results}} = map { $_ || 0 } @{$row->{results}};
        # Extend the rows so they're all the same length.
        push @{$row->{results}}, (0) x ($row_length - @{$row->{results}});
    }

    return (\@rows, \%index_to_rule_id, \%rule_id_to_index);
}

=head2 my (\@cluster_groups) = ASO::DecisionTree->build_cluster_groups($dbi_dsn, $username, $password, \%rule_id_to_index)

Builds and returns the cluster groups structure from the database.  The
structure returned is an array of arrays of cluster elements (see
L</@cluster_groups> and L</%cluster_element>); in synopsis:

    @cluster_groups = (
        [
            { column => ... }, # cluster element
            { column => ... },
            { column => ... },
        ],
        [
            { column => ... },
            { column => ... },
            { column => ... },
        ],
        ...
    );

The column from each %cluster_element will be used in build_tree() to split
@rows (returned by load_data()); the elements from the first cluster
(@cluster_groups[0]) should be used first until exhausted or ineffective in
splitting the tree, after which the elements from subsequent clusters should be
used.

There will be a cluster element for every rule that is present in
\%rule_id_to_index or that references a cluster group with the C<required>
attribute set to true.  @cluster_groups is sorted by the C<cluster_group>
attribute in the database (see L<ASO::DB::ClusterGroup> for a list of
attributes); the contents of an individual @cluster_group (e.g.
$cluster_groups[0]) are not sorted.

Connects to the database using $dbi_dsn, $using and $password - see L<DBI> and
L<DBD::foo> (your database driver) for details of $dbi_dsn.  Dies if unable to
connect to the database.  Returns (\@cluster_groups).  %rule_id_to_index should
have been returned from load_data(); if not the columns in each %cluster_element
won't match the indices in @rows.

=cut

sub build_cluster_groups {
    my ($package, $dbi_dsn, $username, $password, $rule_id_to_index) = @_;

    if (@_ != 5) {
        my $num_args = @_ - 1;
        croak qq{build_cluster_groups(): }
              . qq{expecting four arguments, not $num_args\n};
    }

    my $dbix = ASO::DB->connect(
        $dbi_dsn,
        $username,
        $password,
        {AutoCommit => 1},
    );

    my $search = $dbix->resultset(q{ClusterGroup})->search(
        {
            # No search criteria.
        },
        {
            q{prefetch} => [qw(rules)],
        },
    );

    my @cluster_groups;
    CLUSTER_GROUP:
    while (my $cg = $search->next()) {
        # I probably won't need all the fields, but it's easier to yank them all
        # now.
        my %template_cg = (
            name                => $cg->name(),
            description         => $cg->description(),
            id                  => $cg->id(),
            cluster_group       => $cg->cluster_group(),
            restriction_list    => $cg->restriction_list(),
            required            => $cg->required(),
        );

        my @cluster_elements;
        RULE:
        foreach my $rule ($cg->rules()) {
            # Skip rules unless the cluster group is required or the rule has
            # been seen in results; the other rules are not interesting.
            if (        not exists $rule_id_to_index->{$rule->id()}
                    and not $template_cg{required}) {
                next RULE;
            }
            my $cluster_element = dclone(\%template_cg);
            $cluster_element->{rule_id} = $rule->id();
            $cluster_element->{restriction_name} = $rule->restriction_name()
                                                   || q{unknown restriction};
            if (exists $rule_id_to_index->{$rule->id()}) {
                $cluster_element->{column} = $rule_id_to_index->{$rule->id()};
            }
            push @cluster_elements, $cluster_element;
        }
        $cluster_groups[$template_cg{cluster_group}] = \@cluster_elements;
    }

    # Collapse @cluster_groups - it'll be mostly empty.
    my @reduced_cgs = grep { defined $_ and @{$_} } @cluster_groups;
    return \@reduced_cgs;
}

=head1 SCORE FUNCTIONS

All score function return a number between zero and one; zero is worse, one is
better.

=cut

=head2 my $score = $adt->rejection_ratio(\@rows, $column, $current_cg, $original_cg)

The fraction of @rows where $column is a rejection.

=cut

sub rejection_ratio {
    my ($package, $rows, $column, $current_cg, $original_cg) = @_;

    if (@_ != 5) {
        my $num_args = @_ - 1;
        croak qq{rejection_ratio(): expecting four arguments, not $num_args\n};
    }

    # Returning zero when there are zero rows seems like the best option.
    if (not @{$rows}) {
        return 0;
    }

    my @counts = (0, 0);
    map { $counts[$_->{results}->[$column]] += $_->{count}; } @{$rows};
    my $total_results = sum( map { $_->{count}; } @{$rows} );

    return $counts[1] / $total_results;
}

=head2 my $score = $adt->subsequent_rejections(\@rows, $column, $current_cg, $original_cg)

How many other columns/restrictions in the current column group would reject
when this column/restriction rejects.

=cut

sub subsequent_rejections {
    my ($package, $rows, $column, $current_cg, $original_cg) = @_;

    if (@_ != 5) {
        my $num_args = @_ - 1;
        croak qq{subsequent_rejections(): expecting four arguments, not $num_args\n};
    }

    # Returning zero when there are zero rows seems like the best option.
    if (not @{$rows}) {
        return 0;
    }

    # If this is the false subset we might as well return 0 now.
    if (not $rows->[0]->{results}->[$column]) {
        return 0;
    }

    if (@{$current_cg->[0]} == 1) {
        # There's only one column left - this one.  Return 1.
        return 1;
    }

    my $num_other_restrictions = @{$current_cg->[0]} - 1;
    my ($num_subsequent_rejects, $num_possible_rejects) = (0, 0);
    ROW:
    foreach my $row (@{$rows}) {
        # The number of possible subsequent rejections in the current column
        # group.
        $num_possible_rejects += $num_other_restrictions * $row->{count};
        # The number of subsequent rejections in the current column group which
        # would have taken effect.
        foreach my $cg (@{$current_cg->[0]}) {
            if ($row->{results}->[$cg->{column}] and $cg->{column} != $column) {
                $num_subsequent_rejects += $row->{count};
            }
        }
    }

    my $score = $num_subsequent_rejects / $num_possible_rejects;
    return $score;
}

=head1 DATA STRUCTURES

The data structures used throughout this module and passed as arguments to
methods are described below.

=head2 Example data

           | connection 1 | connection 2 | connection 3
    rule 1 | 1            |              | 1
    rule 2 |              |              | 1
    rule 3 |              | 1            |  
    rule 4 |              | 1            | 1
    rule 5 |              |              | 

    # There may be other elements in the hashes below; they've been excluded for
    # clarity.
    @rows = (
    # rule:  1, 3, 4, 2
            { results => [1, 0, 0, 0] },   # connection 1
            { results => [0, 1, 1, 0] },   # connection 2
            { results => [1, 0, 1, 1] },   # connection 3
    );

=head2 @rows

@rows is an array of %row, in no particular order.  L</Example data> shows a
table and @rows returned for it.  It helps to think of @rows as a table of
results, plus some additional data.

=head2 %row

%row represents all connections with the same results.  %row contains the
following keys:

=over 4

=item @results = $row{results};

Each element in @results corresponds to one result and will be either C<0> or
C<1>.  The element also corresponds to a rule: see L</%rule_id_to_index>.  A
rule will only be present in @results if there was at least one true result for
that rule (not necessarily for the connection represented by @results).
@results will have elements for every rule which produced results; if a rule did
not create a result for the connection represented by @results the corresponding
element will be set to C<0>.

L</Example data> shows a table and @rows resulting from it.  @results for each
%row has the same number of elements, and has been zero-filled as required.
Rule 2 first appears in connection 3, so it is represented by element 3 in each
@results; rules 3 and 4 precede it.  Rule 5 has no results in the connections,
so it is not present in @results.

=item my $count = $row{count}

The number of times this row's results were present in the data; this is used to
avoid repeating duplicate rows.

=back

=head2 %index_to_rule_id

%index_to_rule_id maps the index of an element in @row to a rule id.
%index_to_rule_id for L</Example data> is shown below:

    %index_to_rule_id = (
        0 => 1,
        1 => 3,
        2 => 4,
        3 => 2,
    );

=head2 %rule_id_to_index

%rule_id_to_index maps a rule id to the index of an element in @row.
%rule_id_to_index for L</Example data> is shown below:

    %rule_id_to_index = (
        1 => 0, 
        2 => 3,
        3 => 1,
        4 => 2,
    );

=head2 @cluster_groups

Array of arrays of @cluster_element.  build_tree() will use each
%cluster_element from $cluster_groups[0] when trying to split @rows to make the
decision tree; once $cluster_groups[0] is exhausted build_tree() will move on to
$cluster_groups[1], etc.

=head2 %cluster_element

Represents a single array index to be used when splitting @rows to make the
decision tree.  Sometimes a %cluster_element represents a restriction which
isn't present in @results, but which must be included - generally the standard
C<permit_mynetworks, reject_unauth_destination> restriction pair.  Keys you can
expect to find:

=over 4

=item column

The column to split on.

=item required

True if this is a required restriction.

=item rule_id

The rule_id of the associated rule.

=item restriction_list

The restriction list the restriction is recommended for - typically
L<smtpd_recipient_restrictions>.

=back

If C<required> is true C<column> may not be present.

=head2 @current_cg

@original_cg is the original @cluster_groups, unmodified by build_tree().  

=head2 @original_cg

@current_cg is the remaining cluster groups - those which have been consumed by
build_tree() have been removed.  @current_cg is modified automatically by
build_tree() as it recursively builds the tree.

=cut

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

=head1 DEPENDENCIES

Standard modules shipped with Perl: L<Carp>, L<Data::Dumper>, L<List::Util>,
L<Storable>.

Modules packaged with ASO::Parser: L<ASO::DB>.

External modules: none.

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree
