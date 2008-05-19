#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::DB::ClusterGroup - ORM module representing the cluster_groups table.

=head1 VERSION

Version $Id$

=head1 SYNOPSIS

    use ASO::DB;

    my $dbix = ASO::DB->connect(
        q{dbi:SQLite:dbname=../sql/db.sq3},
        {AutoCommit => 1},
    );

    foreach my $cluster_group ($dbix->resultset(q{ClusterGroup})->search()) {
        # Do something with $cluster_group
        print $cluster_group->description();
    }

    my $cluster_group = $dbix->resultset(q{ClusterGroup})->new_result({
        restriction_list    => q{smtpd_recipient_restrictions},
        cluster_group       => XXX,
        # etc. etc.
    });

=head1 DESCRIPTION

ORM module representing the cluster_groups table.  Refer to the L<DBIx::Class>
documentation for more details about what can be done with this class.

The entries in this table represent cluster groups used in L<ASO::DecisionTree>
XXX IMPROVE THIS.

=cut

use strict;
use warnings;

package ASO::DB::ClusterGroup;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 COLUMNS

The columns in this table are:

=over 4

=item id

Primary key, uniquely identifying the row.  This is not an auto-increment key
because rules need to refer to it, so it needs to be stable.

=item name

The name of the cluster group.

=item description

A description of the cluster group, to help the user understand it better.

=item cluster_group

Restrictions are placed in cluster groups so that the decision tree algorithm in
L<ASO::DecisionTree> can treat them differently when constructing the tree.
This attribute is an integer specifying which cluster group (used by
L<ASO::DecisionTree>) restrictions referencing this cluster group (this row in
the database, or this object) should be placed in.  Using cluster group to refer
to two different things is a bit confusing at first, but it will make sense
after a while.

=item restriction_list

The restriction list (C<smtpd_recipient_restrictions>,
C<smtpd_data_restrictions>, etc.) this restriction is recommended for.  Most
restrictions are usually placed in C<smtpd_recipient_restrictions>, but there
are exceptions.

=item required

0 if the restrictions referencing this cluster group are not required, 1 if they
are required.  Typically this will only be 1 for the cluster group that's
referenced by the 'permit_mynetworks, reject_unauth_destination' rule.

=back

=cut

my %cols = (
    id                  => {
        sql                 => q{NOT NULL PRIMARY KEY UNIQUE},
        type                => q{integer},
    },
    name                => {
        sql                 => q{NOT NULL UNIQUE},
        type                => q{text},
    },
    description         => {
        sql                 => q{NOT NULL},
        type                => q{text},
    },
    # The cluster group that restrictions referencing this row should be placed
    # in by ASO::DecisionTree.
    cluster_group       => {
        sql                 => q{NOT NULL UNIQUE},
        type                => q{integer},
    },
    # The restriction list restrictions referencing this group should be used
    # in.
    # XXX ADD A CHECK TO ENSURE THAT THIS IS ONE OF THE VALID LISTS.
    restriction_list    => {
        sql                 => q{NOT NULL},
        type                => q{text},
    },
    required            => {
        sql                 => q{NOT NULL DEFAULT 0},
        type                => q{integer},
    },
);

=head1 SUBROUTINES/METHODS 

See L<DBIx::Class> for an idea of what is possible; this documentation only
covers the subroutines added by this module.

=over 4

=item $self->get_cols()

Returns a hash reference giving the columns in the rules table and their
associated attributes.  Modifying the returned hash is a bad idea.

=back

=cut

sub get_cols {
    my ($self) = @_;
    return %cols;
}

# Sneakily call get_cols() to improve coverage.  Silly, I know.
get_cols();

=over 4

=item $self->table_name()

Returns the name of the table in the database, "cluster_groups" in this case.

=back

=cut

sub table_name {
    my ($self) = @_;
    return q{cluster_groups};
}

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(table_name());
__PACKAGE__->add_columns(
    grep { exists $cols{$_}->{sql} } keys %cols
);
__PACKAGE__->set_primary_key(q{id});

=over 4

=item $self->rules()

Returns all entries in the rules table which reference this cluster group.

=back

=cut

# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{rules}              => q{ASO::DB::Rule}
                                            => q{cluster_group_id});
1;

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: L<Carp>.

Bundled modules: L<ASO::DB::Base>.

External modules: L<DBIx::Class>.

=head1 SEE ALSO

L<DBIx::Class>.

=head1 INCOMPATIBILITIES

None.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to John Tobin
<tobinjt@cs.tcd.ie>.  Patches are welcome.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2008 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

