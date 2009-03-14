#!/usr/bin/env perl

# $Id$

=head1 NAME

ASO::DB::Rule - ORM module representing the rules table.

=head1 VERSION

Version $Id$

=head1 SYNOPSIS

    use ASO::DB;

    my $dbix = ASO::DB->connect(
        q{dbi:SQLite:dbname=../sql/db.sq3},
        {AutoCommit => 0},
    );

    foreach my $rule ($dbix->resultset(q{Rule})->search()) {
        # Do something with $rule
        print $rule->regex();
    }

    my $rule = $dbix->resultset(q{Rule})->new_result({
        regex   => q{asdf[qwerty](0xdeadbeef)}.
        # etc. etc.
    });

=head1 DESCRIPTION

ORM module representing the rules table.  Refer to the L<DBIx::Class>
documentation for more details about what can be done with this class.

The entries in this table represent the rules used to parse Postfix log files.
The rules specify a regex to match lines, the data to extract from matched
lines, an action for the parsing algorithm to take, and more; see the
COLUMNS section for more detail.

=cut

use strict;
use warnings;

package ASO::DB::Rule;
use base qw{DBIx::Class};
use base qw{ASO::DB::Base};

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 COLUMNS

The columns in this table are:

=over 4

=item id

Auto-generated primary key, uniquely identifying the row.

=item name

The name of the rule.

=item description

Something must have occurred to cause Postfix to log each line (e.g. a remote
client connecting causes a connection line to be logged).  The description field
is generally used to describe the action causing the log lines this rule
matches.

=item restriction_name

The restriction which caused the mail to be rejected.  Only applicable to rules
which have a result of rejected, other rules will have an empty string.

=item program

The program (postfix/smtp, postfix/smtpd, postfix/qmgr, etc.) whose log lines
the rule applies to.  This avoids needlessly trying rules which won't match the
line, or worse, might match unintentionally.

=item regex

The regex to apply to log lines.  Several keywords will be expanded in the regex
(see filter_regex() in L<ASO::Parser> for the full list); this allows each regex
to be compact, easy to read, less prone to typos (some of the regex components
are pretty hairy), and far easier to fix when a problem in one of the components
is discovered.  For efficiency each regex is compiled when the rule is loaded,
rather than recompiling it each time.

=item result_cols

This is how matched fields from the regex are extracted and saved.  The columns
result_cols and connection_cols specify fields to go in the result and
connection table respectively.  The format is:

  hostname = 1; helo = 2, sender = 4;

I.e. semi-colon/comma separated assignment statements, with the column name on
the left and the match from the regex ($1, $2 etc.) on the right hand side (no
$).  The list of accepted variable names can be found in L<ASO::DB::Result> or
L<ASO::DB::Connection> as appropriate.

Similarly result_data and connection_data specify data to go in the result and
connection table respectively.  The format is: client_ip = ::1; client_hostname
= localhost, helo = unknown; i.e. semi-colon/comma separated assignment
statements, with the column name on the left and the data to be saved on the
right.  There is no escape mechanism, so neither commas nor semi-colons can be
used in the data.  The list of accepted variable names can be found in
L<ASO::DB::Result> or L<ASO::DB::Connection> as appropriate.

=item connection_cols

See result_cols above.

=item result_data

See result_cols above.

=item connection_data

See result_cols above.

=item action

The action for the parser to take.  See ACTIONS in L<ASO::Parser> for the full
list.

=item queueid

The match in the regex giving the queueid from the line, or 0 if the line
doesn't contain a queueid.

=item rule_order

This is an efficiency measure.  This counter is maintained for every rule and
incremented each time the rule successfully matches.  At the start of each run
the program sorts the rules in descending rule_order (subject to sort_rules),
and at the end of the run updates every rule's rule_order.  Assuming that the
distribution of log lines is reasonably consistent, rules matching more commonly
occurring log lines will be tried before rules matching less commonly occurring
log lines, lowering the program's execution time.

=item priority

This is the user-configurable companion to rule_order: rules with a higher
priority will be tried first, overriding rule_order, allowing more specific
rules to take precedence over more general rules.

=back

=cut

my %cols = (
    id                  => {
        sql                 => q{NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE},
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
    # The program the rule applies to: smtpd, qmgr, etc.
    program             => {
        sql                 => q{NOT NULL},
        type                => q{text},
    },
    # A regex to parse the line.
    regex               => {
        sql                 => q{NOT NULL},
        type                => q{text},
    },
    # The action to take: IGNORE, CONNECT, DISCONNECT . . .
    action              => {
        sql                 => q{NOT NULL},
        type                => q{text},
    },
    # The order to apply the rules in: highest first; this is automatically
    # updated after every run of the program.
    hits                => {
        sql                 => q{NOT NULL DEFAULT 0},
        type                => q{integer},
    },
    # The total number of hits this rule has had, i.e. the sum of all hits over
    # all runs.
    hits_total          => {
        sql                 => q{NOT NULL DEFAULT 0},
        type                => q{integer},
    },
    # This is the user-configurable part of the rule ordering; it supercedes
    # rule_order, and won't be changed by the program.  Higher goes first.
    priority            => {
        sql                 => q{NOT NULL DEFAULT 0},
        type                => q{integer},
    },
    # additional data to be saved; same format as result_cols, for now.
    result_data         => {
        sql                 => q{NOT NULL DEFAULT ''},
        type                => q{text},
    },
    connection_data     => {
        sql                 => q{NOT NULL DEFAULT ''},
        type                => q{text},
    },
    # The name of the restriction which caused the rejection.
    restriction_name    => {
        sql                 => q{},
        type                => q{text},
    },
    # Reference to cluster_groups->id.
    cluster_group_id    => {
        sql                 => q{},
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

Returns the name of the table in the database, "rules" in this case.

=back

=cut

sub table_name {
    my ($self) = @_;
    return q{rules};
}

__PACKAGE__->load_components(qw(PK::Auto Core));
__PACKAGE__->table(table_name());
__PACKAGE__->add_columns(
    grep { exists $cols{$_}->{sql} } keys %cols
);
__PACKAGE__->set_primary_key(q{id});

=over 4

=item $self->results()

Returns all entries in the results table which are due to this rule.

=back

=cut

# Foreign keys: other tables reference this one.
__PACKAGE__->has_many(q{results}            => q{ASO::DB::Result}
                                            => q{rule_id});
# Foreign keys: this table references other tables.
__PACKAGE__->belongs_to(q{cluster_group}    => q{ASO::DB::ClusterGroup}
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

Copyright (c) 2006-2008 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

