#!/usr/bin/env perl

# $Id$


=head1 NAME

ASO::DB - Load required database classes.

=head1 VERSION

This documentation refers to ASO::DB version $Id$


=head1 SYNOPSIS

    use ASO::DB;
    my $dbix = ASO::DB->connect(
        q{dbi:SQLite:dbname=../sql/db.sq3},
        {AutoCommit => 0},
    );
    # Do stuff with $dbix - see DBIx::Class documentation.

    foreach my $connection ($dbix->resultset(q{Connection})->search()) {
        # Do something with $connection
        print $connection->server_ip();
    }

    my $connection = $dbix->resultset(q{Connection})->new_result({
        server_ip   => q{127.0.0.1}.
        # etc. etc.
    });

=head1 DESCRIPTION

This module wraps DBIx::Class and the modules representing each table so they 
can be easily loaded.

=head1 SUBROUTINES/METHODS 

None.

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

External packages: DBIx::Class::Schema.

Bundled packages: ASO::DB::Connection, ASO::DB::Result, ASO::DB::Rule.

=head1 INCOMPATIBILITIES

None.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report problems to John Tobin
<tobinjt@cs.tcd.ie>.  Patches are welcome.

=head1 AUTHOR

John Tobin <tobinjt@cs.tcd.ie>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006-2007 John Tobin <tobinjt@cs.tcd.ie>.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

=cut

use strict;
use warnings;

package ASO::DB;
use base qw(DBIx::Class::Schema);

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

our @classes = qw(
    Connection
    Result
    Rule
);

# load the various classes.
__PACKAGE__->load_classes(@classes);

1;
