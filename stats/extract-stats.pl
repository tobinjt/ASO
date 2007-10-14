#!/usr/bin/env perl

# $Id$

use strict;
use warnings;

use IO::File;
use IO::Dir;
use File::Spec::Functions qw(catfile);
use File::Slurp;
use Regexp::Common;
use List::Util qw(sum min max);

sub usage {
    warn qq{Usage: $0 <results directory> <output directory>};
    warn qq{Process <results directory>/timing.*, creating graphs in <output directory>};
    exit 1;
}

if (@ARGV != 2) {
    usage();
}

my ($results_dir, $output_dir) = @ARGV;
my $plot_file = catfile($output_dir, q{plot.gpi});
my $plot_file_fh = IO::File->new(q{> } . $plot_file)
    or die qq{$0: failed opening $plot_file: $!\n};

print $plot_file_fh <<"HEADER";
set xlabel "Log file"
set grid
# Don't continue the scales to the next round number; stop at the topmost point.
set autoscale xfixmax
# Put the legend at the top left, Left justified text.
set key top left Left reverse


HEADER

my $dir_dh = IO::Dir->new($results_dir)
    or die qq{$0: Failed opening $results_dir: $!\n};
my @files = grep /^timing\./, $dir_dh->read();
my %files_split = map { m/(.*)\.(\d+)$/;
    ( $_ => { prefix => $1, number => $2 } ); }
        @files;
@files = sort { $files_split{$a}->{prefix} cmp $files_split{$b}->{prefix}
        || $files_split{$a}->{number} <=> $files_split{$b}->{number} } @files;
@files = map { catfile($results_dir, $_); } @files;
use Data::Dumper;
#print qq{files: }, Dumper(\@files);
#print qq{files_split: }, Dumper(\%files_split);

my %data;
foreach my $file (@files) {
    my @lines = read_file($file);
    foreach my $line (@lines) {
        chomp $line;
        my ($field, $filename, $time) = split /:/, $line;
        $data{$field} ||= [];
        push @{$data{$field}}, $time;
    }
}
#print qq{data: }, Dumper(\%data);

my $plot_number = 1;
foreach my $field (sort keys %data) {
    my $values = $data{$field};
    my $output_file = catfile($output_dir, $field);
    my $output_file_fh = IO::File->new(q{> } . $output_file)
        or die qq{$0: failed opening $output_file: $!\n};
    print $output_file_fh join qq{\n}, @$values;
    print $output_file_fh qq{\n};

    print $plot_file_fh <<"PLOT";
set ylabel "$field"
#set terminal postscript monochrome eps size 5.4,3.3
#set output "$field.ps"
set terminal X11 $plot_number
plot "$field" using 1 with lines title "$field"
PLOT
    $plot_number++;

    my $num_values = @$values;
    my $mean = sum(@$values) / $num_values;
    my $sum_of_differences = 0;
    foreach my $value (@$values) {
        $sum_of_differences += (($value - $mean) ** 2);
    }
    my $stddev = sqrt ($sum_of_differences / $num_values);
    my $stddev_percent = $stddev * 100 / $mean;
    my $min = min(@$values);
    my $max = max(@$values);

    print <<"STATS";
Field: $field
Number of values: $num_values
Mean: $mean
Standard deviation: $stddev
Standard deviation as percentage of mean: $stddev_percent\%
Minimum value: $min
Maximum value: $max

STATS
}
