package ASO::DecisionTree::Output::Image;

use warnings;
use strict;

use List::Util qw(max);
use Imager;
use Carp;

=head1 NAME

ASO::DecisionTree::Output::Image - Output an L<ASO::DecisionTree> as an image.

=head1 VERSION

This documentation refers to ASO::DB version $Id$

=cut

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 SYNOPSIS

ASO::DecisionTree::Output::Image converts an L<ASO::DecisionTree> to an image
for easy viewing.

    my $decision_tree = ....;
    my $image = ASO::DecisionTree::Output::Image->draw_tree($decision_tree);
    # Do something with $image
    # ....
    # Save the image
    ASO::DecisionTree::Output::Image->save_image($image, $filename);

=head1 METHODS

=head2 my $image = ASO::DecisionTree::Output::Image->draw_tree($decision_tree)

Returns an image representing $decision_tree; $image is an L<Imager> object.
Will C<croak> if anything fails.

=cut

sub draw_tree {
    my ($package, $tree) = @_;

    if (@_ != 2) {
        my $num_args = @_ - 1;
        croak qq{draw_tree(): expecting one argument, not $num_args\n};
    }

    my $tree_height = $package->get_tree_height($tree);
print qq{tree height: $tree_height\n};
    my $tree_width  = $package->get_tree_width($tree);
print qq{tree width: $tree_width\n};

    my $height_between_nodes = 50;
    # XXX use bounding_box() at some stage.
    my $height_of_label      = 15;
    my $height_per_node      = $height_between_nodes + $height_of_label;
    my $image_height         = ($height_per_node * ($tree_height - 1))
                               + $height_of_label;
    # XXX use 8 as a reasonable approximation; use bounding_box() at some stage.
    my $image_width          = $tree_width * 8;
    print qq{image size: $image_width * $image_height\n};

    # XXX allow the user to specify this
    my $fontfile = q{/usr/share/fonts/truetype/ttf-bitstream-vera/VeraMono.ttf};

    my $image = Imager->new(xsize => $image_width, ysize => $image_height)
        or croak q{Failed creating image: } . Imager->errstr() . qq{\n};
    $image->box(filled => 1, color => 'white');
    my $font = Imager::Font->new(file => $fontfile)
        or croak qq{failed to load $fontfile: } . Imager->errstr() . qq{\n};

    $package->draw_tree_r(
        image                   => $image,
        font                    => $font,
        tree                    => $tree,
        xmin                    => 0,
        ymin                    => 0,
        xmax                    => $image_width,
        ymax                    => $image_height,
        height_of_label         => $height_of_label,
        height_between_nodes    => $height_between_nodes,
    );

    return $image;
}

=head2 ASO::DecisionTree::Output::Image->save_image($image, $filename)

Saves $image to $filename; the output type is determined by the extension of
$filename.  Will C<croak> if saving the image fails.

=cut

sub save_image {
    my ($package, $image, $filename) = @_;

    if (@_ != 3) {
        my $num_args = @_ - 1;
        croak qq{save_image(): expecting two arguments, not $num_args\n};
    }

    $image->write(file => $filename)
        or croak qq{Failed writing image: $filename: }
                 . $image->errstr() . qq{\n};
}

=head1 INTERNAL METHODS

These methods should Just Work for you, but if you're sub-classing this module
you may need to replace them.

=cut

=head2 ASO::DecisionTree::Output::Image->draw_tree_r(%args)

XXX Recursively draw a tree.

=cut

sub draw_tree_r {
    my ($package, %args) = @_;

    if ($args{tree}->{leaf_node} or $args{tree}->{info_node}) {
        # Draw the label.
        my $label_x = ($args{xmin} + $args{xmax}) / 2;
        $package->draw_label(
            string     => $package->get_label($args{tree}),
            x          => $label_x,
            y          => $args{ymin},
            image      => $args{image},
            font       => $args{font},
        );
        if ($args{tree}->{leaf_node}) {
            # Finished with leaf nodes.
            return ($label_x, $args{ymin});
        }

        # Draw the remainder of the tree.
        my $child_ymin = $args{ymin} + $args{height_of_label}
                                     + $args{height_between_nodes};
        my ($child_x, $child_y) = $package->draw_tree_r(
            %args,
            tree       => $args{tree}->{info_branch},
            xmin       => $args{xmin},
            ymin       => $child_ymin,
            xmax       => $args{xmax},
            ymax       => $args{ymax},
        );

        # Draw the connecting line for info node.
        my $line_y = $args{ymin} + $args{height_of_label};
        my $line_x = $label_x;
        $package->draw_line(
            image   => $args{image},
            x1      => $line_x,
            y1      => $line_y,
            x2      => $child_x,
            y2      => $child_y,
        );

        # Finished with info nodes.
        return ($label_x, $args{ymin});
    }

    # Displaying true/false nodes is enough code to go into a separate function.
    return $package->draw_tree_true_false_node(%args);
}

=head2 ASO::DecisionTree::Output::Image->draw_tree_r(%args)

XXX Draw a node with true and false branches.

=cut

sub draw_tree_true_false_node {
    my ($package, %args) = @_;

    my $false_width = $package->get_tree_width($args{tree}->{false_branch});
    my $true_width  = $package->get_tree_width($args{tree}->{true_branch});
    my $total_width = $false_width + $true_width;

    my $xsize       = $args{xmax} - $args{xmin};
    my $false_xsize = $xsize * $false_width / $total_width;
    my $true_xsize  = $xsize * $true_width  / $total_width;

    # Need to ensure the label doesn't extend past xmin or xmax; this can
    # happen if half the label width is greater than the width of one of the
    # branches.  In that case shift it left or right enough to fit in the box.
    my $half_label_length = $package->get_label_length($args{tree}) / 2;
    my $left_label_width  = max($false_width, $half_label_length);
    if ($half_label_length > $true_width) {
        $left_label_width  = $total_width - $half_label_length;
    }
    my $label_x = $args{xmin} + ($xsize * $left_label_width / $total_width);

    # Add the label.
    $package->draw_label(
        string     => $package->get_label($args{tree}),
        x          => $label_x,
        y          => $args{ymin},
        image      => $args{image},
        font       => $args{font},
    );

    my $child_ymin = $args{ymin} + $args{height_of_label}
                                 + $args{height_between_nodes};
    # Draw the false branch
    my ($false_line_x, $false_line_y) = $package->draw_tree_r(
        %args,
        tree       => $args{tree}->{false_branch},
        xmin       => $args{xmin},
        ymin       => $child_ymin,
        xmax       => $args{xmin} + $false_xsize,
        ymax       => $args{ymax},
    );

    # Draw the true branch
    my ($true_line_x, $true_line_y) = $package->draw_tree_r(
        %args,
        tree       => $args{tree}->{true_branch},
        xmin       => $args{xmin} + $false_xsize,
        ymin       => $child_ymin,
        xmax       => $args{xmax},
        ymax       => $args{ymax},
    );

    # Draw the connecting lines
    my $line_y = $args{ymin} + $args{height_of_label};
    my $line_x = $label_x;
    $package->draw_line(
        image   => $args{image},
        x1      => $line_x,
        y1      => $line_y,
        x2      => $false_line_x,
        y2      => $false_line_y,
    );

    $package->draw_line(
        image   => $args{image},
        x1      => $line_x,
        y1      => $line_y,
        x2      => $true_line_x,
        y2      => $true_line_y,
    );

    my $line_label_y = $line_y + ($args{height_between_nodes} / 2) - 2;
    # Label the lines.
    $package->draw_label(
        string      => q{0},
        x           => (($line_x + $false_line_x) / 2) - 2,
        y           => $line_label_y,
        image       => $args{image},
        font        => $args{font},
        halign      => q{right},
        valign      => q{bottom},
    );

    $package->draw_label(
        string      => q{1},
        x           => (($line_x + $true_line_x) / 2) + 2,
        y           => $line_label_y,
        image       => $args{image},
        font        => $args{font},
        halign      => q{left},
        valign      => q{bottom},
    );

    return ($label_x, $args{ymin});
}

=head2 ASO::DecisionTree::Output::Image->draw_line(%args)

XXX Draw a line on the image.

=cut

sub draw_line {
    my ($package, %args) = @_;
    my %defaults = (
        color   => q{blue},
        aa      => 1,
        endp    => 0,
    );
    %args = (%defaults, %args);

    my $image = delete $args{image};
    $image->line(%args)
        or die qq{Drawing line failed: } . $image->errstr() . qq{\n};
}

=head2 ASO::DecisionTree::Output::Image->draw_label(%args)

XXX Draw a label on the image.

=cut

sub draw_label {
    my ($package, %args) = @_;
    my %defaults = (
        size       => 12,
        color      => q{black},
        valign     => q{top},
        halign     => q{center},
    );
    %args = (%defaults, %args);

    my $font = delete $args{font};
    $font->align(%args)
        or die qq{Drawing label failed: } . $args{image}->errstr() . qq{\n};
}

=head2 ASO::DecisionTree::Output::Image->get_tree_height(%args)

XXX Recursively determine the height of the tree.

=cut

sub get_tree_height {
    my ($package, $subtree) = @_;

    if ($subtree->{leaf_node}) {
        return 1;
    }

    if ($subtree->{info_node}) {
        return 1 + $package->get_tree_height($subtree->{info_branch});
    }

    my $false_height = $package->get_tree_height($subtree->{false_branch});
    my $true_height  = $package->get_tree_height($subtree->{true_branch});
    return max($false_height, $true_height) + 1;
}

=head2 ASO::DecisionTree::Output::Image->get_tree_width(%args)

XXX Determine the width of the tree; will possibly over estimate it, depending
on the shape of the tree.

=cut

sub get_tree_width {
    my ($package, $subtree) = @_;

    my $label_width = $package->get_label_length($subtree);
    if ($subtree->{leaf_node}) {
        return $label_width;
    }

    if ($subtree->{info_node}) {
        my $child_width = $package->get_tree_width($subtree->{info_branch});
        return max($label_width, $child_width);
    }

    my $false_width = $package->get_tree_width($subtree->{false_branch});
    my $true_width  = $package->get_tree_width($subtree->{true_branch});
    my $child_width = $false_width + $true_width;
    return max($child_width, $label_width);
}

=head2 ASO::DecisionTree::Output::Image->get_label_length($tree)

Returns the width of the label for the top node of $tree.

=cut

sub get_label_length {
    my ($package, $subtree) = @_;

    my $label = $package->get_label($subtree);
    # Add some padding to separate labels.
    return 2 + length $label;
}

=head2 ASO::DecisionTree::Output::Image->get_label($tree)

Returns the label for the top node of $tree.

=cut

sub get_label {
    my ($package, $subtree) = @_;

    # At some point this should display more information.
    return $subtree->{label};
}

=head1 AUTHOR

John Tobin, C<< <tobinjt at cs.tcd.ie> >>

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report any bugs or feature
requests to C<bug-aso-decisiontree-output-image at rt.cpan.org>, or through the
web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ASO-DecisionTree-Output-Image>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.  Patches are welcome.

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: L<List::Util>, L<Carp>.

External modules: L<Imager>.

=head1 SEE ALSO

L<Imager>.

=head1 INCOMPATIBILITIES

None.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc ASO::DecisionTree::Output::Image

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=ASO-DecisionTree-Output-Image>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/ASO-DecisionTree-Output-Image>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/ASO-DecisionTree-Output-Image>

=item * Search CPAN

L<http://search.cpan.org/dist/ASO-DecisionTree-Output-Image>

=back

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Output::Image
