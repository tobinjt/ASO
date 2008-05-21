package ASO::DecisionTree::Output::ImageLR;

use warnings;
use strict;

use base q{ASO::DecisionTree::Output::Image};
use List::Util qw(max sum);
use Imager;
use Carp;

=head1 NAME

ASO::DecisionTree::Output::ImageLR - Output an L<ASO::DecisionTree> as an image.

=head1 VERSION

Version $Id$

=cut

our ($VERSION) = q{$Id$} =~ m/(\d+)/mx;

=head1 SYNOPSIS

ASO::DecisionTree::Output::ImageLR converts an L<ASO::DecisionTree> to an image
for easy viewing.  The root is at the left of the image, and the tree grows to
the right, hence the name ImageLR.  It's hoped that this will produce an image
that's easier to navigate, as top-down images (e.g. those produced by
L<ASO::DecisionTree::Output::Image>) end up being extremely wide.  This module
subclasses L<ASO::DecisionTree::Output::Image> and replaces specific functions.

    my $decision_tree = ....; # See ASO::DecisionTree.
    my $image = ASO::DecisionTree::Output::ImageLR->new(
        fontfile => q{/usr/share/fonts/truetype/ttf-bitstream-vera/VeraMono.ttf},
        fontsize => 12,
    );
    $image->draw_tree($decision_tree);
    $image->save_image($filename);

=head1 METHODS

=cut

=head2 my $image = ASO::DecisionTree::Output::ImageLR->new(%options)

Create a new image object.  Takes the following arguments:

=over 4

=item fontfile => filename

The font to use in the image.  Picking a good font is difficult; I suggest
F</usr/share/fonts/truetype/ttf-bitstream-vera/VeraMono.ttf> if you have it.
This is a required option.

=item fontsize => integer

The size of font to use; 12 is a reasonable start, though your font may require
a larger or smaller size.  This is a required argument.

=item width_between_nodes => integer

The width between nodes in the tree.  Default is 50 pixels.

=back

=cut

=head1 INTERNAL METHODS

These methods should Just Work for you, but if you're sub-classing this module
you may need to replace them.

=cut

=head2 $image->draw_tree_r(%args)

Recursively draw a tree.

=cut

sub draw_tree_r {
    my ($self, %args) = @_;

    if ($args{tree}->{leaf_node} or $args{tree}->{info_node}) {
        # Draw the label.
        my $label_x = ($args{xmin} + $args{xmax}) / 2;
        $self->draw_label(
            string     => $self->get_label($args{tree}),
            x          => $label_x,
            y          => $args{ymin},
        );
        if ($args{tree}->{leaf_node}) {
            # Finished with leaf nodes.
            return ($label_x, $args{ymin});
        }

        # Draw the remainder of the tree.
        my $child_ymin = $args{ymin} + $self->get_label_height($args{tree})
                                     + $self->{width_between_nodes};
        my ($child_x, $child_y) = $self->draw_tree_r(
            %args,
            tree       => $args{tree}->{info_branch},
            xmin       => $args{xmin},
            ymin       => $child_ymin,
            xmax       => $args{xmax},
            ymax       => $args{ymax},
        );

        # Draw the connecting line for info node.
        my $line_y = $args{ymin} + $self->get_label_height($args{tree});
        my $line_x = $label_x;
        $self->draw_line(
            x1      => $line_x,
            y1      => $line_y,
            x2      => $child_x,
            y2      => $child_y,
        );

        # Finished with info nodes.
        return ($label_x, $args{ymin});
    }

    # Displaying true/false nodes is enough code to go into a separate function.
    return $self->draw_tree_true_false_node(%args);
}

=head2 $image->draw_tree_true_false_node(%args)

Draw a node with true and false branches.

=cut

sub draw_tree_true_false_node {
    my ($self, %args) = @_;

    my $false_width = $self->get_tree_width($args{tree}->{false_branch});
    my $true_width  = $self->get_tree_width($args{tree}->{true_branch});
    my $total_width = $false_width + $true_width;

    # Need to ensure the label doesn't extend past xmin or xmax; this can
    # happen if half the label width is greater than the width of one of the
    # branches.  In that case shift it left or right enough to fit in the box.
    my $half_label_length = $self->get_label_width($args{tree}) / 2;
    my $left_label_width  = max($false_width, $half_label_length);
    if ($half_label_length > $true_width) {
        $left_label_width  = $total_width - $half_label_length;
    }
    my $label_x = $args{xmin} + $left_label_width;

    # Add the label.
    $self->draw_label(
        string     => $self->get_label($args{tree}),
        x          => $label_x,
        y          => $args{ymin},
    );

    my $child_ymin = $args{ymin} + $self->get_label_height($args{tree})
                                 + $self->{width_between_nodes};
    # Draw the false branch
    my ($false_line_x, $false_line_y) = $self->draw_tree_r(
        %args,
        tree       => $args{tree}->{false_branch},
        xmin       => $args{xmin},
        ymin       => $child_ymin,
        xmax       => $args{xmin} + $false_width,
        ymax       => $args{ymax},
    );

    # Draw the true branch
    my ($true_line_x, $true_line_y) = $self->draw_tree_r(
        %args,
        tree       => $args{tree}->{true_branch},
        xmin       => $args{xmin} + $false_width,
        ymin       => $child_ymin,
        xmax       => $args{xmax},
        ymax       => $args{ymax},
    );

    # Draw the connecting lines
    my $line_y = $args{ymin} + $self->get_label_height($args{tree});
    my $line_x = $label_x;
    $self->draw_line(
        x1      => $line_x,
        y1      => $line_y,
        x2      => $false_line_x,
        y2      => $false_line_y,
    );

    $self->draw_line(
        x1      => $line_x,
        y1      => $line_y,
        x2      => $true_line_x,
        y2      => $true_line_y,
    );

    my $line_label_y = $line_y + ($self->{width_between_nodes} / 2) - 2;
    # Label the lines.
    $self->draw_label(
        string      => q{0},
        x           => (($line_x + $false_line_x) / 2) - 2,
        y           => $line_label_y,
        halign      => q{right},
        valign      => q{bottom},
    );

    $self->draw_label(
        string      => q{1},
        x           => (($line_x + $true_line_x) / 2) + 2,
        y           => $line_label_y,
        halign      => q{left},
        valign      => q{bottom},
    );

    return ($label_x, $args{ymin});
}

=head2 $image->get_tree_height(%args)

Recursively determine the height of the tree, based on the font used.

=cut

sub get_tree_height {
    my ($self, $subtree) = @_;

    my ($label_height, $label_width) = $self->get_label_size($subtree);
    if ($subtree->{leaf_node}) {
        return $label_height;
    }

    if ($subtree->{info_node}) {
        return $label_height + $self->{width_between_nodes}
                + $self->get_tree_height($subtree->{info_branch});
    }

    my $false_height = $self->get_tree_height($subtree->{false_branch});
    my $true_height  = $self->get_tree_height($subtree->{true_branch});
    return $label_height + $self->{width_between_nodes}
            + max($false_height, $true_height);
}

=head2 $image->get_tree_width(%args)

Determine the width of the tree based on the font size; will possibly over
estimate it, depending on the shape of the tree.

=cut

sub get_tree_width {
    my ($self, $subtree) = @_;

    my $label_width = $self->get_label_width($subtree);
    if ($subtree->{leaf_node}) {
        return $label_width;
    }

    if ($subtree->{info_node}) {
        my $child_width = $self->get_tree_width($subtree->{info_branch});
        return max($label_width, $child_width);
    }

    my $false_width = $self->get_tree_width($subtree->{false_branch});
    my $true_width  = $self->get_tree_width($subtree->{true_branch});
    my $child_width = $false_width + $true_width;
    return max($child_width, $label_width);
}

=head2 ASO::DecisionTree::Output::ImageLR->get_default_options()

Returns the default options accepted by new().

=cut

sub get_default_options {
    my ($package) = @_;

    my %defaults = (
        width_between_nodes => 50,
    );
    return %defaults;
}

=head1 AUTHOR

John Tobin, C<< <tobinjt at cs.tcd.ie> >>

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.  Please report any bugs or feature
requests to C<bug-aso-decisiontree-output-imagelr at rt.cpan.org>, or through the
web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=ASO-DecisionTree-Output-ImageLR>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.  Patches are welcome.

=head1 DIAGNOSTICS

None.

=head1 CONFIGURATION AND ENVIRONMENT

None.

=head1 DEPENDENCIES

Standard Perl modules: L<List::Util>, L<Carp>.

Modules bundled with ASO: L<ASO::DecisionTree::Output::Image>.

External modules: L<Imager>.

=head1 SEE ALSO

L<Imager>.

=head1 INCOMPATIBILITIES

None.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc ASO::DecisionTree::Output::ImageLR

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=ASO-DecisionTree-Output-ImageLR>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/ASO-DecisionTree-Output-ImageLR>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/ASO-DecisionTree-Output-ImageLR>

=item * Search CPAN

L<http://search.cpan.org/dist/ASO-DecisionTree-Output-ImageLR>

=back

=head1 COPYRIGHT & LICENSE

Copyright 2008 John Tobin, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of ASO::DecisionTree::Output::ImageLR
