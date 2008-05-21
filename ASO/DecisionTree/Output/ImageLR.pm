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

=item width_between_branch_nodes => integer

The width of the gap between branch nodes in the tree.  Default is 100 pixels.

=item width_between_info_nodes => integer

The width of the gap between info nodes in the tree.  Default is 50 pixels.

=item label_padding => integer

The amount of padding to put before and after labels.  Default is 10
pixels.

=item height_between_nodes => integer

The height of the gap between nodes in the tree.  Default is 10 pixels.

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
        my $label_y = ($args{ymin} + $args{ymax}) / 2;
        $self->draw_label(
            string     => $self->get_label($args{tree}),
            x          => $args{xmin} + $self->{label_padding},
            y          => $label_y,
        );
        if ($args{tree}->{leaf_node}) {
            # Finished with leaf nodes.
            return ($args{xmin}, $label_y);
        }

        # Draw the remainder of the tree.
        my $child_xmin = $args{xmin} + $self->get_label_width($args{tree})
                                     + $self->{width_between_info_nodes};
        my ($child_x, $child_y) = $self->draw_tree_r(
            %args,
            tree       => $args{tree}->{info_branch},
            xmin       => $child_xmin,
            ymin       => $args{ymin},
            xmax       => $args{xmax},
            ymax       => $args{ymax},
        );

        # Draw the connecting line for info node.
        my $line_x = $args{xmin} + $self->get_label_width($args{tree});
        my $line_y = $label_y;
        $self->draw_line(
            x1      => $line_x,
            y1      => $line_y,
            x2      => $child_x,
            y2      => $child_y,
        );

        # Finished with info nodes.
        return ($args{xmin}, $label_y);
    }

    # Displaying true/false nodes is enough code to go into a separate function.
    return $self->draw_tree_true_false_node(%args);
}

=head2 $image->draw_tree_true_false_node(%args)

Draw a node with true and false branches.

=cut

sub draw_tree_true_false_node {
    my ($self, %args) = @_;

    my $false_height = $self->get_tree_height($args{tree}->{false_branch});
    my $true_height  = $self->get_tree_height($args{tree}->{true_branch});
    my $total_height = $self->get_tree_height($args{tree});

    my $label_y = $args{ymin} + $true_height
                    + ($self->{height_between_nodes} / 2);

    # Add the label.
    $self->draw_label(
        string     => $self->get_label($args{tree}),
        x          => $args{xmin} + $self->{label_padding},
        y          => $label_y,
    );

    my $child_xmin = $args{xmin} + $self->get_label_width($args{tree})
                                 + $self->{width_between_branch_nodes};
    # Draw the false branch - on the bottom
    my ($false_line_x, $false_line_y) = $self->draw_tree_r(
        %args,
        tree       => $args{tree}->{false_branch},
        xmin       => $child_xmin,
        ymin       => $args{ymax} - $false_height,
        xmax       => $args{xmax},
        ymax       => $args{ymax},
    );

    # Draw the true branch - on the top
    my ($true_line_x, $true_line_y) = $self->draw_tree_r(
        %args,
        tree       => $args{tree}->{true_branch},
        xmin       => $child_xmin,
        ymin       => $args{ymin},
        xmax       => $args{xmax},
        ymax       => $args{ymin} + $true_height,
    );

    # Draw the connecting lines
    my $line_y = $label_y;
    my $line_x = $args{xmin} + $self->get_label_width($args{tree});
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

    my $line_label_x = $line_x + ($self->{width_between_branch_nodes} / 2) - 2;
    # Label the lines.
    $self->draw_label(
        string      => q{0},
        x           => $line_label_x,
        y           => (($line_y + $false_line_y) / 2) + 2,
        halign      => q{right},
        valign      => q{top},
    );

    $self->draw_label(
        string      => q{1},
        x           => $line_label_x,
        y           => (($line_y + $true_line_y) / 2) - 2,
        halign      => q{right},
        valign      => q{bottom},
    );

    return ($args{xmin}, $label_y);
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
        my $child_height = $self->get_tree_height($subtree->{info_branch});
        return max($label_height, $child_height);
    }

    my $false_height = $self->get_tree_height($subtree->{false_branch});
    my $true_height  = $self->get_tree_height($subtree->{true_branch});
    my $child_height = $false_height + $self->{height_between_nodes}
                        + $true_height;
    return max($label_height, $child_height);
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
        return $label_width + $self->{width_between_info_nodes} + $child_width;
    }

    my $false_width = $self->get_tree_width($subtree->{false_branch});
    my $true_width  = $self->get_tree_width($subtree->{true_branch});
    return $label_width + $self->{width_between_branch_nodes}
            + max($false_width, $true_width);
}

=head2 ASO::DecisionTree::Output::ImageLR->get_default_options()

Returns the default options accepted by new().

=cut

sub get_default_options {
    my ($package) = @_;

    my %defaults = (
        width_between_branch_nodes  => 100,
        width_between_info_nodes    => 50,
        height_between_nodes        => 10,
        label_padding               => 10,
    );
    return %defaults;
}

=head2 $image->draw_label(%args)

Draw a label on the image.

=cut

sub draw_label {
    my ($self, %args) = @_;

    # Alter the interpretation of the coordinates.
    my %defaults = (
        valign     => q{center},
        halign     => q{left},
    );
    %args = (%defaults, %args);
    return $self->SUPER::draw_label(%args);
}

=head2 $image->get_label_width($tree)

Returns the width of the label, including label_padding, for the top node of $tree.

=cut

sub get_label_width {
    my ($self, $subtree) = @_;

    my ($height, $width) = $self->get_label_size($subtree);
    return $width + ($self->{label_padding} * 2);
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
