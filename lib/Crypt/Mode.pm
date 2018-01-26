package Crypt::Mode;

use strict;
use warnings;
our $VERSION = '0.056_001';

### METHODS

sub new { die }    # overriden in subclass

sub encrypt {
  my ($self, $pt) = (shift, shift);
  $self->start_encrypt(@_)->_crypt($pt) . $self->finish;
}

sub decrypt {
  my ($self, $ct) = (shift, shift);
  $self->start_decrypt(@_)->_crypt($ct) . $self->finish;
}

sub add {
  my $self = shift;
  my $rv = '';
  $rv .= $self->_crypt($_) for (@_);
  return $rv;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Mode - [internal only]

=cut
