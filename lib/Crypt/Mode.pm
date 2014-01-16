package Crypt::Mode;

use strict;
use warnings;

### METHODS

sub new { die }    # overriden in subclass

sub encrypt {
  my ($self, $pt) = (shift, shift);
  $self->_start(1, @_);
  return $self->add($pt) . $self->finish;
}

sub decrypt {
  my ($self, $ct) = (shift, shift);
  $self->_start(-1, @_);
  return $self->add($ct) . $self->finish;
}

sub start_encrypt {
  my $self = shift;
  $self->_start(1, @_);
  return $self;
}

sub start_decrypt {
  my $self = shift;
  $self->_start(-1, @_);
  return $self;
}

sub finish {
  shift->_finish(@_);
}

sub add {
  my $self = shift;
  my $rv = '';
  $rv .= $self->_crypt($_) for (@_);
  return $rv;
}

sub _crypt {
  my $self = shift;
  return $self->_encrypt(@_) if $self->_get_dir == 1;
  return $self->_decrypt(@_) if $self->_get_dir == -1;
  return undef;
}

sub _finish {
  my $self = shift;
  return $self->_finish_enc(@_) if $self->_get_dir == 1;
  return $self->_finish_dec(@_) if $self->_get_dir == -1;
  return undef;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

__END__
 
=head1 NAME

Crypt::Mode - [internal only]

=cut