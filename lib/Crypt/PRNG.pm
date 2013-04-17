package Crypt::PRNG;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( random_bytes random_string_from )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;

sub _trans_prng_name {
  my $name = shift;
  $name =~ s/^Crypt::PRNG:://;
  return lc($name);
}

### METHODS

sub new {
  my $pkg = shift;
  my $prng_name = $pkg eq __PACKAGE__ ? _trans_prng_name(shift) : _trans_prng_name($pkg);
  return _new($prng_name, @_);
}

sub string_from {
  my ($self, $chars, $len) = @_;
  my @ch = split(//, $chars);
  my $max_index = scalar(@ch)-1;
  
  my $mask;
  for my $n (1..31) { 
    $mask = (1<<$n) - 1;
    last if $mask >= $max_index;
  }

  my $rv = '';
  while (length $rv < $len) {
    my $i = $self->irand & $mask;
    next if $i > $max_index;
    $rv .= $ch[$i];
  }
  return $rv;
}

#XXX-TODO maybe add
#random_bytes_base64
#random_bytes_hex
#random_bytes_qp
#bytes_hex
#bytes_base64
#bytes_qp

### FUNCTIONS

{
  ### stolen from Bytes::Random::Secure
  #
  # Instantiate our random number generator(s) inside of a lexical closure,
  # limiting the scope of the RNG object so it can't be tampered with.
  
  my $RNG_object = undef;
  
  my $fetch_RNG = sub { # Lazily, instantiate the RNG object, but only once.
    $RNG_object = Crypt::PRNG->new('Fortuna') unless defined $RNG_object;
    return $RNG_object;
  };
 
  sub random_bytes { return $fetch_RNG->()->bytes(@_) }  
  sub random_string_from { return $fetch_RNG->()->string_from(@_) }
}


1;

=pod

=head1 NAME

Crypt::PRNG - Cryptographically secure random number generator

=head1 FUNCTIONS

 #xxx

=head2 random_bytes

 #xxx

=head2 random_string_from

 #xxx

=head1 METHODS

=head2 new

 #xxx

=head2 add_entropy

 #xxx

=head2 bytes

 #xxx

=head2 string_from

 #xxx

=head1 SEE ALSO

xxx