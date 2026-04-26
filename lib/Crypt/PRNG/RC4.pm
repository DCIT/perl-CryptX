package Crypt::PRNG::RC4;

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::PRNG Exporter);
our %EXPORT_TAGS = ( all => [qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u random_string random_string_from rand irand)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;

sub new {
  my ($class, @args) = @_;
  my $obj = Crypt::PRNG->new('RC4', @args);
  return bless $obj, $class;
}

{
  ### stolen from Bytes::Random::Secure
  my $RNG_object = undef;
  my $fetch_RNG = sub { # Lazily, instantiate the RNG object, but only once.
    $RNG_object = Crypt::PRNG::RC4->new unless defined $RNG_object && ref($RNG_object) ne 'SCALAR';
    return $RNG_object;
  };
  sub rand               { return $fetch_RNG->()->double(@_) }
  sub irand              { return $fetch_RNG->()->int32(@_) }
  sub random_bytes       { return $fetch_RNG->()->bytes(@_) }
  sub random_bytes_hex   { return $fetch_RNG->()->bytes_hex(@_) }
  sub random_bytes_b64   { return $fetch_RNG->()->bytes_b64(@_) }
  sub random_bytes_b64u  { return $fetch_RNG->()->bytes_b64u(@_) }
  sub random_string_from { return $fetch_RNG->()->string_from(@_) }
  sub random_string      { return $fetch_RNG->()->string(@_) }
}


1;

=pod

=head1 NAME

Crypt::PRNG::RC4 - Legacy RC4-based PRNG wrapper

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::PRNG::RC4 qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u random_string random_string_from rand irand);

   my $octets = random_bytes(45);
   my $hex_string = random_bytes_hex(45);
   my $base64_string = random_bytes_b64(45);
   my $base64url_string = random_bytes_b64u(45);
   my $alphanumeric_string = random_string(30);
   my $string = random_string_from('ACGT', 64);
   my $floating_point_number_0_to_1 = rand;
   my $floating_point_number_0_to_88 = rand(88);
   my $unsigned_32bit_int = irand;

   ### OO interface:
   use Crypt::PRNG::RC4;

   my $prng = Crypt::PRNG::RC4->new;
   my $seeded_prng = Crypt::PRNG::RC4->new("some data used for seeding PRNG");

   my $octets = $prng->bytes(45);
   my $hex_string = $prng->bytes_hex(45);
   my $base64_string = $prng->bytes_b64(45);
   my $base64url_string = $prng->bytes_b64u(45);
   my $alphanumeric_string = $prng->string(30);
   my $string = $prng->string_from('ACGT', 64);
   my $floating_point_number_0_to_1 = $prng->double;
   my $floating_point_number_0_to_88 = $prng->double(88);
   my $unsigned_32bit_int = $prng->int32;

=head1 DESCRIPTION

Provides an interface to the RC4-based pseudo-random number generator.

This is a thin wrapper around L<Crypt::PRNG> with the algorithm fixed to RC4.
All functions and methods accept the same arguments and return the same values
as the corresponding L<Crypt::PRNG> entries.

RC4 is provided for compatibility with legacy code only and is not recommended
for new designs.

=head1 FUNCTIONS

All functions below behave exactly like the corresponding L<Crypt::PRNG>
functions, but use a hidden C<Crypt::PRNG::RC4> object internally.

=head2 random_bytes

See L<Crypt::PRNG/random_bytes>.

=head2 random_bytes_hex

See L<Crypt::PRNG/random_bytes_hex>.

=head2 random_bytes_b64

See L<Crypt::PRNG/random_bytes_b64>.

=head2 random_bytes_b64u

See L<Crypt::PRNG/random_bytes_b64u>.

=head2 random_string

See L<Crypt::PRNG/random_string>.

=head2 random_string_from

See L<Crypt::PRNG/random_string_from>.

=head2 rand

See L<Crypt::PRNG/rand>.

=head2 irand

See L<Crypt::PRNG/irand>.

=head1 METHODS

Unless noted otherwise, assume C<$prng> is an existing C<Crypt::PRNG::RC4>
object created via C<new>.

=head2 new

 my $prng = Crypt::PRNG::RC4->new;
 my $seeded_prng = Crypt::PRNG::RC4->new($seed);

Creates a PRNG object using the RC4 algorithm. If C<$seed> is omitted, the
object is automatically seeded by the underlying L<Crypt::PRNG> logic. If
C<$seed> is provided it must be at least 5 bytes long; empty or shorter seeds
fail during initialization.

=head2 bytes

See L<Crypt::PRNG/bytes>.

=head2 bytes_hex

See L<Crypt::PRNG/bytes_hex>.

=head2 bytes_b64

See L<Crypt::PRNG/bytes_b64>.

=head2 bytes_b64u

See L<Crypt::PRNG/bytes_b64u>.

=head2 string

See L<Crypt::PRNG/string>.

=head2 string_from

See L<Crypt::PRNG/string_from>.

=head2 double

See L<Crypt::PRNG/double>.

=head2 int32

See L<Crypt::PRNG/int32>.

=head1 SEE ALSO

=over

=item * L<Crypt::PRNG>

=item * L<https://en.wikipedia.org/wiki/RC4_cipher|https://en.wikipedia.org/wiki/RC4_cipher>

=back

=cut
