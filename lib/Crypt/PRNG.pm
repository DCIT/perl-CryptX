package Crypt::PRNG;

use strict;
use warnings;
our $VERSION = '0.088_003';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u random_string random_string_from rand irand)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub string {
  my ($self, $len) = @_;
  return $self->string_from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", $len);
}

sub string_from {
  my ($self, $chars, $len) = @_;

  $len = 20 unless defined $len;
  return unless $len > 0;
  return unless length($chars) > 0;

  my @ch = split(//, $chars);
  my $max_index = $#ch;
  return if $max_index > 65535;

  my $mask;
  for my $n (1..31) {
    $mask = (1<<$n) - 1;
    last if $mask >= $max_index;
  }

  my $upck = ($max_index > 255) ? "n*" : "C*";
  my $l = $len * 2;

  my $rv = '';
  my @r;
  my $ri = 0;
  while (length $rv < $len) {
    if ($ri >= @r) {
      @r = unpack($upck, $self->bytes($l));
      $ri = 0;
    }
    my $i = $r[$ri++] & $mask;
    next if $i > $max_index;
    $rv .= $ch[$i];
  }
  return $rv;
}

sub CLONE_SKIP { 1 } # prevent cloning

### FUNCTIONS

{
  ### stolen from Bytes::Random::Secure
  #
  # Instantiate our random number generator(s) inside of a lexical closure,
  # limiting the scope of the RNG object so it can't be tampered with.
  my $RNG_object = undef;
  my $fetch_RNG = sub { # Lazily, instantiate the RNG object, but only once.
    $RNG_object = Crypt::PRNG->new unless defined $RNG_object && ref($RNG_object) ne 'SCALAR';
    return $RNG_object;
  };
  sub rand(;$)                { return $fetch_RNG->()->double(@_) }
  sub irand()                 { return $fetch_RNG->()->int32() }
  sub random_bytes($)         { return $fetch_RNG->()->bytes(@_) }
  sub random_bytes_hex($)     { return $fetch_RNG->()->bytes_hex(@_) }
  sub random_bytes_b64($)     { return $fetch_RNG->()->bytes_b64(@_) }
  sub random_bytes_b64u($)    { return $fetch_RNG->()->bytes_b64u(@_) }
  sub random_string_from($;$) { return $fetch_RNG->()->string_from(@_) }
  sub random_string(;$)       { return $fetch_RNG->()->string(@_) }
}

1;

=pod

=head1 NAME

Crypt::PRNG - Cryptographically secure random number generator

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::PRNG qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u
                      random_string random_string_from rand irand);

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
   use Crypt::PRNG;

   my $prng = Crypt::PRNG->new;  # defaults to ChaCha20
   my $rc4_prng = Crypt::PRNG->new("RC4");
   my $seeded_prng = Crypt::PRNG->new("RC4", "some data used for seeding PRNG");

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

Provides an interface to several pseudo random number generators (thread-safe
and fork-safe). The default algorithm is ChaCha20.

=head1 FUNCTIONS

For all C<random_bytes*> functions and the corresponding C<bytes*> methods,
C<$length> must not be greater than C<1000000000>.

=head2 random_bytes

   my $octets = random_bytes($length);
   # $length .. [integer] number of random bytes to generate

Returns C<$length> random octets as a binary string.

=head2 random_bytes_hex

   my $hex_string = random_bytes_hex($length);
   # $length .. [integer] number of random bytes (output string will be 2x longer)

Returns C<$length> random octets encoded as a lowercase hexadecimal string.

=head2 random_bytes_b64

   my $base64_string = random_bytes_b64($length);
   # $length .. [integer] number of random bytes to encode

Returns C<$length> random octets encoded as a Base64 string.

=head2 random_bytes_b64u

   my $base64url_string = random_bytes_b64u($length);
   # $length .. [integer] number of random bytes to encode

Returns C<$length> random octets encoded as a Base64 URL Safe string (RFC 4648 section 5).

=head2 random_string_from

   my $string = random_string_from($range, $length);
   # $range  .. [string] alphabet of allowed characters
   # $length .. [integer] optional, number of characters (DEFAULT: 20)
   #e.g.
   my $dna_string = random_string_from("ABCD", 10);

Returns a random string made of C<$length> chars randomly chosen from C<$range> string.
The alphabet must contain between 1 and 65536 characters; longer alphabets
return C<undef>.

=head2 random_string

   my $alphanumeric_string = random_string($length);
   # $length .. [integer] optional, number of characters (DEFAULT: 20)
   #or
   my $default_alphanumeric_string = random_string;  # default length = 20

Similar to random_string_from, only C<$range> is fixed to C<'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'>.

=head2 rand

   my $n = rand;
   #or
   my $limited_n = rand($limit);
   # $limit .. [number] optional, upper bound (exclusive)

Returns a random floating point number from range C<[0,1)> (if called without parameter) or C<[0,$limit)>.
If C<$limit> is C<0>, behaves like no limit (returns C<[0,1)>), matching Perl's built-in C<rand>.

=head2 irand

   my $i = irand;

Returns a random unsigned 32bit integer - range C<0 .. 0xFFFFFFFF>.

=head1 METHODS

Unless noted otherwise, assume C<$prng> is an existing PRNG object created via
C<new>, for example:

   my $prng = Crypt::PRNG->new;

=head2 new

   my $prng = Crypt::PRNG->new;  # defaults to ChaCha20
   #or
   my $prng = Crypt::PRNG->new($alg);
   #or
   my $prng = Crypt::PRNG->new($alg, $seed);

   # $alg  ... [string] algorithm name: 'ChaCha20' (DEFAULT), 'Fortuna', 'RC4' (legacy; compatibility only), 'Sober128' or 'Yarrow'
   # $seed ... [binary string] optional, initial entropy for seeding the PRNG

If C<$seed> is not specified the PRNG is automatically seeded with 40 bytes
obtained via libtomcrypt's C<rng_get_bytes()> platform RNG logic.

If C<$seed> is specified it must be non-empty for all algorithms. RC4 is
provided for legacy compatibility only, is not recommended for new designs, and
requires a seed of at least 5 bytes.

=head2 add_entropy

  my $prng = Crypt::PRNG->new;
  $prng->add_entropy($random_data);
  #or
  $prng->add_entropy();

If called without parameter it uses 40 bytes obtained via libtomcrypt's
C<rng_get_bytes()> platform RNG logic.

B<BEWARE:> you probably do not need this function at all as the module does automatic seeding on initialization as well as reseeding after fork and thread creation.

=head2 bytes

   my $octets = $prng->bytes($length);

See L<random_bytes|/random_bytes>

=head2 bytes_hex

   my $hex_string = $prng->bytes_hex($length);

See L<random_bytes_hex|/random_bytes_hex>

=head2 bytes_b64

   my $base64_string = $prng->bytes_b64($length);

See L<random_bytes_b64|/random_bytes_b64>

=head2 bytes_b64u

   my $base64url_string = $prng->bytes_b64u($length);

See L<random_bytes_b64u|/random_bytes_b64u>

=head2 string

   my $alphanumeric_string = $prng->string($length);
   #or
   my $default_alphanumeric_string = $prng->string;  # default length = 20

See L<random_string|/random_string>

=head2 string_from

   my $string = $prng->string_from($range, $length);  # default length = 20

See L<random_string_from|/random_string_from>

=head2 double

   my $n = $prng->double;
   #or
   my $limited_n = $prng->double($limit);

See L<rand|/rand>

=head2 int32

   my $i = $prng->int32;

See L<irand|/irand>

=head1 SEE ALSO

L<Crypt::PRNG::ChaCha20>, L<Crypt::PRNG::Fortuna>, L<Crypt::PRNG::RC4>,
L<Crypt::PRNG::Sober128>, L<Crypt::PRNG::Yarrow>

For generating random UUIDs see L<Crypt::Misc/random_v4uuid> and L<Crypt::Misc/random_v7uuid>.

=cut
