package Crypt::PQ::MLKEM;

use strict;
use warnings;
our $VERSION = '0.088_005';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::Misc qw(read_rawfile pem_to_der der_to_pem);

sub new {
  my ($class, @args) = @_;
  my $self = $class->_new();
  return $self unless @args;
  return $self->import_key(@args);
}

sub import_key {
  my ($self, $key, $password) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  croak "FATAL: undefined key" unless defined $key;

  my $data;
  if (ref($key) eq 'SCALAR') {
    $data = $$key;
  }
  elsif (-f $key) {
    $data = read_rawfile($key);
  }
  else {
    croak "FATAL: non-existing file '$key'";
  }
  croak "FATAL: invalid key data" unless $data;

  if ($data =~ /-----BEGIN (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----(.+?)-----END (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----/s) {
    return $self->_import_pem($data, $password);
  }
  elsif ($data =~ /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s) {
    return $self->_import_pem($data, undef);
  }
  else {
    my $rv = eval { $self->_import($data) }                  ||
             eval { $self->_import_pkcs8($data, $password) } ||
             eval { $self->_import_x509($data) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported ML-KEM key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  return der_to_pem($key, "PRIVATE KEY", $password, $cipher) if $type eq 'private';
  return der_to_pem($key, "PUBLIC KEY") if $type eq 'public';
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PQ::MLKEM - Post-quantum key encapsulation mechanism (FIPS 203, ML-KEM)

=head1 SYNOPSIS

 use Crypt::PQ::MLKEM;

 # generate a key pair
 my $kem = Crypt::PQ::MLKEM->new;
 $kem->generate_key('ML-KEM-768');

 # encapsulation (using public key)
 my $public_der = $kem->export_key_der('public');
 my $peer = Crypt::PQ::MLKEM->new(\$public_der);
 my ($ciphertext, $shared_secret_a) = $peer->encapsulate;

 # decapsulation (using private key)
 my $shared_secret_b = $kem->decapsulate($ciphertext);
 # $shared_secret_a eq $shared_secret_b

=head1 DESCRIPTION

Module-Lattice-based Key-Encapsulation Mechanism (ML-KEM) as standardised in
NIST FIPS 203. ML-KEM provides three parameter sets at different security
levels:

=over

=item * C<ML-KEM-512> (NIST security category 1)

=item * C<ML-KEM-768> (NIST security category 3)

=item * C<ML-KEM-1024> (NIST security category 5)

=back

I<Since: CryptX-0.100>

=head1 METHODS

=head2 new

 my $kem = Crypt::PQ::MLKEM->new;
 my $kem = Crypt::PQ::MLKEM->new($filename);
 my $kem = Crypt::PQ::MLKEM->new(\$buffer_with_key);
 my $kem = Crypt::PQ::MLKEM->new($filename, $password);

When called without arguments, returns an empty object on which
L</generate_key> or L</import_key> can be invoked. When called with a
filename or scalar reference, the key material is imported via
L</import_key>.

=head2 generate_key

Generates a new ML-KEM key pair using the bundled C<chacha20> PRNG.
The exact OS entropy source is handled by the underlying LibTomCrypt RNG
setup. Returns the object itself (for chaining).

 $kem->generate_key('ML-KEM-512');
 $kem->generate_key('ML-KEM-768');
 $kem->generate_key('ML-KEM-1024');

=head2 make_key_from_seed

Generates a key pair B<deterministically> from a 64-byte seed (the
concatenation of the C<d> and C<z> values defined in FIPS 203). Mainly
used for known-answer test vectors and reproducible test setups; do
not use a fixed or low-entropy seed in production. Returns the object
itself (for chaining).

 $kem->make_key_from_seed($seed, 'ML-KEM-768');

=head2 import_key

Loads an ML-KEM key in DER or PEM format. The parameter set is
auto-detected from the encoded OID.

 $kem->import_key($filename);
 $kem->import_key(\$buffer_with_key);
 $kem->import_key($filename, $password);

Supported formats:

=over

=item * PKCS#8 private keys (DER or PEM, optionally encrypted)

=item * SubjectPublicKeyInfo public keys (DER or PEM)

=item * X.509 certificates carrying an ML-KEM public key

=back

=head2 import_key_raw

Imports a raw (unencoded) ML-KEM key. Both the key C<$type> and the
parameter set C<$alg> must be specified explicitly because raw key
material has no associated algorithm identifier.

 $kem->import_key_raw($pubkey,  'public',  'ML-KEM-768');
 $kem->import_key_raw($privkey, 'private', 'ML-KEM-768');

=head2 export_key_der

Returns the key as a binary DER-encoded string (PKCS#8 for private keys,
SubjectPublicKeyInfo for public keys).

 my $private_der = $kem->export_key_der('private');
 my $public_der  = $kem->export_key_der('public');

=head2 export_key_pem

Returns the key as a PEM-encoded string (ASCII).

 my $private_pem = $kem->export_key_pem('private');
 my $public_pem  = $kem->export_key_pem('public');
 my $private_pem = $kem->export_key_pem('private', $password);
 my $private_pem = $kem->export_key_pem('private', $password, $cipher);

=head2 export_key_raw

Returns the raw key as a binary string.

 my $private_bytes = $kem->export_key_raw('private');
 my $public_bytes  = $kem->export_key_raw('public');

=head2 encapsulate

Generates a fresh shared secret and ciphertext using the loaded public
(encapsulation) key. Returns C<($ciphertext, $shared_secret)> as binary
strings.

 my ($ciphertext, $shared_secret) = $kem->encapsulate;

=head2 decapsulate

Recovers a shared secret from a ciphertext using the loaded private
(decapsulation) key. Returns the shared secret as a binary string.

 my $shared_secret = $kem->decapsulate($ciphertext);

If the ciphertext is malformed, ML-KEM is required by FIPS 203 to return
a pseudorandom value of correct length rather than fail; protocols
relying on the secret must perform their own confirmation step.

=head2 encapsulate_ex

B<Deterministic encapsulation> (FIPS 203 6.2 ML-KEM.Encaps_internal).
Identical to L</encapsulate> but uses the caller-supplied 32-byte
entropy C<$m> instead of drawing from a PRNG. Mainly used for
known-answer test vectors and reproducible test setups; do not use a
fixed or low-entropy C<$m> in production.

 my ($ciphertext, $shared_secret) = $kem->encapsulate_ex($m);

=head2 algorithm

Returns the parameter-set name of the loaded key (e.g. C<"ML-KEM-768">),
or C<undef> if no key is loaded.

 my $alg = $kem->algorithm;

=head2 is_private

 my $rv = $kem->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is loaded.

 my $hash = $kem->key2hash;

 # returns a hash like:
 {
   alg  => "ML-KEM-768",
   pub  => "...",   # raw public key as a hexadecimal string
   priv => "...",   # raw private key as a hexadecimal string (or undef)
 }

=head1 SEE ALSO

=over

=item * L<https://csrc.nist.gov/pubs/fips/203/final> - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard

=item * L<Crypt::PQ::MLDSA>, L<Crypt::PQ::SLHDSA>

=back

=cut
