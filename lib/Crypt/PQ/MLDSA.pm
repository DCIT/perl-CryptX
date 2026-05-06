package Crypt::PQ::MLDSA;

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
  croak "FATAL: invalid or unsupported ML-DSA key format";
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

Crypt::PQ::MLDSA - Post-quantum digital signature (FIPS 204, ML-DSA)

=head1 SYNOPSIS

 use Crypt::PQ::MLDSA;

 my $message = 'hello world';
 my $signer = Crypt::PQ::MLDSA->new;
 $signer->generate_key('ML-DSA-65');
 my $signature = $signer->sign_message($message);

 my $public_der = $signer->export_key_der('public');
 my $verifier = Crypt::PQ::MLDSA->new(\$public_der);
 $verifier->verify_message($signature, $message) or die "ERROR";

=head1 DESCRIPTION

Module-Lattice-based Digital Signature Algorithm (ML-DSA) as standardised
in NIST FIPS 204. ML-DSA provides three parameter sets:

=over

=item * C<ML-DSA-44> (NIST security category 2)

=item * C<ML-DSA-65> (NIST security category 3)

=item * C<ML-DSA-87> (NIST security category 5)

=back

I<Since: CryptX-0.100>

=head1 METHODS

=head2 new

 my $sig = Crypt::PQ::MLDSA->new;
 my $sig = Crypt::PQ::MLDSA->new($filename);
 my $sig = Crypt::PQ::MLDSA->new(\$buffer_with_key);
 my $sig = Crypt::PQ::MLDSA->new($filename, $password);

When called without arguments, returns an empty object on which
L</generate_key> or L</import_key> can be invoked. When called with a
filename or scalar reference, the key material is imported via
L</import_key>.

=head2 generate_key

Generates a new ML-DSA key pair using the bundled C<chacha20> PRNG.
Returns the object itself (for chaining).

 $sig->generate_key('ML-DSA-44');
 $sig->generate_key('ML-DSA-65');
 $sig->generate_key('ML-DSA-87');

=head2 make_key_from_seed

Generates a key pair B<deterministically> from a 32-byte seed (the
C<xi> value defined in FIPS 204). Mainly used for known-answer test
vectors and reproducible test setups; do not use a fixed or
low-entropy seed in production. Returns the object itself (for
chaining).

 $sig->make_key_from_seed($seed, 'ML-DSA-65');

=head2 import_key

Loads an ML-DSA key in DER or PEM format. The parameter set is
auto-detected from the encoded OID.

 $sig->import_key($filename);
 $sig->import_key(\$buffer_with_key);
 $sig->import_key($filename, $password);

=head2 import_key_raw

Imports a raw (unencoded) ML-DSA key. Both the key C<$type> and the
parameter set C<$alg> must be specified explicitly because raw key
material has no associated algorithm identifier.

 $sig->import_key_raw($pubkey,  'public',  'ML-DSA-65');
 $sig->import_key_raw($privkey, 'private', 'ML-DSA-65');

=head2 export_key_der

 my $private_der = $sig->export_key_der('private');
 my $public_der  = $sig->export_key_der('public');

=head2 export_key_pem

 my $private_pem = $sig->export_key_pem('private');
 my $public_pem  = $sig->export_key_pem('public');
 my $private_pem = $sig->export_key_pem('private', $password);
 my $private_pem = $sig->export_key_pem('private', $password, $cipher);

=head2 export_key_raw

 my $private_bytes = $sig->export_key_raw('private');
 my $public_bytes  = $sig->export_key_raw('public');

=head2 sign_message

Signs the given message and returns the signature as a binary string.

 my $signature = $sig->sign_message($message);
 my $signature = $sig->sign_message($message, $context);

The optional context string (at most 255 bytes) provides domain
separation. The same context must be supplied to L</verify_message>.

=head2 sign_message_ex

B<Deterministic signing> (FIPS 204 5.2 ML-DSA.Sign_internal). Identical
to L</sign_message> but uses the caller-supplied 32-byte per-signature
randomness C<$rnd> instead of drawing from a PRNG. Passing
C<"\0" x 32> produces the spec's deterministic variant; passing fresh
random bytes produces the hedged variant. Mainly used for
known-answer test vectors and protocols that require deterministic
signatures.

 my $signature = $sig->sign_message_ex($message, $context, $rnd);

C<$context> may be C<undef> for the empty context. C<$rnd> must be
exactly 32 bytes.

=head2 sign_message_ex_mu

B<External-mu deterministic signing> (FIPS 204 5.4.1
ML-DSA.Sign_internal alternative input). Signs an externally computed
C<mu = H(BytesToBits(tr) || M', 64)> instead of the original message.
Used by streaming/precomputed-hash protocols and by ACVP test vectors
that supply C<mu> directly.

 my $signature = $sig->sign_message_ex_mu($mu, $rnd);

C<$mu> must be exactly 64 bytes; C<$rnd> must be exactly 32 bytes.
There is no separate context parameter: the caller has already folded
context into C<mu> via C<tr>.

=head2 verify_message

Returns C<1> if the signature is valid, C<0> otherwise.

 my $valid = $sig->verify_message($signature, $message);
 my $valid = $sig->verify_message($signature, $message, $context);

=head2 algorithm

Returns the parameter-set name of the loaded key (e.g. C<"ML-DSA-65">),
or C<undef> if no key is loaded.

=head2 is_private

 my $rv = $sig->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is
loaded.

 my $hash = $sig->key2hash;

 # returns a hash like:
 {
   alg  => "ML-DSA-65",
   pub  => "...",   # raw public key as a hexadecimal string
   priv => "...",   # raw private key as a hexadecimal string (or undef)
 }

=head1 SEE ALSO

=over

=item * L<https://csrc.nist.gov/pubs/fips/204/final> - FIPS 204, Module-Lattice-Based Digital Signature Standard

=item * L<Crypt::PQ::MLKEM>, L<Crypt::PQ::SLHDSA>

=back

=cut
