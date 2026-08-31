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
use Crypt::Digest qw(digest_data_b64u);
use Crypt::Misc qw(read_rawfile encode_b64u decode_b64u pem_to_der der_to_pem);

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

  if (ref($key) eq 'HASH') {
    # JWK-like structure, draft-ietf-jose-pqc-kem e.g.
    # {"kty":"AKP","alg":"ML-KEM-768","pub":"...","priv":"..."}
    return $self->_import_jwk($key) if $key->{kty};
    croak "FATAL: unexpected ML-KEM key hash";
  }

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
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) { # JSON
    return $self->_import_jwk(CryptX::_decode_json("$1"));
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
  if ($type =~ /\Aprivate(?:_seed|_expanded|_both)?\z/) {
    croak "FATAL: export_key_pem: password-protected PEM is not supported for PKCS#8 keys yet, see the export_key_pem documentation" if defined $password;
    return der_to_pem($key, "PRIVATE KEY");
  }
  return der_to_pem($key, "PUBLIC KEY") if $type eq 'public';
}

sub _import_jwk {
  # draft-ietf-jose-pqc-kem: kty=AKP, alg names the parameter set, pub carries the
  # encapsulation key, priv MUST be the 64-octet ML-KEM seed d || z
  my ($self, $h) = @_;
  croak "FATAL: unexpected ML-KEM key hash" unless ref($h) eq 'HASH';
  croak "FATAL: unsupported JWK kty '" . ($h->{kty} // '') . "', expected 'AKP'"
    unless ($h->{kty} // '') eq 'AKP';
  my $alg = $h->{alg} or croak "FATAL: JWK is missing 'alg'";
  croak "FATAL: JWK is missing 'pub'" unless defined $h->{pub};

  if (defined $h->{priv}) {
    my $seed = decode_b64u($h->{priv});
    croak "FATAL: JWK 'priv' must be the 64-byte ML-KEM seed d || z"
      unless defined $seed && length($seed) == 64;
    $self->make_key_from_seed($seed, $alg);
    croak "FATAL: JWK 'pub' does not match the key derived from 'priv'"
      unless decode_b64u($h->{pub}) eq $self->export_key_raw('public');
    return $self;
  }
  return $self->import_key_raw(decode_b64u($h->{pub}), 'public', $alg);
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  if ($type && $type eq 'private') {
    # draft-ietf-jose-pqc-kem encodes the seed, not the expanded decapsulation key
    croak "FATAL: export_key_jwk('private') needs a key with a seed, there is no JWK encoding for the expanded decapsulation key"
      unless defined $kh->{seed};
    my $hash = {
      kty  => "AKP",
      alg  => $kh->{alg},
      pub  => encode_b64u(pack("H*", $kh->{pub})),
      priv => encode_b64u(pack("H*", $kh->{seed})),
    };
    return $wanthash ? $hash : CryptX::_encode_json($hash);
  }
  elsif ($type && $type eq 'public') {
    my $hash = {
      kty => "AKP",
      alg => $kh->{alg},
      pub => encode_b64u(pack("H*", $kh->{pub})),
    };
    return $wanthash ? $hash : CryptX::_encode_json($hash);
  }
  croak "FATAL: export_key_jwk invalid type '" . (defined $type ? $type : '') . "'";
}

sub export_key_jwk_thumbprint {
  my ($self, $hash_name) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $hash_name ||= 'SHA256';
  my $h = $self->export_key_jwk('public', 1);
  # AKP thumbprints (RFC 9964) are computed over kty, alg and pub
  my $json = CryptX::_encode_json({ alg => $h->{alg}, kty => $h->{kty}, pub => $h->{pub} });
  return digest_data_b64u($hash_name, $json);
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

A JWK (draft-ietf-jose-pqc-kem) is also accepted, either as a JSON string or as an
already decoded hashref:

 $kem->import_key(\$json_with_jwk);
 $kem->import_key($hashref_with_jwk);

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

A private key has two valid encodings, and the type selects between them:

=over

=item * C<'private_seed'> - the 64-byte generation seed. Compact; the reader
re-derives the key from it. Only available if the key has one, see L</has_seed>.

=item * C<'private_expanded'> - the expanded key. Always available, and what a
peer that cannot handle the seed form expects.

=item * C<'private_both'> - both in one structure. On import the seed is
re-expanded and checked against the expanded key.

=item * C<'private'> - C<private_seed> when the key has a seed,
C<private_expanded> otherwise.

=back

 my $seed_der     = $kem->export_key_der('private_seed');
 my $expanded_der = $kem->export_key_der('private_expanded');
 my $both_der     = $kem->export_key_der('private_both');

B<Note> that C<'private'> therefore depends on how the key was obtained: one
from L</generate_key>, L</make_key_from_seed> or a seed-form import has a seed
and exports the short form, while one from L</import_key_raw> or an
expanded-form import does not. Name the encoding explicitly when the output
has to be stable or has to interoperate with a specific peer.

C<'private_seed'> and C<'private_both'> croak on a key with no seed.
L</import_key> reads all three encodings.

=head2 export_key_pem

Returns the key as a PEM-encoded string (ASCII).

 my $private_pem = $kem->export_key_pem('private');
 my $public_pem  = $kem->export_key_pem('public');

The private-key types of L</export_key_der> work here too; they all use
the same C<PRIVATE KEY> PEM header.

 my $seed_pem     = $kem->export_key_pem('private_seed');
 my $expanded_pem = $kem->export_key_pem('private_expanded');

B<Password protection is not supported> for these keys.

=head2 export_key_jwk

Returns the key as a JWK (JSON Web Key) - a JSON string, or a hashref when the
second argument is true.

 my $private_jwk = $kem->export_key_jwk('private');
 my $public_jwk  = $kem->export_key_jwk('public');
 my $hashref     = $kem->export_key_jwk('public', 1);

 # returns JSON like:
 {
   "kty":"AKP",              # Algorithm Key Pair
   "alg":"ML-KEM-768",            # names the parameter set
   "pub":"...",              # base64url of the public key
   "priv":"..."              # base64url of the 64-byte seed d || z, private only
 }

RFC 9964 defines the JWK serialisation of C<AKP> keys; draft-ietf-jose-pqc-kem
supplies the ML-KEM specifics - C<alg> names the parameter set, C<pub> carries
the encapsulation key, and C<priv> B<MUST> be the 64-byte ML-KEM seed
C<d || z>. Note that the ML-KEM document is written against COSE, so the JWK
form here follows the C<AKP> serialisation by analogy rather than from an
explicit JWK specification.

A key with no seed cannot be exported as a private JWK - there is no encoding
for the expanded decapsulation key - so C<export_key_jwk('private')> croaks;
test with L</has_seed> first.

There are no C<private_seed> / C<private_expanded> / C<private_both> variants as
there are for L</export_key_der>, because a JWK has a single C<priv> member with
a single defined meaning.

=head2 export_key_jwk_thumbprint

Returns the JWK thumbprint (RFC 7638) of the public key as a base64url string,
computed over C<kty>, C<alg> and C<pub> as RFC 9964 prescribes for C<AKP> keys.

 my $thumbprint = $kem->export_key_jwk_thumbprint;           # SHA256 (DEFAULT)
 my $thumbprint = $kem->export_key_jwk_thumbprint('SHA512');

=head2 export_key_raw

Returns the raw key as a binary string.

 my $private_bytes = $kem->export_key_raw('private');
 my $public_bytes  = $kem->export_key_raw('public');
 my $seed          = $kem->export_key_raw('seed');

The private key is always the expanded key. C<'seed'> returns the 64-byte
generation seed instead, which L</make_key_from_seed> accepts; it croaks on a
key with no seed, so test with L</has_seed> first.

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

=head2 supported_algorithms

Returns the list of ML-KEM parameter-set names this build accepts, ordered
by increasing security level. Can be called as a class method, as an object
method, or as a plain function.

 my @algs = Crypt::PQ::MLKEM->supported_algorithms;
 # ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024')

Every returned name is valid wherever a parameter set is expected, i.e. in
L</generate_key>, L</make_key_from_seed>, L</import_key_raw> and L</sizes>.
Those all accept the name case-insensitively and ignore C<-> and C<_>, so
C<'ml_kem_768'> and C<'MLKEM768'> work too; the names returned here are the
canonical FIPS 203 spellings reported by L</algorithm>.

=head2 sizes

Returns a hashref with the byte lengths fixed by an ML-KEM parameter set.
Can be called as a class method with an explicit parameter set, as an
object method (the parameter set of the loaded key is used), or as a
plain function.

 my $s = Crypt::PQ::MLKEM->sizes('ML-KEM-768');
 my $s = $kem->sizes;
 my $s = Crypt::PQ::MLKEM::sizes('ML-KEM-768');

 # returns a hash like:
 {
   public_key    => 1184,  # encapsulation key, export_key_raw('public')
   private_key   => 2400,  # decapsulation key, export_key_raw('private')
   ciphertext    => 1088,  # first value returned by encapsulate
   shared_secret => 32,    # second value returned by encapsulate
   keygen_seed   => 64,    # $seed accepted by make_key_from_seed
   encaps_seed   => 32,    # $m accepted by encapsulate_ex
 }

When called on an object with no key loaded returns C<undef>. An
explicit parameter-set argument is ignored when called on an object.

=head2 is_private

 my $rv = $kem->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 has_seed

Whether the loaded key carries the generation seed it was derived from, i.e.
whether C<export_key_raw('seed')>, C<export_key_der('private_seed')> and
C<export_key_der('private_both')> can be used.

 my $rv = $kem->has_seed;
 # 1 .. seed available
 # 0 .. no seed (expanded key only)
 # undef .. no key loaded

A seed cannot be recovered from an expanded key, so this is true only for keys
from L</generate_key>, L</make_key_from_seed>, or an import of a seed-form or
both-form private key.

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is loaded.

 my $hash = $kem->key2hash;

 # returns a hash like:
 {
   alg  => "ML-KEM-768",
   pub  => "...",   # raw public key as a hexadecimal string
   priv => "...",   # raw private key as a hexadecimal string (or undef)
   seed => "...",   # generation seed as a hexadecimal string (or undef)
 }

=head1 SEE ALSO

=over

=item * L<https://csrc.nist.gov/pubs/fips/203/final> - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard

=item * L<Crypt::PQ::MLDSA>, L<Crypt::PQ::SLHDSA>

=back

=cut
