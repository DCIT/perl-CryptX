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
    # JWK-like structure, RFC 9964 e.g.
    # {"kty":"AKP","alg":"ML-DSA-44","pub":"...","priv":"..."}
    return $self->_import_jwk($key) if $key->{kty};
    croak "FATAL: unexpected ML-DSA key hash";
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
  croak "FATAL: invalid or unsupported ML-DSA key format";
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
  # RFC 9964 "ML-DSA for JOSE and COSE": kty=AKP, alg names the parameter set,
  # pub is the FIPS 204 5.3 public key and is REQUIRED, priv is the 32-byte seed.
  my ($self, $h) = @_;
  croak "FATAL: unexpected ML-DSA key hash" unless ref($h) eq 'HASH';
  croak "FATAL: unsupported JWK kty '" . ($h->{kty} // '') . "', expected 'AKP'"
    unless ($h->{kty} // '') eq 'AKP';
  my $alg = $h->{alg} or croak "FATAL: JWK is missing 'alg'";
  croak "FATAL: JWK is missing 'pub'" unless defined $h->{pub};

  if (defined $h->{priv}) {
    my $seed = decode_b64u($h->{priv});
    croak "FATAL: JWK 'priv' must be a 32-byte seed (RFC 9964)"
      unless defined $seed && length($seed) == 32;
    $self->make_key_from_seed($seed, $alg);
    # pub is REQUIRED even for private keys, so use it to check the seed expands to it
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
    # RFC 9964 encodes only the seed form: "the priv parameter MUST be the seed
    # and MUST have a length of 32 bytes"
    croak "FATAL: export_key_jwk('private') needs a key with a seed, RFC 9964 has no encoding for the expanded private key"
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
  # RFC 9964: the required members of an AKP thumbprint are kty, alg and pub
  my $json = CryptX::_encode_json({ alg => $h->{alg}, kty => $h->{kty}, pub => $h->{pub} });
  return digest_data_b64u($hash_name, $json);
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

 # External-mu (RFC 9881): pre-hash the message, then sign the representative
 my $mu = $signer->compute_mu($message);
 my $sig2 = $signer->sign_mu($mu);

 # the result is an ordinary ML-DSA signature
 $verifier->verify_message($sig2, $message) or die "ERROR";
 $verifier->verify_mu($sig2, $verifier->compute_mu($message)) or die "ERROR";

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

A JWK (RFC 9964) is also accepted, either as a JSON string or as an already
decoded hashref:

 $sig->import_key(\$json_with_jwk);
 $sig->import_key($hashref_with_jwk);

A private JWK carries the seed, so the imported key has one; a public JWK
yields a public key.

=head2 import_key_raw

Imports a raw (unencoded) ML-DSA key. Both the key C<$type> and the
parameter set C<$alg> must be specified explicitly because raw key
material has no associated algorithm identifier.

 $sig->import_key_raw($pubkey,  'public',  'ML-DSA-65');
 $sig->import_key_raw($privkey, 'private', 'ML-DSA-65');

=head2 export_key_der

 my $private_der = $sig->export_key_der('private');
 my $public_der  = $sig->export_key_der('public');

A private key has two valid encodings, and the type selects between them:

=over

=item * C<'private_seed'> - the 32-byte generation seed. Compact; the reader
re-derives the key from it. Only available if the key has one, see L</has_seed>.

=item * C<'private_expanded'> - the expanded key. Always available, and what a
peer that cannot handle the seed form expects.

=item * C<'private_both'> - both in one structure. On import the seed is
re-expanded and checked against the expanded key.

=item * C<'private'> - C<private_seed> when the key has a seed,
C<private_expanded> otherwise.

=back

 my $seed_der     = $sig->export_key_der('private_seed');
 my $expanded_der = $sig->export_key_der('private_expanded');
 my $both_der     = $sig->export_key_der('private_both');

B<Note> that C<'private'> therefore depends on how the key was obtained: one
from L</generate_key>, L</make_key_from_seed> or a seed-form import has a seed
and exports the short form, while one from L</import_key_raw> or an
expanded-form import does not. Name the encoding explicitly when the output
has to be stable or has to interoperate with a specific peer.

C<'private_seed'> and C<'private_both'> croak on a key with no seed.
L</import_key> reads all three encodings.

=head2 export_key_pem

 my $private_pem = $sig->export_key_pem('private');
 my $public_pem  = $sig->export_key_pem('public');

The private-key types of L</export_key_der> work here too; they all use
the same C<PRIVATE KEY> PEM header.

 my $seed_pem     = $sig->export_key_pem('private_seed');
 my $expanded_pem = $sig->export_key_pem('private_expanded');

B<Password protection is not supported> for these keys.

=head2 export_key_jwk

Returns the key as a JWK (JSON Web Key) as specified by RFC 9964, I<ML-DSA for
JOSE and COSE> - a JSON string, or a hashref when the second argument is true.

 my $private_jwk = $sig->export_key_jwk('private');
 my $public_jwk  = $sig->export_key_jwk('public');
 my $hashref     = $sig->export_key_jwk('public', 1);

 # returns JSON like:
 {
   "kty":"AKP",              # Algorithm Key Pair
   "alg":"ML-DSA-44",        # names the parameter set
   "pub":"...",              # base64url of the FIPS 204 public key
   "priv":"..."              # base64url of the 32-byte seed, private keys only
 }

RFC 9964 encodes B<only> the seed form of an ML-DSA private key - C<priv> must
be the 32-byte seed, and the specification deliberately defines no encoding for
the expanded private key. A key without a seed therefore cannot be exported as
a private JWK and C<export_key_jwk('private')> croaks; test with L</has_seed>
first. Its public JWK is unaffected.

Unlike L</export_key_der> there are no C<private_seed> / C<private_expanded> /
C<private_both> variants, because a JWK has a single C<priv> member with a
single defined meaning.

=head2 export_key_jwk_thumbprint

Returns the JWK thumbprint (RFC 7638) of the public key as a base64url string.
Per RFC 9964 the required members of an C<AKP> thumbprint are C<kty>, C<alg>
and C<pub>.

 my $thumbprint = $sig->export_key_jwk_thumbprint;           # SHA256 (DEFAULT)
 my $thumbprint = $sig->export_key_jwk_thumbprint('SHA512');

=head2 export_key_raw

 my $private_bytes = $sig->export_key_raw('private');
 my $public_bytes  = $sig->export_key_raw('public');
 my $seed          = $sig->export_key_raw('seed');

The private key is always the expanded key. C<'seed'> returns the 32-byte
generation seed instead, which L</make_key_from_seed> accepts; it croaks on a
key with no seed, so test with L</has_seed> first.

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

=head2 compute_mu

Returns the 64-byte B<External-mu> message representative for C<$message>
(RFC 9881, FIPS 204 5.4.1):

 my $mu = $pk->compute_mu($message);
 my $mu = $pk->compute_mu($message, $context);

C<mu> is derived from the public key, the optional context string and the
message, so it can be computed from either a private or a public key - both
give the same value for the same inputs. Signing it with L</sign_mu> produces
an B<ordinary> ML-DSA signature: no special verification path is needed, and
L</verify_message> called with the same C<$message> and C<$context> accepts it.

=head2 sign_mu

Signs a 64-byte C<$mu> from L</compute_mu> and returns the signature as a
binary string.

 my $signature = $pk->sign_mu($mu);

Like L</sign_message> this is hedged - the per-signature randomness comes from
the bundled C<chacha20> PRNG, so two calls on the same C<$mu> give different
(equally valid) signatures. Use L</sign_message_ex_mu> to supply that
randomness yourself.

C<$mu> must have been computed from B<this> key: mu commits to the public key,
so signing a mu derived from a different key pair yields a signature that no
verifier will accept.

=head2 verify_mu

Verifies a signature against a 64-byte C<$mu> instead of against the message.

 my $rv = $pk->verify_mu($signature, $mu);
 # 1 .. signature is valid
 # 0 .. signature is not valid

Useful when the verifier already has C<$mu> and would rather not recompute it
from the message. A signature produced by L</sign_mu> is an ordinary ML-DSA
signature, so a verifier that has the message can equally well use
L</verify_message>.

=head2 algorithm

Returns the parameter-set name of the loaded key (e.g. C<"ML-DSA-65">),
or C<undef> if no key is loaded.

=head2 supported_algorithms

Returns the list of ML-DSA parameter-set names this build accepts, ordered
by increasing security level. Can be called as a class method, as an object
method, or as a plain function.

 my @algs = Crypt::PQ::MLDSA->supported_algorithms;
 # ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87')

Every returned name is valid wherever a parameter set is expected, i.e. in
L</generate_key>, L</make_key_from_seed>, L</import_key_raw> and L</sizes>.
Those all accept the name case-insensitively and ignore C<-> and C<_>, so
C<'ml_dsa_65'> and C<'MLDSA65'> work too; the names returned here are the
canonical FIPS 204 spellings reported by L</algorithm>.

=head2 sizes

Returns a hashref with the byte lengths fixed by an ML-DSA parameter set.
Can be called as a class method with an explicit parameter set, as an
object method (the parameter set of the loaded key is used), or as a
plain function.

 my $s = Crypt::PQ::MLDSA->sizes('ML-DSA-65');
 my $s = $pk->sizes;
 my $s = Crypt::PQ::MLDSA::sizes('ML-DSA-65');

 # returns a hash like:
 {
   public_key  => 1952,  # verification key, export_key_raw('public')
   private_key => 4032,  # signing key, export_key_raw('private')
   signature   => 3309,  # output of sign_message
   keygen_seed => 32,    # $seed accepted by make_key_from_seed
   rnd         => 32,    # $rnd accepted by sign_message_ex and sign_message_ex_mu
   mu          => 64,    # $mu accepted by sign_message_ex_mu
 }

When called on an object with no key loaded returns C<undef>. An
explicit parameter-set argument is ignored when called on an object.

=head2 is_private

 my $rv = $sig->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 has_seed

Whether the loaded key carries the generation seed it was derived from, i.e.
whether C<export_key_raw('seed')>, C<export_key_der('private_seed')> and
C<export_key_der('private_both')> can be used.

 my $rv = $sig->has_seed;
 # 1 .. seed available
 # 0 .. no seed (expanded key only)
 # undef .. no key loaded

A seed cannot be recovered from an expanded key, so this is true only for keys
from L</generate_key>, L</make_key_from_seed>, or an import of a seed-form or
both-form private key.

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is
loaded.

 my $hash = $sig->key2hash;

 # returns a hash like:
 {
   alg  => "ML-DSA-65",
   pub  => "...",   # raw public key as a hexadecimal string
   priv => "...",   # raw private key as a hexadecimal string (or undef)
   seed => "...",   # generation seed as a hexadecimal string (or undef)
 }

=head1 SEE ALSO

=over

=item * L<https://csrc.nist.gov/pubs/fips/204/final> - FIPS 204, Module-Lattice-Based Digital Signature Standard

=item * L<https://www.rfc-editor.org/rfc/rfc9881.html> - RFC 9881, External-mu for ML-DSA

=item * L<Crypt::PQ::MLKEM>, L<Crypt::PQ::SLHDSA>

=back

=cut
