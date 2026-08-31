package Crypt::PQ::SLHDSA;

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
    # JWK-like structure, draft-ietf-cose-sphincs-plus e.g.
    # {"kty":"AKP","alg":"SLH-DSA-SHA2-128s","pub":"...","priv":"..."}
    return $self->_import_jwk($key) if $key->{kty};
    croak "FATAL: unexpected SLH-DSA key hash";
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
  croak "FATAL: invalid or unsupported SLH-DSA key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  if ($type eq 'private') {
    croak "FATAL: export_key_pem: password-protected PEM is not supported for PKCS#8 keys yet, see the export_key_pem documentation" if defined $password;
    return der_to_pem($key, "PRIVATE KEY");
  }
  return der_to_pem($key, "PUBLIC KEY") if $type eq 'public';
}

# draft-ietf-cose-sphincs-plus registers only the two NIST category 1 "small"
# parameter sets, one per hash family, so those are the only ones with an 'alg'
our %JWK_ALG = map { $_ => 1 } ('SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s');

sub _import_jwk {
  # kty=AKP, pub = PK.seed || PK.root (32 bytes),
  # priv = SK.seed || SK.prf || PK.seed || PK.root (64 bytes)
  my ($self, $h) = @_;
  croak "FATAL: unexpected SLH-DSA key hash" unless ref($h) eq 'HASH';
  croak "FATAL: unsupported JWK kty '" . ($h->{kty} // '') . "', expected 'AKP'"
    unless ($h->{kty} // '') eq 'AKP';
  my $alg = $h->{alg} or croak "FATAL: JWK is missing 'alg'";
  croak "FATAL: JWK is missing 'pub'" unless defined $h->{pub};

  return $self->import_key_raw(decode_b64u($h->{priv}), 'private', $alg) if defined $h->{priv};
  return $self->import_key_raw(decode_b64u($h->{pub}),  'public',  $alg);
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  croak "FATAL: no 'alg' is registered for $kh->{alg}, draft-ietf-cose-sphincs-plus covers only "
        . join(' and ', sort keys %JWK_ALG)
    unless $JWK_ALG{$kh->{alg}};
  if ($type && $type eq 'private') {
    croak "FATAL: not a private key" unless $kh->{priv};
    my $hash = {
      kty  => "AKP",
      alg  => $kh->{alg},
      pub  => encode_b64u(pack("H*", $kh->{pub})),
      priv => encode_b64u(pack("H*", $kh->{priv})),
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
  # SLH-DSA thumbprints follow the RFC 9964 process: kty, alg and pub
  my $json = CryptX::_encode_json({ alg => $h->{alg}, kty => $h->{kty}, pub => $h->{pub} });
  return digest_data_b64u($hash_name, $json);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PQ::SLHDSA - Post-quantum digital signature (FIPS 205, SLH-DSA / SPHINCS+)

=head1 SYNOPSIS

 use Crypt::PQ::SLHDSA;

 my $message = 'hello world';
 my $signer = Crypt::PQ::SLHDSA->new;
 $signer->generate_key('SLH-DSA-SHA2-128s');
 my $signature = $signer->sign_message($message);

 my $public_der = $signer->export_key_der('public');
 my $verifier = Crypt::PQ::SLHDSA->new(\$public_der);
 $verifier->verify_message($signature, $message) or die "ERROR";

=head1 DESCRIPTION

Stateless Hash-Based Digital Signature Algorithm (SLH-DSA, derived from
SPHINCS+) as standardised in NIST FIPS 205. SLH-DSA defines twelve "pure"
parameter sets along three axes: hash family (SHA-2 or SHAKE), security
strength (128/192/256 bits) and tradeoff (s = small signature, slower
signing; f = fast signing, larger signatures).

Pure parameter sets:

  SLH-DSA-SHA2-128s    SLH-DSA-SHA2-128f
  SLH-DSA-SHA2-192s    SLH-DSA-SHA2-192f
  SLH-DSA-SHA2-256s    SLH-DSA-SHA2-256f
  SLH-DSA-SHAKE-128s   SLH-DSA-SHAKE-128f
  SLH-DSA-SHAKE-192s   SLH-DSA-SHAKE-192f
  SLH-DSA-SHAKE-256s   SLH-DSA-SHAKE-256f

Pre-hash parameter sets (FIPS 205 HashSLH-DSA):

  HASH-SLH-DSA-SHA2-128s-WITH-SHA256
  HASH-SLH-DSA-SHA2-128f-WITH-SHA256
  HASH-SLH-DSA-SHA2-192s-WITH-SHA512
  HASH-SLH-DSA-SHA2-192f-WITH-SHA512
  HASH-SLH-DSA-SHA2-256s-WITH-SHA512
  HASH-SLH-DSA-SHA2-256f-WITH-SHA512
  HASH-SLH-DSA-SHAKE-128s-WITH-SHAKE128
  HASH-SLH-DSA-SHAKE-128f-WITH-SHAKE128
  HASH-SLH-DSA-SHAKE-192s-WITH-SHAKE256
  HASH-SLH-DSA-SHAKE-192f-WITH-SHAKE256
  HASH-SLH-DSA-SHAKE-256s-WITH-SHAKE256
  HASH-SLH-DSA-SHAKE-256f-WITH-SHAKE256

I<Since: CryptX-0.100>

=head1 METHODS

=head2 new

 my $sig = Crypt::PQ::SLHDSA->new;
 my $sig = Crypt::PQ::SLHDSA->new($filename);
 my $sig = Crypt::PQ::SLHDSA->new(\$buffer_with_key);
 my $sig = Crypt::PQ::SLHDSA->new($filename, $password);

When called without arguments, returns an empty object on which
L</generate_key> or L</import_key> can be invoked. When called with a
filename or scalar reference, the key material is imported via
L</import_key>.

=head2 generate_key

Generates a new SLH-DSA key pair using the bundled C<chacha20> PRNG.
Returns the object itself (for chaining).

 $sig->generate_key('SLH-DSA-SHA2-128s');
 $sig->generate_key('SLH-DSA-SHAKE-256f');

B<NOTE:> the C<256s> and similar "small" parameter sets can take several
seconds (up to a minute) for a single signing operation. The C<128f>
variant is the cheapest.

=head2 make_key_from_seed

Generates a key pair B<deterministically> from the concatenation of
SLH-DSA's three secret seeds C<SK.seed || SK.prf || PK.seed>, FIPS 205
10.1. Each seed is C<n> bytes, so the input must be exactly C<3*n>
bytes long: 48 for the C<128*> parameter sets, 72 for C<192*>, 96 for
C<256*>. Mainly used for known-answer test vectors and reproducible
test setups; do not use a fixed or low-entropy seed in production.
Returns the object itself (for chaining).

 $sig->make_key_from_seed($seed, 'SLH-DSA-SHA2-128s');

=head2 import_key

Loads an SLH-DSA key in DER or PEM format. The parameter set is
auto-detected from the encoded OID.

 $sig->import_key($filename);
 $sig->import_key(\$buffer_with_key);
 $sig->import_key($filename, $password);

A JWK (draft-ietf-cose-sphincs-plus) is also accepted, either as a JSON string or as an
already decoded hashref:

 $sig->import_key(\$json_with_jwk);
 $sig->import_key($hashref_with_jwk);

=head2 import_key_raw

Imports a raw (unencoded) SLH-DSA key. Both the key C<$type> and the
parameter set C<$alg> must be specified explicitly because raw key
material has no associated algorithm identifier.

 $sig->import_key_raw($pubkey,  'public',  'SLH-DSA-SHA2-128s');
 $sig->import_key_raw($privkey, 'private', 'SLH-DSA-SHA2-128s');

=head2 export_key_der

 my $private_der = $sig->export_key_der('private');
 my $public_der  = $sig->export_key_der('public');

=head2 export_key_pem

 my $private_pem = $sig->export_key_pem('private');
 my $public_pem  = $sig->export_key_pem('public');

B<Password protection is not supported> for these keys.

=head2 export_key_jwk

Returns the key as a JWK (JSON Web Key) - a JSON string, or a hashref when the
second argument is true.

 my $private_jwk = $sig->export_key_jwk('private');
 my $public_jwk  = $sig->export_key_jwk('public');
 my $hashref     = $sig->export_key_jwk('public', 1);

 # returns JSON like:
 {
   "kty":"AKP",              # Algorithm Key Pair
   "alg":"SLH-DSA-SHA2-128s",     # names the parameter set
   "pub":"...",              # base64url of the public key
   "priv":"..."              # base64url of SK.seed||SK.prf||PK.seed||PK.root
 }

C<pub> is C<PK.seed || PK.root> (32 bytes) and C<priv> is the full private key
C<SK.seed || SK.prf || PK.seed || PK.root> (64 bytes) - unlike ML-DSA and ML-KEM
there is no seed form, so any private key can be exported.

B<Only two parameter sets have a registered> C<alg>: C<SLH-DSA-SHA2-128s> and
C<SLH-DSA-SHAKE-128s>. The draft registers just the two NIST category 1 "small"
sets, one per hash family, to keep early interoperability tight; the other ten
pure sets and all the pre-hash sets have no C<alg> and cannot be expressed as a
JWK, so C<export_key_jwk> croaks for them.

There are no C<private_seed> / C<private_expanded> / C<private_both> variants as
there are for L</export_key_der>, because a JWK has a single C<priv> member with
a single defined meaning.

=head2 export_key_jwk_thumbprint

Returns the JWK thumbprint (RFC 7638) of the public key as a base64url string,
computed over C<kty>, C<alg> and C<pub> as RFC 9964 prescribes for C<AKP> keys.

 my $thumbprint = $sig->export_key_jwk_thumbprint;           # SHA256 (DEFAULT)
 my $thumbprint = $sig->export_key_jwk_thumbprint('SHA512');

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

B<Deterministic signing> (FIPS 205 10.2 slh_sign_internal). Identical
to L</sign_message> but uses the caller-supplied C<$optrand> instead of
drawing from a PRNG. Passing all-zero bytes produces the spec's
deterministic variant; passing fresh random bytes produces the hedged
variant. Mainly used for known-answer test vectors.

 my $signature = $sig->sign_message_ex($message, $context, $optrand);

C<$context> may be C<undef> for the empty context. C<$optrand> length
must equal the parameter set's security parameter C<n>: 16 bytes for
the C<128*> variants, 24 for C<192*>, 32 for C<256*>.

=head2 verify_message

Returns C<1> if the signature is valid, C<0> otherwise.

 my $valid = $sig->verify_message($signature, $message);
 my $valid = $sig->verify_message($signature, $message, $context);

=head2 algorithm

Returns the parameter-set name of the loaded key (e.g.
C<"SLH-DSA-SHA2-128s">), or C<undef> if no key is loaded.

=head2 supported_algorithms

Returns the list of all 24 SLH-DSA parameter-set names this build accepts:
the twelve pure parameter sets first, then the twelve HashSLH-DSA (pre-hash)
forms, each group ordered as in FIPS 205. Can be called as a class method, as
an object method, or as a plain function.

 my @algs = Crypt::PQ::SLHDSA->supported_algorithms;
 # ('SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-128f', ... 'SLH-DSA-SHAKE-256f',
 #  'HashSLH-DSA-SHA2-128s-with-SHA256', ... 'HashSLH-DSA-SHAKE-256f-with-SHAKE256')

Every returned name is valid wherever a parameter set is expected, i.e. in
L</generate_key>, L</make_key_from_seed>, L</import_key_raw> and L</sizes>.
Those all accept the name case-insensitively and ignore C<-> and C<_>, so the
C<HASH-SLH-DSA-...-WITH-...> spelling used above under L</DESCRIPTION> works
just as well as input; the names returned here are the canonical FIPS 205
spellings reported by L</algorithm>.

=head2 sizes

Returns a hashref with the byte lengths fixed by an SLH-DSA parameter set.
Can be called as a class method with an explicit parameter set, as an
object method (the parameter set of the loaded key is used), or as a
plain function.

 my $s = Crypt::PQ::SLHDSA->sizes('SLH-DSA-SHAKE-128f');
 my $s = $pk->sizes;
 my $s = Crypt::PQ::SLHDSA::sizes('SLH-DSA-SHAKE-128f');

 # returns a hash like:
 {
   public_key  => 32,     # verification key, export_key_raw('public')
   private_key => 64,     # signing key, export_key_raw('private')
   signature   => 17088,  # output of sign_message
   keygen_seed => 48,     # $seed accepted by make_key_from_seed
   optrand     => 16,     # $optrand accepted by sign_message_ex
 }

Unlike ML-KEM and ML-DSA, every one of these lengths varies between
SLH-DSA parameter sets.

When called on an object with no key loaded returns C<undef>. An
explicit parameter-set argument is ignored when called on an object.

=head2 is_private

 my $rv = $sig->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is
loaded.

 my $hash = $sig->key2hash;

=head1 SEE ALSO

=over

=item * L<https://csrc.nist.gov/pubs/fips/205/final> - FIPS 205, Stateless Hash-Based Digital Signature Standard

=item * L<Crypt::PQ::MLKEM>, L<Crypt::PQ::MLDSA>

=back

=cut
