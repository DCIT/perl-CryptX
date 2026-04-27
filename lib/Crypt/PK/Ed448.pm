package Crypt::PK::Ed448;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::PK;
use Crypt::Misc qw(read_rawfile encode_b64u decode_b64u pem_to_der der_to_pem);

sub new {
  my $self = shift->_new();
  return @_ > 0 ? $self->import_key(@_) : $self;
}

sub import_key_raw {
  my ($self, $key, $type) = @_;
  croak "FATAL: undefined key" unless $key;
  croak "FATAL: invalid key" unless length($key) == 57;
  croak "FATAL: undefined type" unless $type;
  return $self->_import_raw($key, 1) if $type eq 'private';
  return $self->_import_raw($key, 0) if $type eq 'public';
  croak "FATAL: invalid key type '$type'";
}

sub import_key {
  my ($self, $key, $password) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  croak "FATAL: undefined key" unless $key;

  if (ref($key) eq 'HASH') {
    if ($key->{kty} && $key->{kty} eq "OKP" && $key->{crv} && $key->{crv} eq 'Ed448') {
      return $self->_import_raw(decode_b64u($key->{d}), 1) if $key->{d};
      return $self->_import_raw(decode_b64u($key->{x}), 0) if $key->{x};
    }
    if ($key->{curve} && $key->{curve} eq "ed448" && ($key->{priv} || $key->{pub})) {
      return $self->_import_raw(pack("H*", $key->{priv}), 1) if $key->{priv};
      return $self->_import_raw(pack("H*", $key->{pub}),  0) if $key->{pub};
    }
    croak "FATAL: unexpected Ed448 key hash";
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
    return $self->_import_x509(pem_to_der($data));
  }
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) {
    my $h = CryptX::_decode_json("$1") || {};
    if ($h->{kty} && $h->{kty} eq "OKP" && $h->{crv} && $h->{crv} eq 'Ed448') {
      return $self->_import_raw(decode_b64u($h->{d}), 1) if $h->{d};
      return $self->_import_raw(decode_b64u($h->{x}), 0) if $h->{x};
    }
  }
  elsif (length($data) == 57) {
    croak "FATAL: use import_key_raw() to load raw (57 bytes) Ed448 key";
  }
  else {
    my $rv = eval { $self->_import($data) }                  ||
             eval { $self->_import_pkcs8($data, $password) } ||
             eval { $self->_import_x509($data) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported Ed448 key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  return der_to_pem($key, "PRIVATE KEY", $password, $cipher) if $type eq 'private';
  return der_to_pem($key, "PUBLIC KEY") if $type eq 'public';
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  my $hash = { kty => "OKP", crv => "Ed448" };
  $hash->{x} = encode_b64u(pack("H*", $kh->{pub}));
  $hash->{d} = encode_b64u(pack("H*", $kh->{priv})) if $type && $type eq 'private' && $kh->{priv};
  return $wanthash ? $hash : CryptX::_encode_json($hash);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::Ed448 - Digital signature based on Ed448

=head1 SYNOPSIS

 use Crypt::PK::Ed448;

 my $message = 'hello world';
 my $signer = Crypt::PK::Ed448->new->generate_key;
 my $signature = $signer->sign_message($message);

 my $public_der = $signer->export_key_der('public');
 my $verifier = Crypt::PK::Ed448->new(\$public_der);
 $verifier->verify_message($signature, $message) or die "ERROR";

 my $pk = Crypt::PK::Ed448->new;
 $pk->import_key_raw(pack("H*", "1b0055aad3b239a0fa1ed1ea8023151a5791d0bb556435299da6cf1aaa272d858b0238822654bc15f64adbab97f1bb9ec848d72cd8ad856800"), "public");

 my $sk = Crypt::PK::Ed448->new;
 $sk->import_key_raw(pack("H*", "f82bd65291965de46d87c7447863924e8efb8da36993618a784cd3b69a6d66e61cdc0a48a31e66bd8e81e4d77cedc311aa0f72a322ef3e4fad"), "private");

=head1 DESCRIPTION

I<Since: CryptX-0.100>

=head1 METHODS

=head2 new

I<Since: CryptX-0.100>

 my $source = Crypt::PK::Ed448->new();
 $source->generate_key;

 my $public_der = $source->export_key_der('public');
 my $pub = Crypt::PK::Ed448->new(\$public_der);

 my $private_pem = $source->export_key_pem('private', 'secret', 'AES-256-CBC');
 my $priv = Crypt::PK::Ed448->new(\$private_pem, 'secret');

Passing C<$filename> or C<\$buffer> to C<new> is equivalent: both forms
immediately import the key material into the new object.

=head2 generate_key

I<Since: CryptX-0.100>

Returns the object itself (for chaining).

 $pk->generate_key;

=head2 import_key

I<Since: CryptX-0.100>

Loads Ed448 private or public keys from DER, PEM, PKCS#8, X.509 certificates, SubjectPublicKeyInfo, or JWK.

 my $source = Crypt::PK::Ed448->new();
 $source->generate_key;

 my $public_der = $source->export_key_der('public');
 my $pub = Crypt::PK::Ed448->new();
 $pub->import_key(\$public_der);
 my $private_pem = $source->export_key_pem('private', 'secret', 'AES-256-CBC');
 my $priv = Crypt::PK::Ed448->new();
 $priv->import_key(\$private_pem, 'secret');
 $pk->import_key({
   curve => "ed448",
   pub   => "1B0055AAD3B239A0FA1ED1EA8023151A5791D0BB556435299DA6CF1AAA272D858B0238822654BC15F64ADBAB97F1BB9EC848D72CD8AD856800",
   priv  => "F82BD65291965DE46D87C7447863924E8EFB8DA36993618A784CD3B69A6D66E61CDC0A48A31E66BD8E81E4D77CEDC311AA0F72A322EF3E4FAD",
 });
 $pk->import_key({
   kty => "OKP",
   crv => "Ed448",
   d   => "-CvWUpGWXeRth8dEeGOSTo77jaNpk2GKeEzTtpptZuYc3ApIox5mvY6B5Nd87cMRqg9yoyLvPk-t",
   x   => "GwBVqtOyOaD6HtHqgCMVGleR0LtVZDUpnabPGqonLYWLAjiCJlS8FfZK26uX8bueyEjXLNithWgA",
 });

The same method also accepts filenames instead of buffers.

=head2 import_key_raw

I<Since: CryptX-0.100>

Import raw public/private key bytes.

 $pk->import_key_raw($key, 'public');
 $pk->import_key_raw($key, 'private');

The raw key must be exactly 57 bytes long.

=head2 export_key_der

I<Since: CryptX-0.100>

Returns the key as a binary DER-encoded string.

 my $der = $pk->export_key_der('private');
 my $der = $pk->export_key_der('public');

=head2 export_key_pem

I<Since: CryptX-0.100>

Returns the key as a PEM-encoded string (ASCII).

 my $pem = $pk->export_key_pem('private');
 my $pem = $pk->export_key_pem('public');
 my $pem = $pk->export_key_pem('private', $password, 'AES-256-CBC');

=head2 export_key_jwk

I<Since: CryptX-0.100>

Returns a JSON string, or a hashref if the optional second argument is true.

 my $json = $pk->export_key_jwk('private');
 my $hash = $pk->export_key_jwk('public', 1);

=head2 export_key_raw

I<Since: CryptX-0.100>

Returns the raw key as a binary string.

 my $raw = $pk->export_key_raw('private');
 my $raw = $pk->export_key_raw('public');

=head2 sign_message

I<Since: CryptX-0.100>

Returns the signature as a binary string. Ed448 uses a fixed hash internally
(SHAKE256); unlike RSA or ECDSA there is no C<$hash_name> parameter.

 my $signature = $priv->sign_message($message);

=head2 verify_message

I<Since: CryptX-0.100>

Returns C<1> if the signature is valid, C<0> otherwise.

 my $valid = $pub->verify_message($signature, $message);

=head2 is_private

I<Since: CryptX-0.100>

 my $rv = $pk->is_private;

=head2 key2hash

I<Since: CryptX-0.100>

Returns a hashref with the key components, or C<undef> if no key is loaded.

 my $hash = $pk->key2hash;

Returns a hash like:

 {
   curve => "ed448",
   pub   => "1B0055AAD3B239A0FA1ED1EA8023151A5791D0BB556435299DA6CF1AAA272D858B0238822654BC15F64ADBAB97F1BB9EC848D72CD8AD856800",
   priv  => "F82BD65291965DE46D87C7447863924E8EFB8DA36993618A784CD3B69A6D66E61CDC0A48A31E66BD8E81E4D77CEDC311AA0F72A322EF3E4FAD",
 }

=head1 OpenSSL interoperability

 # Generate a key with OpenSSL
 # openssl genpkey -algorithm ed448 -out ed448_priv.pem
 # openssl pkey -in ed448_priv.pem -pubout -out ed448_pub.pem

 # Load the OpenSSL-generated key in CryptX
 use Crypt::PK::Ed448;
 my $priv = Crypt::PK::Ed448->new("ed448_priv.pem");
 my $pub  = Crypt::PK::Ed448->new("ed448_pub.pem");

 # Sign in CryptX, verify with OpenSSL
 my $message = "hello";
 my $signature = $priv->sign_message($message);

 # Export CryptX key for OpenSSL
 my $pem = $priv->export_key_pem('private');
 # then: openssl pkey -in priv.pem -text -noout

=head1 SEE ALSO

=over

=item * L<https://www.rfc-editor.org/rfc/rfc8032>

=item * L<Crypt::PK::Ed25519>

=back

=cut
