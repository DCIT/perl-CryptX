package Crypt::PK::Ed25519;

use strict;
use warnings;
our $VERSION = '0.066_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::PK;
use Crypt::Misc qw(read_rawfile encode_b64u decode_b64u encode_b64 decode_b64 pem_to_der der_to_pem);

sub new {
  my $self = shift->_new();
  return @_ > 0 ? $self->import_key(@_) : $self;
}

sub import_key_raw {
  my ($self, $key, $type) = @_;
  croak "FATAL: undefined key" unless $key;
  croak "FATAL: invalid key" unless length($key) == 32;
  croak "FATAL: undefined type" unless $type;
  return $self->_import_raw($key, 1) if $type eq 'private';
  return $self->_import_raw($key, 0) if $type eq 'public';
  croak "FATAL: invalid key type '$type'";
}

sub import_key {
  my ($self, $key, $password) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  croak "FATAL: undefined key" unless $key;

  # special case
  if (ref($key) eq 'HASH') {
    if ($key->{kty} && $key->{kty} eq "OKP" && $key->{crv} && $key->{crv} eq 'Ed25519') {
      # JWK-like structure e.g.
      # {"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}
      return $self->_import_raw(decode_b64u($key->{d}), 1) if $key->{d}; # private
      return $self->_import_raw(decode_b64u($key->{x}), 0) if $key->{x}; # public
    }
    if ($key->{curve} && $key->{curve} eq "ed25519" && ($key->{priv} || $key->{pub})) {
      # hash exported via key2hash
      return $self->_import_raw(pack("H*", $key->{priv}), 1) if $key->{priv};
      return $self->_import_raw(pack("H*", $key->{pub}),  0) if $key->{pub};
    }
    croak "FATAL: unexpected Ed25519 key hash";
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

  if ($data =~ /-----BEGIN PUBLIC KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import($data);
  }
  elsif ($data =~ /-----BEGIN PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /-----BEGIN ENCRYPTED PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /-----BEGIN ED25519 PRIVATE KEY-----(.*?)-----END/sg) {
    $data = pem_to_der($data, $password);
    return $self->_import_pkcs8($data, $password);
  }
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) { # JSON
    my $h = CryptX::_decode_json("$1");
    if ($h->{kty} && $h->{kty} eq "OKP" && $h->{crv} && $h->{crv} eq 'Ed25519') {
      return $self->_import_raw(decode_b64u($h->{d}), 1) if $h->{d}; # private
      return $self->_import_raw(decode_b64u($h->{x}), 0) if $h->{x}; # public
    }
  }
  elsif ($data =~ /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/sg) {
    $data = pem_to_der($data);
    return $self->_import_x509($data);
  }
  elsif ($data =~ /-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END/sg) {
    #XXX-FIXME-TODO
    # https://crypto.stackexchange.com/questions/71789/openssh-ed2215-private-key-format
    # https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
    croak "FATAL: OPENSSH PRIVATE KEY not supported";
  }
  elsif ($data =~ /---- BEGIN SSH2 PUBLIC KEY ----(.*?)---- END SSH2 PUBLIC KEY ----/sg) {
    $data = pem_to_der($data);
    my ($typ, $pubkey) = Crypt::PK::_ssh_parse($data);
    return $self->_import_raw($pubkey, 0) if $typ eq 'ssh-ed25519' && length($pubkey) == 32;
  }
  elsif ($data =~ /(ssh-ed25519)\s+(\S+)/) {
    $data = decode_b64("$2");
    my ($typ, $pubkey) = Crypt::PK::_ssh_parse($data);
    return $self->_import_raw($pubkey, 0) if $typ eq 'ssh-ed25519' && length($pubkey) == 32;
  }
  elsif (length($data) == 32) {
    croak "FATAL: use import_key_raw() to load raw (32 bytes) Ed25519 key";
  }
  else {
    my $rv = eval { $self->_import($data) }                  ||
             eval { $self->_import_pkcs8($data, $password) } ||
             eval { $self->_import_x509($data) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported Ed25519 key format";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $key = $self->export_key_der($type||'');
  return unless $key;
  return der_to_pem($key, "ED25519 PRIVATE KEY", $password, $cipher) if substr($type, 0, 7) eq 'private';
  return der_to_pem($key, "PUBLIC KEY") if substr($type,0, 6) eq 'public';
}

sub export_key_jwk {
  my ($self, $type, $wanthash) = @_;
  local $SIG{__DIE__} = \&CryptX::_croak;
  my $kh = $self->key2hash;
  return unless $kh;
  my $hash = { kty => "OKP", crv => "Ed25519" };
  $hash->{x} = encode_b64u(pack("H*", $kh->{pub}));
  $hash->{d} = encode_b64u(pack("H*", $kh->{priv})) if $type && $type eq 'private' && $kh->{priv};
  return $wanthash ? $hash : CryptX::_encode_json($hash);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::Ed25519 - Digital signature based on Ed25519

=head1 SYNOPSIS

=head1 METHODS

=head2 new

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key;

=head2 import_key

TODO

=head2 import_key_raw

Import raw public/private key - can load raw key data exported by L</export_key_raw>.

 $pk->import_key_raw($key, 'public');
 $pk->import_key_raw($key, 'private');

=head2 export_key_der

 my $private_der = $pk->export_key_der('private');
 #or
 my $public_der = $pk->export_key_der('public');

=head2 export_key_pem

 my $private_pem = $pk->export_key_pem('private');
 #or
 my $public_pem = $pk->export_key_pem('public');

=head2 export_key_jwk

Exports public/private keys as a JSON Web Key (JWK).

 my $private_json_text = $pk->export_key_jwk('private');
 #or
 my $public_json_text = $pk->export_key_jwk('public');

Also exports public/private keys as a perl HASH with JWK structure.

 my $jwk_hash = $pk->export_key_jwk('private', 1);
 #or
 my $jwk_hash = $pk->export_key_jwk('public', 1);

B<BEWARE:> For JWK support you need to have L<JSON::PP>, L<JSON::XS> or L<Cpanel::JSON::XS> module.

=head2 export_key_raw

Export raw public/private key

 my $private_pem = $pk->export_key_raw('private');
 #or
 my $public_pem = $pk->export_key_raw('public');

=head2 sign_message

 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

 my $valid = $pub->verify_message($signature, $message)
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 is_private

 my $rv = $pk->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 key2hash

 my $hash = $pk->key2hash;

 # returns hash like this (or undef if no key loaded):
 {
   curve => "ed25519",
   # raw public key as a hexadecimal string
   pub   => "A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D",
   # raw private key as a hexadecimal string. undef if key is public only
   priv  => "45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD",
 }

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/EdDSA#Ed25519>

=item * L<https://en.wikipedia.org/wiki/Curve25519>

=item * L<https://tools.ietf.org/html/rfc8032>

=back

=cut
