package Crypt::PK::Ed25519;

use strict;
use warnings;
our $VERSION = '0.085';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
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

  if ($data =~ /-----BEGIN (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----(.+?)-----END (PUBLIC|PRIVATE|ENCRYPTED PRIVATE) KEY-----/s) {
    return $self->_import_pem($data, $password);
  }
  elsif ($data =~ /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s) {
    return $self->_import_pem($data, undef);
  }
  elsif ($data =~ /-----BEGIN OPENSSH (PUBLIC|PRIVATE) KEY-----(.+?)-----END/s) {
    return $self->_import_openssh($data, $password);
  }
  elsif ($data =~ /---- BEGIN SSH2 PUBLIC KEY ----(.+?)---- END SSH2 PUBLIC KEY ----/s) {
    return $self->_import_openssh($data, undef);
  }
  elsif ($data =~ /^\s*(\{.*?\})\s*$/s) { # JSON
    my $h = CryptX::_decode_json("$1");
    if ($h->{kty} && $h->{kty} eq "OKP" && $h->{crv} && $h->{crv} eq 'Ed25519') {
      return $self->_import_raw(decode_b64u($h->{d}), 1) if $h->{d}; # private
      return $self->_import_raw(decode_b64u($h->{x}), 0) if $h->{x}; # public
    }
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
  return der_to_pem($key, "PRIVATE KEY", $password, $cipher) if substr($type, 0, 7) eq 'private';
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

 use Crypt::PK::Ed25519;

 #Signature: Alice
 my $priv = Crypt::PK::Ed25519->new('Alice_priv_ed25519.der');
 my $sig = $priv->sign_message($message);

 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::Ed25519->new('Alice_pub_ed25519.der');
 $pub->verify_message($sig, $message) or die "ERROR";

 #Load key
 my $pk = Crypt::PK::Ed25519->new;
 my $pk_hex = "A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D";
 $pk->import_key_raw(pack("H*", $pk_hex), "public");
 my $sk = Crypt::PK::Ed25519->new;
 my $sk_hex = "45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD";
 $sk->import_key_raw(pack("H*", $sk_hex), "private");

 #Key generation
 my $pk = Crypt::PK::Ed25519->new->generate_key;
 my $private_der = $pk->export_key_der('private');
 my $public_der  = $pk->export_key_der('public');
 my $private_pem = $pk->export_key_pem('private');
 my $public_pem  = $pk->export_key_pem('public');
 my $private_raw = $pk->export_key_raw('private');
 my $public_raw  = $pk->export_key_raw('public');
 my $private_jwk = $pk->export_key_jwk('private');
 my $public_jwk  = $pk->export_key_jwk('public');

=head1 DESCRIPTION

I<Since: CryptX-0.067>

=head1 METHODS

=head2 new

 my $pk = Crypt::PK::Ed25519->new();
 #or
 my $pk = Crypt::PK::Ed25519->new($priv_or_pub_key_filename);
 #or
 my $pk = Crypt::PK::Ed25519->new(\$buffer_containing_priv_or_pub_key);

Support for password protected PEM keys

 my $pk = Crypt::PK::Ed25519->new($priv_pem_key_filename, $password);
 #or
 my $pk = Crypt::PK::Ed25519->new(\$buffer_containing_priv_pem_key, $password);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key;

=head2 import_key

Loads private or public key in DER or PEM format.

 $pk->import_key($filename);
 #or
 $pk->import_key(\$buffer_containing_key);

Support for password protected PEM keys:

 $pk->import_key($filename, $password);
 #or
 $pk->import_key(\$buffer_containing_key, $password);

Loading private or public keys form perl hash:

 $pk->import_key($hashref);

 # the $hashref is either a key exported via key2hash
 $pk->import_key({
      curve => "ed25519",
      pub   => "A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D",
      priv  => "45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD",
 });

 # or a hash with items corresponding to JWK (JSON Web Key)
 $pk->import_key({
       kty => "OKP",
       crv => "Ed25519",
       d   => "RcEJum_STotn0j77a5LZnNRX4hNxcsDXSf4rWgwULa0",
       x   => "oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0",
 });

Supported key formats:

 # all formats can be loaded from a file
 my $pk = Crypt::PK::Ed25519->new($filename);

 # or from a buffer containing the key
 my $pk = Crypt::PK::Ed25519->new(\$buffer_with_key);

=over

=item * Ed25519 private keys in PEM format

 -----BEGIN ED25519 PRIVATE KEY-----
 MC4CAQAwBQYDK2VwBCIEIEXBCbpv0k6LZ9I++2uS2ZzUV+ITcXLA10n+K1oMFC2t
 -----END ED25519 PRIVATE KEY-----

=item * Ed25519 private keys in password protected PEM format

 -----BEGIN ED25519 PRIVATE KEY-----
 Proc-Type: 4,ENCRYPTED
 DEK-Info: DES-CBC,6A64D756D49C1EFF

 8xQ7OyfQ10IITNEKcJGZA53Z1yk+NJQU7hrKqXwChZtgWNInhMBJRl9pozLKDSkH
 v7u6EOve8NY=
 -----END ED25519 PRIVATE KEY-----

=item * PKCS#8 private keys

 -----BEGIN PRIVATE KEY-----
 MC4CAQAwBQYDK2VwBCIEIEXBCbpv0k6LZ9I++2uS2ZzUV+ITcXLA10n+K1oMFC2t
 -----END PRIVATE KEY-----

=item * PKCS#8 encrypted private keys

 -----BEGIN ENCRYPTED PRIVATE KEY-----
 MIGHMEsGCSqGSIb3DQEFDTA+MCkGCSqGSIb3DQEFDDAcBAjPx9JkdpRH2QICCAAw
 DAYIKoZIhvcNAgkFADARBgUrDgMCBwQIWWieQojaWTcEOGj43SxqHUys4Eb2M27N
 AkhqpmhosOxKrpGi0L3h8m8ipHE8EwI94NeOMsjfVw60aJuCrssY5vKN
 -----END ENCRYPTED PRIVATE KEY-----

=item * Ed25519 public keys in PEM format

 -----BEGIN PUBLIC KEY-----
 MCowBQYDK2VwAyEAoF0a6lgwrJplzfs4RmDUl+NpfEa0Gc8s7IXei9JFRZ0=
 -----END PUBLIC KEY-----

=item * Ed25519 public key from X509 certificate

 -----BEGIN CERTIFICATE-----
 MIIBODCB66ADAgECAhRWDU9FZBBUZ7KTdX8f7Bco8jsoaTAFBgMrZXAwETEPMA0G
 A1UEAwwGQ3J5cHRYMCAXDTIwMDExOTEzMDIwMloYDzIyOTMxMTAyMTMwMjAyWjAR
 MQ8wDQYDVQQDDAZDcnlwdFgwKjAFBgMrZXADIQCgXRrqWDCsmmXN+zhGYNSX42l8
 RrQZzyzshd6L0kVFnaNTMFEwHQYDVR0OBBYEFHCGFtVibAxxWYyRt5wazMpqSZDV
 MB8GA1UdIwQYMBaAFHCGFtVibAxxWYyRt5wazMpqSZDVMA8GA1UdEwEB/wQFMAMB
 Af8wBQYDK2VwA0EAqG/+98smzqF/wmFX3zHXSaA67as202HnBJod1Tiurw1f+lr3
 BX6OMtsDpgRq9O77IF1Qyx/MdJEwwErczOIbAA==
 -----END CERTIFICATE-----

=item * SSH public Ed25519 keys

 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++

=item * SSH public Ed25519 keys (RFC-4716 format)

 ---- BEGIN SSH2 PUBLIC KEY ----
 Comment: "256-bit ED25519, converted from OpenSSH"
 AAAAC3NzaC1lZDI1NTE5AAAAIL0XsiFcRDp6Hpsoak8OdiiBMJhM2UKszNTxoGS7dJ++
 ---- END SSH2 PUBLIC KEY ----

=item * Ed25519 private keys in JSON Web Key (JWK) format

See L<https://tools.ietf.org/html/rfc8037>

 {
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0",
  "d":"RcEJum_STotn0j77a5LZnNRX4hNxcsDXSf4rWgwULa0",
 }

B<BEWARE:> For JWK support you need to have L<JSON> module installed.

=item * Ed25519 public keys in JSON Web Key (JWK) format

 {
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0",
 }

B<BEWARE:> For JWK support you need to have L<JSON> module installed.

=back

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

Support for password protected PEM keys

 my $private_pem = $pk->export_key_pem('private', $password);
 #or
 my $private_pem = $pk->export_key_pem('private', $password, $cipher);

 # supported ciphers: 'DES-CBC'
 #                    'DES-EDE3-CBC'
 #                    'SEED-CBC'
 #                    'CAMELLIA-128-CBC'
 #                    'CAMELLIA-192-CBC'
 #                    'CAMELLIA-256-CBC'
 #                    'AES-128-CBC'
 #                    'AES-192-CBC'
 #                    'AES-256-CBC' (DEFAULT)

=head2 export_key_jwk

Exports public/private keys as a JSON Web Key (JWK).

 my $private_json_text = $pk->export_key_jwk('private');
 #or
 my $public_json_text = $pk->export_key_jwk('public');

Also exports public/private keys as a perl HASH with JWK structure.

 my $jwk_hash = $pk->export_key_jwk('private', 1);
 #or
 my $jwk_hash = $pk->export_key_jwk('public', 1);

B<BEWARE:> For JWK support you need to have L<JSON> module installed.

=head2 export_key_raw

Export raw public/private key

 my $private_bytes = $pk->export_key_raw('private');
 #or
 my $public_bytes = $pk->export_key_raw('public');

=head2 sign_message

 my $signature = $priv->sign_message($message);

=head2 verify_message

 my $valid = $pub->verify_message($signature, $message)

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
