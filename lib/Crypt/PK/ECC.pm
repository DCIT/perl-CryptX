package Crypt::PK::ECC;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( ecc_encrypt ecc_decrypt ecc_sign_message ecc_verify_message ecc_sign_hash ecc_verify_hash ecc_shared_secret )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::PK;
use Crypt::Digest 'digest_data';
use Carp;
use MIME::Base64 qw(encode_base64 decode_base64);

sub new {
  my ($class, $f) = @_;
  my $self = _new();
  $self->import_key($f) if $f;
  return  $self;
}

sub import_key {
  my ($self, $key) = @_;
  croak "FATAL: undefined key" unless $key;
  my $data;
  if (ref($key) eq 'SCALAR') {
    $data = $$key;
  }
  elsif (-f $key) {
    $data = Crypt::PK::_slurp_file($key);
  }
  else {
    croak "FATAL: non-existing file '$key'";
  }
  ### no PEM support
  #if ($data && $data =~ /-----BEGIN (EC PRIVATE|EC PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
  #  $data = decode_base64($2);
  #}
  croak "FATAL: invalid key format" unless $data;
  return $self->_import($data);
}

sub encrypt {
  my ($self, $data, $hash_name) = @_;
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  return $self->_encrypt($data, $hash_name);
}

sub decrypt {
  my ($self, $data) = @_;
  return $self->_decrypt($data);
}

sub sign_message {
  my ($self, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_sign($data_hash);
}

sub verify_message {
  my ($self, $sig, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_verify($sig, $data_hash);
}

sub sign_hash {
  my ($self, $data_hash) = @_;
  return $self->_sign($data_hash);
}

sub verify_hash {
  my ($self, $sig, $data_hash) = @_;
  return $self->_verify($sig, $data_hash);
}

### FUNCTIONS

sub ecc_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub ecc_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->decrypt(@_);
}

sub ecc_sign_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub ecc_verify_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
}

sub ecc_sign_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub ecc_verify_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub ecc_shared_secret {
  my ($privkey, $pubkey) = @_;
  $privkey = __PACKAGE__->new($privkey) unless ref $privkey;
  $pubkey  = __PACKAGE__->new($pubkey)  unless ref $pubkey;
  carp "FATAL: invalid 'privkey' param" unless ref($privkey) eq __PACKAGE__ && $privkey->is_private;
  carp "FATAL: invalid 'pubkey' param"  unless ref($pubkey)  eq __PACKAGE__;
  return $privkey->shared_secret($pubkey);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::ECC - Public key cryptography based on EC

=head1 SYNOPSIS

 ### OO interface

 #Encryption: Alice
 my $pub = Crypt::PK::ECC->new('Bob_pub_ecc1.der');
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::ECC->new('Bob_priv_ecc1.der');
 my $pt = $priv->decrypt($ct);

 #Signature: Alice
 my $priv = Crypt::PK::ECC->new('Alice_priv_ecc1.der');
 my $sig = $priv->sign_message($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::ECC->new('Alice_pub_ecc1.der');
 $pub->verify_message($sig, $message) or die "ERROR";

 #Shared secret
 my $priv = Crypt::PK::ECC->new('Alice_priv_ecc1.der');
 my $pub = Crypt::PK::ECC->new('Bob_pub_ecc1.der');
 my $shared_secret = $priv->shared_secret($pub);

 #Key generation
 my $pk = Crypt::PK::ECC->new();
 $pk->generate_key(24);
 my $private_der = $pk->export_key_der('private');
 my $public_der = $pk->export_key_der('public');
 my $public_ansi_x963 = $pk->export_key_x963();

 ### Functional interface

 #Encryption: Alice
 my $ct = ecc_encrypt('Bob_pub_ecc1.der', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = ecc_decrypt('Bob_priv_ecc1.der', $ct);

 #Signature: Alice
 my $sig = ecc_sign_message('Alice_priv_ecc1.der', $message);
 #Signature: Bob (received $message + $sig)
 ecc_verify_message('Alice_pub_ecc1.der', $sig, $message) or die "ERROR";

 #Shared secret
 my $shared_secret = ecc_shared_secret('Alice_priv_ecc1.der', 'Bob_pub_ecc1.der');

=head1 DESCRIPTION

The module provides a set of core ECC functions as well that are designed to be the Elliptic Curve analogy of
all of the Diffie-Hellman routines (ECDH).

=head1 FUNCTIONS

=head2 ecc_encrypt

Elliptic Curve Diffie-Hellman (ECDH) encryption as implemented by libtomcrypt. See method L</encrypt> below.

 my $ct = ecc_encrypt($pub_key_filename, $message);
 #or
 my $ct = ecc_encrypt(\$buffer_containing_pub_key, $message);
 #or
 my $ct = ecc_encrypt($pub_key_filename, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

ECCDH Encryption is performed by producing a random key, hashing it, and XOR'ing the digest against the plaintext.

=head2 ecc_decrypt

Elliptic Curve Diffie-Hellman (ECDH) decryption as implemented by libtomcrypt. See method L</decrypt> below.

 my $pt = ecc_decrypt($priv_key_filename, $ciphertext);
 #or
 my $pt = ecc_decrypt(\$buffer_containing_priv_key, $ciphertext);

=head2 ecc_sign_message

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature generation. See method L</sign_message> below.

 my $sig = ecc_sign_message($priv_key_filename, $message);
 #or
 my $sig = ecc_sign_message(\$buffer_containing_priv_key, $message);
 #or
 my $sig = ecc_sign_message($priv_key, $message, $hash_name);

=head2 ecc_verify_message

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature verification. See method L</verify_message> below.

 ecc_verify_message($pub_key_filename, $signature, $message) or die "ERROR";
 #or
 ecc_verify_message(\$buffer_containing_pub_key, $signature, $message) or die "ERROR";
 #or
 ecc_verify_message($pub_key, $signature, $message, $hash_name) or die "ERROR";

=head2 ecc_sign_hash

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature generation. See method L</sign_hash> below.

 my $sig = ecc_sign_hash($priv_key_filename, $message_hash);
 #or
 my $sig = ecc_sign_hash(\$buffer_containing_priv_key, $message_hash);

=head2 ecc_verify_hash

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature verification. See method L</verify_hash> below.

 ecc_verify_hash($pub_key_filename, $signature, $message_hash) or die "ERROR";
 #or
 ecc_verify_hash(\$buffer_containing_pub_key, $signature, $message_hash) or die "ERROR";

=head2 ecc_shared_secret

Elliptic curve Diffie-Hellman (ECDH) - construct a Diffie-Hellman shared secret with a private and public ECC key. See method L</shared_secret> below.

 #on Alice side
 my $shared_secret = ecc_shared_secret('Alice_priv_ecc1.der', 'Bob_pub_ecc1.der');

 #on Bob side
 my $shared_secret = ecc_shared_secret('Bob_priv_ecc1.der', 'Alice_pub_ecc1.der');

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::ECC->new();
  #or
  my $pk = Crypt::PK::ECC->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::ECC->new(\$buffer_containing_priv_or_pub_key);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($keysize);
 # $keysize .. key size in bytes: 14, 16, 20, 24, 28, 32, 48 or 65
 #   14 => use curve SECP112R1
 #   16 => use curve SECP128R1
 #   20 => use curve SECP160R1
 #   24 => use curve P-192 recommended by FIPS 186-3
 #   28 => use curve P-224 recommended by FIPS 186-3
 #   32 => use curve P-256 recommended by FIPS 186-3
 #   48 => use curve P-384 recommended by FIPS 186-3
 #   65 => use curve P-521 recommended by FIPS 186-3

See L<http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf> and L<http://www.secg.org/collateral/sec2_final.pdf>

=head2 import_key

Loads private or public key in DER format (exported by L</export_key_der>).

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 import_key_x963

ANSI X9.63 Import (public key only) - can load data exported by L</export_key_x963>.

 $pk->import_key(\$buffer_containing_pub_key_ansi_x963);

=head2 export_key_der

 my $private_der = $pk->export_key_der('private');
 #or
 my $public_der = $pk->export_key_der('public');

=head2 export_key_x963

ANSI X9.63 Export (public key only)

 my $public_ansi_x963 = $pk->export_key_x963();

=head2 encrypt

 my $pk = Crypt::PK::ECC->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 decrypt

 my $pk = Crypt::PK::ECC->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);

=head2 sign_message

 my $pk = Crypt::PK::ECC->new($priv_key_filename);
 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

 my $pk = Crypt::PK::ECC->new($pub_key_filename);
 my $valid = $pub->verify_message($signature, $message)
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 sign_hash

 my $pk = Crypt::PK::ECC->new($priv_key_filename);
 my $signature = $priv->sign_hash($message_hash);

=head2 verify_hash

 my $pk = Crypt::PK::ECC->new($pub_key_filename);
 my $valid = $pub->verify_hash($signature, $message_hash);

=head2 shared_secret

  # Alice having her priv key $pk and Bob's public key $pkb
  my $pk  = Crypt::PK::ECC->new($priv_key_filename);
  my $pkb = Crypt::PK::ECC->new($pub_key_filename);
  my $shared_secret = $pk->shared_secret($pkb);

  # Bob having his priv key $pk and Alice's public key $pka
  my $pk = Crypt::PK::ECC->new($priv_key_filename);
  my $pka = Crypt::PK::ECC->new($pub_key_filename);
  my $shared_secret = $pk->shared_secret($pka);  # same value as computed by Alice

=head2 is_private

 my $rv = $pk->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 size

 my $size = $pk->size;
 # returns key size in bytes or undef if no key loaded

=head2 key2hash

 my $hash = $pk->key2hash;

 # returns hash like this (or undef if no key loaded):
 {
   type => 1,  # integer: 1 .. private, 0 .. public
   size => 32, # integer: key (curve) size in bytes
   #curve parameters
   curve_name  => "ECC-256",
   curve_size  => 32,
   curve_B     => "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
   curve_Gx    => "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
   curve_Gy    => "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
   curve_order => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
   curve_prime => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
   #private key
   k => "A7F43ACD4A05D69AE4597E6E723EB5F1E9B9B7EAA51B6DE83CF36F9687B57DEE",
   #public key point coordinates
   pub_x => "AB53ED5D16CE550BAAF16BA4F161332AAD56D63790629C27871ED515D4FC229C",
   pub_y => "78FC34C6A320E22672A96EBB6DA48387A40541A3D7E5CFAE0D58A513E38C8888",
   pub_z => "1",
 }

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/Elliptic_curve_cryptography|https://en.wikipedia.org/wiki/Elliptic_curve_cryptography>

=item * L<https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman|https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman>

=item * L<https://en.wikipedia.org/wiki/ECDSA|https://en.wikipedia.org/wiki/ECDSA>

=back
