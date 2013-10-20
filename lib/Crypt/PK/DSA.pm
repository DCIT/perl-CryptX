package Crypt::PK::DSA;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( dsa_encrypt dsa_decrypt dsa_sign_message dsa_verify_message dsa_sign_hash dsa_verify_hash )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::PK;
use Crypt::Digest 'digest_data';
use Carp;
use MIME::Base64 qw(encode_base64 decode_base64);

sub new {
  my ($class, $f, $p) = @_;
  my $self = _new();
  $self->import_key($f, $p) if $f;
  return  $self;
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  my $key = $self->export_key_der($type||'');
  return undef unless $key;
  return Crypt::PK::_asn1_to_pem($key, "DSA PRIVATE KEY", $password, $cipher) if $type eq 'private';  
  return Crypt::PK::_asn1_to_pem($key, "DSA PUBLIC KEY") if $type eq 'public';
}

sub generate_key {
  my $self = shift;
  $self->_generate_key(@_);
  return $self;
}

sub import_key {
  my ($self, $key, $password) = @_;
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
  if ($data && $data =~ /-----BEGIN (DSA PRIVATE|DSA PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
    $data = Crypt::PK::_pem_to_asn1($data, $password);
  }
  croak "FATAL: invalid key format" unless $data;
  $self->_import($data);
  return $self;
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

sub _truncate {
  my ($self, $hash) = @_;
  ### section 4.6 of FIPS 186-4
  # let N be the bit length of q
  # z = the leftmost min(N, outlen) bits of Hash(M).
  my $q = $self->size_q; # = size in bytes
  return $hash if $q >= length($hash);
  return substr($hash, 0, $q);
}

sub sign_message {
  my ($self, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_sign($self->_truncate($data_hash));
}

sub verify_message {
  my ($self, $sig, $data, $hash_name) = @_;
  $hash_name ||= 'SHA1';
  my $data_hash = digest_data($hash_name, $data);
  return $self->_verify($sig, $self->_truncate($data_hash));
}

sub sign_hash {
  my ($self, $data_hash) = @_;
  return $self->_sign($self->_truncate($data_hash));
}

sub verify_hash {
  my ($self, $sig, $data_hash) = @_;
  return $self->_verify($sig, $self->_truncate($data_hash));
}

### FUNCTIONS

sub dsa_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub dsa_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->decrypt(@_);
}

sub dsa_sign_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub dsa_verify_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
}

sub dsa_sign_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub dsa_verify_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::DSA - Public key cryptography based on DSA

=head1 SYNOPSIS

 ### OO interface

 #Encryption: Alice
 my $pub = Crypt::PK::DSA->new('Bob_pub_dsa1.der');
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::DSA->new('Bob_priv_dsa1.der');
 my $pt = $priv->decrypt($ct);

 #Signature: Alice
 my $priv = Crypt::PK::DSA->new('Alice_priv_dsa1.der');
 my $sig = $priv->sign_message($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::DSA->new('Alice_pub_dsa1.der');
 $pub->verify_message($sig, $message) or die "ERROR";

 #Key generation
 my $pk = Crypt::PK::DSA->new();
 $pk->generate_key(30, 256);
 my $private_der = $pk->export_key_der('private');
 my $public_der = $pk->export_key_der('public');
 my $private_pem = $pk->export_key_pem('private');
 my $public_pem = $pk->export_key_pem('public');

 ### Functional interface

 #Encryption: Alice
 my $ct = dsa_encrypt('Bob_pub_dsa1.der', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = dsa_decrypt('Bob_priv_dsa1.der', $ct);

 #Signature: Alice
 my $sig = dsa_sign_message('Alice_priv_dsa1.der', $message);
 #Signature: Bob (received $message + $sig)
 dsa_verify_message('Alice_pub_dsa1.der', $sig, $message) or die "ERROR";

=head1 FUNCTIONS

=head2 dsa_encrypt

DSA based encryption as implemented by libtomcrypt. See method L</encrypt> below.

 my $ct = dsa_encrypt($pub_key_filename, $message);
 #or
 my $ct = dsa_encrypt(\$buffer_containing_pub_key, $message);
 #or
 my $ct = dsa_encrypt($pub_key_filename, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

Encryption works similar to the L<Crypt::PK::ECC> encryption whereas shared DSA key is computed, and
the hash of the shared key XOR'ed against the plaintext forms the ciphertext.

=head2 dsa_decrypt

DSA based decryption as implemented by libtomcrypt. See method L</decrypt> below.

 my $pt = dsa_decrypt($priv_key_filename, $ciphertext);
 #or
 my $pt = dsa_decrypt(\$buffer_containing_priv_key, $ciphertext);

=head2 dsa_sign_message

Generate DSA signature. See method L</sign_message> below.

 my $sig = dsa_sign_message($priv_key_filename, $message);
 #or
 my $sig = dsa_sign_message(\$buffer_containing_priv_key, $message);
 #or
 my $sig = dsa_sign_message($priv_key, $message, $hash_name);

=head2 dsa_verify_message

Verify DSA signature. See method L</verify_message> below.

 dsa_verify_message($pub_key_filename, $signature, $message) or die "ERROR";
 #or
 dsa_verify_message(\$buffer_containing_pub_key, $signature, $message) or die "ERROR";
 #or
 dsa_verify_message($pub_key, $signature, $message, $hash_name) or die "ERROR";

=head2 dsa_sign_hash

Generate DSA signature. See method L</sign_hash> below.

 my $sig = dsa_sign_hash($priv_key_filename, $message_hash);
 #or
 my $sig = dsa_sign_hash(\$buffer_containing_priv_key, $message_hash);

=head2 dsa_verify_hash

Verify DSA signature. See method L</verify_hash> below.

 dsa_verify_hash($pub_key_filename, $signature, $message_hash) or die "ERROR";
 #or
 dsa_verify_hash(\$buffer_containing_pub_key, $signature, $message_hash) or die "ERROR";

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::DSA->new();
  #or
  my $pk = Crypt::PK::DSA->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::DSA->new(\$buffer_containing_priv_or_pub_key);

Support for password protected PEM keys

  my $pk = Crypt::PK::DSA->new($priv_pem_key_filename, $password);
  #or
  my $pk = Crypt::PK::DSA->new(\$buffer_containing_priv_pem_key, $password);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($group_size, $modulus_size);
 # $group_size  ... in bytes .. 15 < $group_size < 1024
 # $modulus_size .. in bytes .. ($modulus_size - $group_size) < 512

 ### Bits of Security according to libtomcrypt documentation
 # 80 bits   => generate_key(20, 128)
 # 120 bits  => generate_key(30, 256)
 # 140 bits  => generate_key(35, 384)
 # 160 bits  => generate_key(40, 512)

 ### Sizes according section 4.2 of FIPS 186-4
 # (L and N are the bit lengths of p and q respectively)
 # L = 1024, N = 160 => generate_key(20, 128)
 # L = 2048, N = 224 => generate_key(28, 256)
 # L = 2048, N = 256 => generate_key(32, 256)
 # L = 3072, N = 256 => generate_key(32, 384)

=head2 import_key

Loads private or public key in DER or PEM format.

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

Support for password protected PEM keys

  $pk->import_key($pem_filename, $password);
  #or
  $pk->import_key(\$buffer_containing_pem_key, $password);

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

=head2 encrypt

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 decrypt

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);

=head2 sign_message

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $valid = $pub->verify_message($signature, $message)
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 sign_hash

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $signature = $priv->sign_hash($message_hash);

=head2 verify_hash

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $valid = $pub->verify_hash($signature, $message_hash);

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
   type => 1,   # integer: 1 .. private, 0 .. public
   size => 256, # integer: key size in bytes
   # all the rest are hex strings
   p => "AAF839A764E04D80824B79FA1F0496C093...", #prime modulus
   q => "D05C4CB45F29D353442F1FEC43A6BE2BE8...", #prime divisor
   g => "847E8896D12C9BF18FE283AE7AD58ED7F3...", #generator of a subgroup of order q in GF(p)
   x => "6C801901AC74E2DC714D75A9F6969483CF...", #private key, random  0 < x < q
   y => "8F7604D77FA62C7539562458A63C7611B7...", #public key, where y = g^x mod p
 }

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/Digital_Signature_Algorithm|https://en.wikipedia.org/wiki/Digital_Signature_Algorithm>

=back
