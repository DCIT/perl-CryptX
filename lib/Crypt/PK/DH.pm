package Crypt::PK::DH;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( dh_encrypt dh_decrypt dh_sign_message dh_verify_message dh_sign_hash dh_verify_hash dh_shared_secret )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::PK;
use Crypt::Digest 'digest_data';
use Carp;

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

sub dh_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub dh_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->decrypt(@_);
}

sub dh_sign_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub dh_verify_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
}

sub dh_sign_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub dh_verify_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub dh_shared_secret {
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

Crypt::PK::DH - Public key cryptography based on Diffie-Hellman

=head1 SYNOPSIS

 ### OO interface

 #Encryption: Alice
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.key');
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::DH->new('Bob_priv_dh1.key');
 my $pt = $priv->decrypt($ct);

 #Signature: Alice
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.key');
 my $sig = $priv->sign_message($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::DH->new('Alice_pub_dh1.key');
 $pub->verify_message($sig, $message) or die "ERROR";

 #Shared secret
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.key');
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.key');
 my $shared_secret = $priv->shared_secret($pub);

 #Key generation
 my $pk = Crypt::PK::DH->new();
 $pk->generate_key(128);
 my $private = $pk->export_key('private');
 my $public = $pk->export_key('public');

 ### Functional interface

 #Encryption: Alice
 my $ct = dh_encrypt('Bob_pub_dh1.key', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = dh_decrypt('Bob_priv_dh1.key', $ct);

 #Signature: Alice
 my $sig = dh_sign_message('Alice_priv_dh1.key', $message);
 #Signature: Bob (received $message + $sig)
 dh_verify_message('Alice_pub_dh1.key', $sig, $message) or die "ERROR";

 #Shared secret
 my $shared_secret = dh_shared_secret('Alice_priv_dh1.key', 'Bob_pub_dh1.key');

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::DH->new();
  #or
  my $pk = Crypt::PK::DH->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::DH->new(\$buffer_containing_priv_or_pub_key);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($keysize);
 ### $keysize (in bytes) corresponds to DH params (p, g) predefined by libtomcrypt
 # 96   =>  DH-768
 # 128  =>  DH-1024
 # 160  =>  DH-1280
 # 192  =>  DH-1536
 # 224  =>  DH-1792
 # 256  =>  DH-2048
 # 320  =>  DH-2560
 # 384  =>  DH-3072
 # 512  =>  DH-4096

=head2 import_key

Loads private or public key (exported by L</export_key>).

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 export_key

 my $private = $pk->export_key('private');
 #or
 my $public = $pk->export_key('public');

=head2 encrypt

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 decrypt

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);

=head2 sign_message

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $valid = $pub->verify_message($signature, $message)
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 sign_hash

 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $signature = $priv->sign_hash($message_hash);

=head2 verify_hash

 my $pk = Crypt::PK::DH->new($pub_key_filename);
 my $valid = $pub->verify_hash($signature, $message_hash);

=head2 shared_secret

 # Alice having her priv key $pk and Bob's public key $pkb
 my $pk  = Crypt::PK::DH->new($priv_key_filename);
 my $pkb = Crypt::PK::DH->new($pub_key_filename);
 my $shared_secret = $pk->shared_secret($pkb);

 # Bob having his priv key $pk and Alice's public key $pka
 my $pk = Crypt::PK::DH->new($priv_key_filename);
 my $pka = Crypt::PK::DH->new($pub_key_filename);
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
   type => 0,   # integer: 1 .. private, 0 .. public
   size => 256, # integer: key size in bytes
   name => "DH-2048", # internal libtomcrypt name
   x => "FBC1062F73B9A17BB8473A2F5A074911FA7F20D28FB...", #private key
   y => "AB9AAA40774D3CD476B52F82E7EE2D8A8D40CD88BF4...", #public key
}

=head1 FUNCTIONS

=head2 dh_encrypt

DH based encryption as implemented by libtomcrypt. See method L</encrypt> below.

 my $ct = dh_encrypt($pub_key_filename, $message);
 #or
 my $ct = dh_encrypt(\$buffer_containing_pub_key, $message);
 #or
 my $ct = dh_encrypt($pub_key_filename, $message, $hash_name);

 #NOTE: $hash_name can be 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

Encryption works similar to the L<Crypt::PK::ECC> encryption whereas shared DH key is computed, and
the hash of the shared key XOR'ed against the plaintext forms the ciphertext.

=head2 dh_decrypt

DH based decryption as implemented by libtomcrypt. See method L</decrypt> below.

 my $pt = dh_decrypt($priv_key_filename, $ciphertext);
 #or
 my $pt = dh_decrypt(\$buffer_containing_priv_key, $ciphertext);

=head2 dh_sign_message

Generate DH signature as implemented by libtomcrypt. See method L</sign_message> below.

 my $sig = dh_sign_message($priv_key_filename, $message);
 #or
 my $sig = dh_sign_message(\$buffer_containing_priv_key, $message);
 #or
 my $sig = dh_sign_message($priv_key, $message, $hash_name);

=head2 dh_verify_message

Verify DH signature as implemented by libtomcrypt. See method L</verify_message> below.

 dh_verify_message($pub_key_filename, $signature, $message) or die "ERROR";
 #or
 dh_verify_message(\$buffer_containing_pub_key, $signature, $message) or die "ERROR";
 #or
 dh_verify_message($pub_key, $signature, $message, $hash_name) or die "ERROR";

=head2 dh_sign_hash

Generate DH signature as implemented by libtomcrypt. See method L</sign_hash> below.

 my $sig = dh_sign_hash($priv_key_filename, $message_hash);
 #or
 my $sig = dh_sign_hash(\$buffer_containing_priv_key, $message_hash);

=head2 dh_verify_hash

Verify DH signature as implemented by libtomcrypt. See method L</verify_hash> below.

 dh_verify_hash($pub_key_filename, $signature, $message_hash) or die "ERROR";
 #or
 dh_verify_hash(\$buffer_containing_pub_key, $signature, $message_hash) or die "ERROR";

=head2 dh_shared_secret

DH based shared secret generation. See method L</shared_secret> below.

 #on Alice side
 my $shared_secret = dh_shared_secret('Alice_priv_dh1.key', 'Bob_pub_dh1.key');

 #on Bob side
 my $shared_secret = dh_shared_secret('Bob_priv_dh1.key', 'Alice_pub_dh1.key');

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange|https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange>

=back
