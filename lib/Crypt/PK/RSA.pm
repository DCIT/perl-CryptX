package Crypt::PK::RSA;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( rsa_encrypt rsa_decrypt rsa_sign rsa_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use Crypt::Digest;
use Carp;
use MIME::Base64 qw(encode_base64 decode_base64);

sub new { 
  my ($class, $f) = @_;
  my $self = _new();
  $self->import_key($f) if $f;
  return  $self;
}

sub export_key_pem {
  my ($self, $type) = @_;
  my $key = $self->export_key_der($type||'');
  return undef unless $key;
  
  # PKCS#1 RSAPrivateKey** (PEM header: BEGIN RSA PRIVATE KEY)
  # PKCS#8 PrivateKeyInfo* (PEM header: BEGIN PRIVATE KEY)
  # PKCS#8 EncryptedPrivateKeyInfo** (PEM header: BEGIN ENCRYPTED PRIVATE KEY)
  return "-----BEGIN RSA PRIVATE KEY-----\n" .
         encode_base64($key) .
         "-----END RSA PRIVATE KEY-----\n " if $type eq 'private';
  
  # PKCS#1 RSAPublicKey* (PEM header: BEGIN RSA PUBLIC KEY)
  # X.509 SubjectPublicKeyInfo** (PEM header: BEGIN PUBLIC KEY)
  return "-----BEGIN PUBLIC KEY-----\n" .
         encode_base64($key) .
         "-----END PUBLIC KEY-----\n " if $type eq 'public';
}

sub import_key {
  my ($self, $data) = @_;
  croak "FATAL: undefined key" unless $data;
  $data = _slurp_file($data) if -f $data;
  if ($data =~ /-----BEGIN (RSA PRIVATE|RSA PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
    $data = decode_base64($2);
  }
  croak "FATAL: invalid key format" unless $data;
  $self->_import($data);
  return $self;
}

sub encrypt {
  my ($self, $data, $padding, $hash_name, $lparam) = @_;
  $lparam ||= '';
  $padding ||= 'oaep';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  
  return $self->_encrypt($data, $padding, $hash_name, $lparam);
}

sub decrypt {
  my ($self, $data, $padding, $hash_name, $lparam) = @_;
  $lparam ||= '';
  $padding ||= 'oaep';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  
  return $self->_decrypt($data, $padding, $hash_name, $lparam);
}

sub sign {
  my ($self, $data, $padding, $hash_name, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  
  return $self->_sign($data, $padding, $hash_name, $saltlen);
}

sub verify {
  my ($self, $sig, $data, $padding, $hash_name, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');
  
  return $self->_verify($sig, $data, $padding, $hash_name, $saltlen);
}

### FUNCTIONS

sub rsa_encrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub rsa_decrypt {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->decrypt(@_);
}

sub rsa_sign {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->sign(@_);
}

sub rsa_verify {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__; 
  return $key->verify(@_);
}

sub _slurp_file {
  my $f = shift;
  local $/ = undef;
  open FILE, "<", $f or croak "FATAL: couldn't open file: $!";
  binmode FILE;
  my $string = <FILE>;
  close FILE;
  return $string;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::RSA - Public key cryptography based on RSA

=head1 SYNOPSIS

 ### OO interface
 
 #Encryption: Alice
 my $pub = Crypt::PK::RSA->new('Bob_pub_rsa1.der'); 
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::RSA->new('Bob_priv_rsa1.der');
 my $pt = $priv->decrypt($ct);
  
 #Signature: Alice
 my $priv = Crypt::PK::RSA->new('Alice_priv_rsa1.der');
 my $sig = $priv->sign($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::RSA->new('Alice_pub_rsa1.der');
 $pub->verify($sig, $message) or die "ERROR";
 
 #Shared secret
 my $priv = Crypt::PK::RSA->new('Alice_priv_rsa1.der');
 my $pub = Crypt::PK::RSA->new('Bob_pub_rsa1.der'); 
 my $shared_secret = $priv->shared_secret($pub);

 #Key generation
 my $pk = Crypt::PK::RSA->new();
 $pk->generate_key(256, 65537);
 my $private_der = $pk->export_key_der('private');
 my $public_der = $pk->export_key_der('public');
 my $private_pem = $pk->export_key_pem('private');
 my $public_pem = $pk->export_key_pem('public');

 ### Functional interface
 
 #Encryption: Alice
 my $ct = rsa_encrypt('Bob_pub_rsa1.der', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = rsa_decrypt('Bob_priv_rsa1.der', $ct);
  
 #Signature: Alice
 my $sig = rsa_sign('Alice_priv_rsa1.der', $message);
 #Signature: Bob (received $message + $sig)
 rsa_verify('Alice_pub_rsa1.der', $sig, $message) or die "ERROR";
 
 #Shared secret
 my $shared_secret = rsa_shared_secret('Alice_priv_rsa1.der', 'Bob_pub_rsa1.der');

=head1 FUNCTIONS

=head2 rsa_encrypt

=head2 rsa_decrypt

=head2 rsa_sign

=head2 rsa_verify

=head2 rsa_shared_secret

=head1 METHODS

=head2 new

=head2 generate_key

 $pk->generate_key($size, $e);
 # $size .. (in bytes) 128 - 512
 # $e   ... 3, 17, 257 or 65537

=head2 import_key

=head2 export_key_der

=head2 export_key_pem

=head2 encrypt

 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $padding);
 #or
 my $ct = $pk->encrypt($message, 'oaep', $hash_name, $lparam);
 
 # $padding .. 'oaep', 'v1.5' or 'none'
 # $hash_name (only for oaep) .. 'SHA1' (DEFAULT), 'SHA256' ...
 # $lparam (only for oaep)

=head2 decrypt

 my $pt = $pk->decrypt($ciphertext);
 #or
 my $pt = $pk->decrypt($ciphertext, $padding);
 #or
 my $pt = $pk->decrypt($ciphertext, 'oaep', $hash_name, $lparam);

=head2 sign

 my $signature = $priv->sign($message);
 #or
 my $signature = $priv->sign($message, $padding);
 #or
 my $signature = $priv->sign($message, $padding, $hash_name);
 #or
 my $signature = $priv->sign($message, $padding, $hash_name, $saltlen);
 
 # $padding .. 'pss' or 'v1.5'
 # $hash_name (only for pss) .. 'SHA1' (DEFAULT), 'SHA256' ...
 # $saltlen (only for pss) ..... DEFAULT: 12

=head2 verify

 my $valid = $pub->verify($signature, $message)
 #or
 my $valid = $pub->verify($signature, $padding, $hash_name);
 #or
 my $valid = $pub->verify($signature, $padding, $hash_name, $saltlen);

=head2 shared_secret

=head2 is_private

=head2 size

