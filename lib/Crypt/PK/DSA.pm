package Crypt::PK::DSA;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( dsa_encrypt dsa_decrypt dsa_sign dsa_verify )] );
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
  
  return "-----BEGIN DSA PRIVATE KEY-----\n" .
         encode_base64($key) .
         "-----END DSA PRIVATE KEY-----\n " if $type eq 'private';
  
  return "-----BEGIN PUBLIC KEY-----\n" .
         encode_base64($key) .
         "-----END PUBLIC KEY-----\n " if $type eq 'public';
}

sub generate_key {
  my $self = shift;
  $self->_generate_key(@_);
  return $self;
}

sub import_key {
  my ($self, $key) = @_;
  croak "FATAL: undefined key" unless $key;
  my $data;
  if (ref($key) eq 'SCALAR') {
    $data = $$key;
  }
  elsif (-f $key) {
    $data = _slurp_file($key);
  }
  else {
    croak "FATAL: non-existing file '$key'";
  }
  if ($data && $data =~ /-----BEGIN (DSA PRIVATE|DSA PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
    $data = decode_base64($2);
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

sub sign {
  my ($self, $data) = @_;  
  return $self->_sign($data);
}

sub verify {
  my ($self, $sig, $data) = @_;  
  return $self->_verify($sig, $data);
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

sub dsa_sign {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->sign(@_);
}

sub dsa_verify {
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
 my $sig = $priv->sign($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::DSA->new('Alice_pub_dsa1.der');
 $pub->verify($sig, $message) or die "ERROR";
 
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
 my $sig = dsa_sign('Alice_priv_dsa1.der', $message);
 #Signature: Bob (received $message + $sig)
 dsa_verify('Alice_pub_dsa1.der', $sig, $message) or die "ERROR";

=head1 FUNCTIONS

=head2 dsa_encrypt

DSA based encryption.

Encryption works similar to the L<Crypt::PK::ECC> encryption whereas shared key is computed, and 
the hash of the shared key XOR'ed against the plaintext forms the ciphertext.

=head2 dsa_decrypt

DSA based decryption.

=head2 dsa_sign

Generate DSA signature.

=head2 dsa_verify

Verify DSA signature.

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::DSA->new();
  #or
  my $pk = Crypt::PK::DSA->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::DSA->new(\$buffer_containing_priv_or_pub_key);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($group_size, $modulus_size);
 # $group_size  ... 15 < $group_size < 1024
 # $modulus_size .. ($modulus_size - $group_size) < 512
 
 # Bits of Security  $group_size  $modulus_size
 # 80                20           128
 # 120               30           256
 # 140               35           384
 # 160               40           512

=head2 import_key

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 export_key_der

 my $private_der = $pk->export_key_der('private');
 #or
 my $public_der = $pk->export_key_der('public');

=head2 export_key_pem

 my $private_pem = $pk->export_key_pem('private');
 #or
 my $public_pem = $pk->export_key_pem('public');

=head2 encrypt

=head2 decrypt

=head2 sign

=head2 verify

=head2 is_private

=head2 size
