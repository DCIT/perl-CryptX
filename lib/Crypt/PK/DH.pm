package Crypt::PK::DH;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( dh_encrypt dh_decrypt dh_sign dh_verify dh_shared_secret )] );
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

sub dh_sign {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->sign(@_);
}

sub dh_verify {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__; 
  return $key->verify(@_);
}

sub dh_shared_secret {
  my ($privkey, $pubkey) = @_;
  $privkey = __PACKAGE__->new($privkey) unless ref $privkey;
  $pubkey  = __PACKAGE__->new($pubkey)  unless ref $pubkey;
  carp "FATAL: invalid 'privkey' param" unless ref($privkey) eq __PACKAGE__ && $privkey->is_private;
  carp "FATAL: invalid 'pubkey' param"  unless ref($pubkey)  eq __PACKAGE__;
  return $privkey->shared_secret($pubkey);
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

Crypt::PK::DH - Public key cryptography based on Diffie-Hellman

=head1 SYNOPSIS

 ### OO interface
 
 #Encryption: Alice
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.der'); 
 my $ct = $pub->encrypt("secret message");
 #
 #Encryption: Bob (received ciphertext $ct)
 my $priv = Crypt::PK::DH->new('Bob_priv_dh1.der');
 my $pt = $priv->decrypt($ct);
  
 #Signature: Alice
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.der');
 my $sig = $priv->sign($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::DH->new('Alice_pub_dh1.der');
 $pub->verify($sig, $message) or die "ERROR";
 
 #Shared secret
 my $priv = Crypt::PK::DH->new('Alice_priv_dh1.der');
 my $pub = Crypt::PK::DH->new('Bob_pub_dh1.der'); 
 my $shared_secret = $priv->shared_secret($pub);

 #Key generation
 my $pk = Crypt::PK::DH->new();
 $pk->generate_key(128);
 my $private = $pk->export_key('private');
 my $public = $pk->export_key('public');
 
 ### Functional interface
 
 #Encryption: Alice
 my $ct = dh_encrypt('Bob_pub_dh1.der', "secret message");
 #Encryption: Bob (received ciphertext $ct)
 my $pt = dh_decrypt('Bob_priv_dh1.der', $ct);
  
 #Signature: Alice
 my $sig = dh_sign('Alice_priv_dh1.der', $message);
 #Signature: Bob (received $message + $sig)
 dh_verify('Alice_pub_dh1.der', $sig, $message) or die "ERROR";
 
 #Shared secret
 my $shared_secret = dh_shared_secret('Alice_priv_dh1.der', 'Bob_pub_dh1.der');

=head1 FUNCTIONS

=head2 dh_encrypt

=head2 dh_decrypt

=head2 dh_sign

=head2 dh_verify

=head2 dh_shared_secret

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
 # $keysize:
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

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 export_key

 my $private = $pk->export_key('private');
 #or
 my $public = $pk->export_key('public');

=head2 encrypt

=head2 decrypt

=head2 sign

=head2 verify

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

=head2 size

