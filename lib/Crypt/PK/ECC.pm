package Crypt::PK::ECC;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( ecc_encrypt ecc_decrypt ecc_sign ecc_verify ecc_shared_secret )] );
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

sub import_key {
  my ($self, $data) = @_;
  croak "FATAL: undefined key" unless $data;
  $data = _slurp_file($data) if -f $data;
  ### no PEM support
  #if ($data =~ /-----BEGIN (EC PRIVATE|EC PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
  #  $data = decode_base64($2);
  #}
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

sub ecc_sign {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;  
  return $key->sign(@_);
}

sub ecc_verify {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__; 
  return $key->verify(@_);
}

sub ecc_shared_secret {
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
 my $sig = $priv->sign($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::ECC->new('Alice_pub_ecc1.der');
 $pub->verify($sig, $message) or die "ERROR";
 
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
 my $sig = ecc_sign('Alice_priv_ecc1.der', $message);
 #Signature: Bob (received $message + $sig)
 ecc_verify('Alice_pub_ecc1.der', $sig, $message) or die "ERROR";
 
 #Shared secret
 my $shared_secret = ecc_shared_secret('Alice_priv_ecc1.der', 'Bob_pub_ecc1.der');

=head1 FUNCTIONS

=head2 ecc_encrypt

=head2 ecc_decrypt

=head2 ecc_sign

=head2 ecc_verify

=head2 ecc_shared_secret

=head1 METHODS

=head2 new

=head2 generate_key

 $pk->generate_key($keysize);
 # $keysize .. key size in bytes: 12, 16, 20, 24, 28, 32, 48 or 65

=head2 import_key

=head2 import_key_x963

=head2 export_key_der

=head2 export_key_x963

=head2 encrypt

=head2 decrypt

=head2 sign

=head2 verify

=head2 shared_secret

=head2 is_private

=head2 size

