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
  ### no PEM support
  #if ($data && $data =~ /-----BEGIN (EC PRIVATE|EC PUBLIC|PRIVATE|PUBLIC) KEY-----(.*?)-----END/sg) {
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

=head1 DESCRIPTION

The module provides a set of core ECC functions as well that are designed to be the Elliptic Curve analogy of 
all of the Diffie-Hellman routines (ECDH).

=head1 FUNCTIONS

=head2 ecc_encrypt

Elliptic Curve Diffie-Hellman (ECDH) encryption.

ECCDH Encryption is performed by producing a random key, hashing it, and XOR'ing the digest against the plaintext.

=head2 ecc_decrypt

Elliptic Curve Diffie-Hellman (ECDH) decryption

=head2 ecc_sign

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature generation

=head2 ecc_verify

Elliptic Curve Digital Signature Algorithm (ECDSA) - signature verification

=head2 ecc_shared_secret

Elliptic curve Diffie-Hellman (ECDH) - construct a Diffie-Hellman shared secret with a private and public ECC key.

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

  $pk->import_key($filename);
  #or
  $pk->import_key(\$buffer_containing_key);

=head2 import_key_x963

ANSI X9.63 Import (public key only) - can load data exported by C<export_key_x963>

 $pk->import_key(\$buffer_containing_pub_key_ansi_x963);

=head2 export_key_der

 my $private_der = $pk->export_key_der('private');
 #or
 my $public_der = $pk->export_key_der('public');

=head2 export_key_x963

ANSI X9.63 Export (public key only)

 my $public_ansi_x963 = $pk->export_key_x963();

=head2 encrypt

=head2 decrypt

=head2 sign

=head2 verify

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

=head2 size
