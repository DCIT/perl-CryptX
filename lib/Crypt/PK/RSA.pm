package Crypt::PK::RSA;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw(rsa_encrypt rsa_decrypt rsa_sign_message rsa_verify_message rsa_sign_hash rsa_verify_hash)] );
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
  return unless $key;

  # PKCS#1 RSAPrivateKey** (PEM header: BEGIN RSA PRIVATE KEY)
  # PKCS#8 PrivateKeyInfo* (PEM header: BEGIN PRIVATE KEY)
  # PKCS#8 EncryptedPrivateKeyInfo** (PEM header: BEGIN ENCRYPTED PRIVATE KEY)
  return Crypt::PK::_asn1_to_pem($key, "RSA PRIVATE KEY", $password, $cipher) if $type eq 'private';

  # PKCS#1 RSAPublicKey* (PEM header: BEGIN RSA PUBLIC KEY)
  return Crypt::PK::_asn1_to_pem($key, "RSA PUBLIC KEY") if $type eq 'public';
  # X.509 SubjectPublicKeyInfo** (PEM header: BEGIN PUBLIC KEY)
  return Crypt::PK::_asn1_to_pem($key, "PUBLIC KEY") if $type eq 'public_x509';  
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
  if ($data && $data =~ /-----BEGIN (RSA PRIVATE|RSA PUBLIC|PRIVATE|PUBLIC|ENCRYPTED PRIVATE) KEY-----(.*?)-----END/sg) {
    $data = Crypt::PK::_pem_to_asn1($data, $password);
  }
  croak "FATAL: invalid key format" unless $data;
  return $self->_import($data);
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

sub sign_hash {
  my ($self, $data, $hash_name, $padding, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');

  return $self->_sign($data, $padding, $hash_name, $saltlen);
}

sub sign_message {
  my ($self, $data, $hash_name, $padding, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');

  return $self->_sign(digest_data($hash_name, $data), $padding, $hash_name, $saltlen);
}

sub verify_hash {
  my ($self, $sig, $data, $hash_name, $padding, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');

  return $self->_verify($sig, $data, $padding, $hash_name, $saltlen);
}

sub verify_message {
  my ($self, $sig, $data, $hash_name, $padding, $saltlen) = @_;
  $saltlen ||= 12;
  $padding ||= 'pss';
  $hash_name = Crypt::Digest::_trans_digest_name($hash_name||'SHA1');

  return $self->_verify($sig, digest_data($hash_name, $data), $padding, $hash_name, $saltlen);
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

sub rsa_sign_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub rsa_verify_hash {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub rsa_sign_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub rsa_verify_message {
  my $key = shift;
  $key = __PACKAGE__->new($key) unless ref $key;
  carp "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
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
 my $sig = $priv->sign_message($message);
 #
 #Signature: Bob (received $message + $sig)
 my $pub = Crypt::PK::RSA->new('Alice_pub_rsa1.der');
 $pub->verify_message($sig, $message) or die "ERROR";

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
 my $sig = rsa_sign_message('Alice_priv_rsa1.der', $message);
 #Signature: Bob (received $message + $sig)
 rsa_verify_message('Alice_pub_rsa1.der', $sig, $message) or die "ERROR";

=head1 DESCRIPTION

The module provides a full featured RSA implementation.

=head1 METHODS

=head2 new

  my $pk = Crypt::PK::RSA->new();
  #or
  my $pk = Crypt::PK::RSA->new($priv_or_pub_key_filename);
  #or
  my $pk = Crypt::PK::RSA->new(\$buffer_containing_priv_or_pub_key);

Support for password protected PEM keys

  my $pk = Crypt::PK::RSA->new($priv_pem_key_filename, $password);
  #or
  my $pk = Crypt::PK::RSA->new(\$buffer_containing_priv_pem_key, $password);

=head2 generate_key

Uses Yarrow-based cryptographically strong random number generator seeded with
random data taken from C</dev/random> (UNIX) or C<CryptGenRandom> (Win32).

 $pk->generate_key($size, $e);
 # $size .. key size: 128-512 bytes (DEFAULT is 256)
 # $e ..... exponent: 3, 17, 257 or 65537 (DEFAULT is 65537)

=head2 import_key

Loads private or public key in DER or PEM format.

  $pk->import_key($priv_or_pub_key_filename);
  #or
  $pk->import_key(\$buffer_containing_priv_or_pub_key);

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
 #or
 my $public_pem = $pk->export_key_pem('public_x509');

With parameter C<'public'> uses header and footer lines:

  -----BEGIN RSA PUBLIC KEY------
  -----END RSA PUBLIC KEY------

With parameter C<'public_x509'> uses header and footer lines:

  -----BEGIN PUBLIC KEY------
  -----END PUBLIC KEY------

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

 my $pk = Crypt::PK::RSA->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $padding);
 #or
 my $ct = $pk->encrypt($message, 'oaep', $hash_name, $lparam);

 # $padding .................... 'oaep' (DEFAULT), 'v1.5' or 'none'
 # $hash_name (only for oaep) .. 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $lparam (only for oaep) ..... DEFAULT is empty string

=head2 decrypt

 my $pk = Crypt::PK::RSA->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);
 #or
 my $pt = $pk->decrypt($ciphertext, $padding);
 #or
 my $pt = $pk->decrypt($ciphertext, 'oaep', $hash_name, $lparam);

 # $padding .................... 'oaep' (DEFAULT), 'v1.5' or 'none'
 # $hash_name (only for oaep) .. 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $lparam (only for oaep) ..... DEFAULT is empty string

=head2 sign_message

 my $pk = Crypt::PK::RSA->new($priv_key_filename);
 my $signature = $priv->sign_message($message);
 #or
 my $signature = $priv->sign_message($message, $hash_name);
 #or
 my $signature = $priv->sign_message($message, $hash_name, $padding);
 #or
 my $signature = $priv->sign_message($message, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 verify_message

 my $pk = Crypt::PK::RSA->new($pub_key_filename);
 my $valid = $pub->verify_message($signature, $message);
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name);
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name, $padding);
 #or
 my $valid = $pub->verify_message($signature, $message, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 sign_hash

 my $pk = Crypt::PK::RSA->new($priv_key_filename);
 my $signature = $priv->sign_hash($message_hash);
 #or
 my $signature = $priv->sign_hash($message_hash, $hash_name);
 #or
 my $signature = $priv->sign_hash($message_hash, $hash_name, $padding);
 #or
 my $signature = $priv->sign_hash($message_hash, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 verify_hash

 my $pk = Crypt::PK::RSA->new($pub_key_filename);
 my $valid = $pub->verify_hash($signature, $message_hash);
 #or
 my $valid = $pub->verify_hash($signature, $message_hash, $hash_name);
 #or
 my $valid = $pub->verify_hash($signature, $message_hash, $hash_name, $padding);
 #or
 my $valid = $pub->verify_hash($signature, $message_hash, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

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
   e  => "10001", #public exponent
   d  => "9ED5C3D3F866E06957CA0E9478A273C39BBDA4EEAC5B...", #private exponent
   N  => "D0A5CCCAE03DF9C2F5C4C8C0CE840D62CDE279990DC6...", #modulus
   p  => "D3EF0028FFAB508E2773C659E428A80FB0E9211346B4...", #p factor of N
   q  => "FC07E46B163CAB6A83B8E467D169534B2077DCDEECAE...", #q factor of N
   qP => "88C6D406F833DF73C8B734548E0385261AD51F4187CF...", #1/q mod p CRT param
   dP => "486F142FEF0A1F53269AC43D2EE4D263E2841B60DA36...", #d mod (p - 1) CRT param
   dQ => "4597284B2968B72C4212DB7E8F24360B987B80514DA9...", #d mod (q - 1) CRT param
 }

=head1 FUNCTIONS

=head2 rsa_encrypt

RSA based encryption. See method L</encrypt> below.

 my $ct = rsa_encrypt($pub_key_filename, $message);
 #or
 my $ct = rsa_encrypt(\$buffer_containing_pub_key, $message);
 #or
 my $ct = rsa_encrypt($pub_key, $message, $padding);
 #or
 my $ct = rsa_encrypt($pub_key, $message, 'oaep', $hash_name, $lparam);

 # $padding .................... 'oaep' (DEFAULT), 'v1.5' or 'none'
 # $hash_name (only for oaep) .. 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $lparam (only for oaep) ..... DEFAULT is empty string

=head2 rsa_decrypt

RSA based decryption. See method L</decrypt> below.

 my $pt = rsa_decrypt($priv_key_filename, $ciphertext);
 #or
 my $pt = rsa_decrypt(\$buffer_containing_priv_key, $ciphertext);
 #or
 my $pt = rsa_decrypt($priv_key, $ciphertext, $padding);
 #or
 my $pt = rsa_decrypt($priv_key, $ciphertext, 'oaep', $hash_name, $lparam);

 # $padding .................... 'oaep' (DEFAULT), 'v1.5' or 'none'
 # $hash_name (only for oaep) .. 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $lparam (only for oaep) ..... DEFAULT is empty string

=head2 rsa_sign_message

Generate RSA signature. See method L</sign_message> below.

 my $sig = rsa_sign_message($priv_key_filename, $message);
 #or
 my $sig = rsa_sign_message(\$buffer_containing_priv_key, $message);
 #or
 my $sig = rsa_sign_message($priv_key, $message, $hash_name);
 #or
 my $sig = rsa_sign_message($priv_key, $message, $hash_name, $padding);
 #or
 my $sig = rsa_sign_message($priv_key, $message, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 rsa_verify_message

Verify RSA signature. See method L</verify_message> below.

 rsa_verify_message($pub_key_filename, $signature, $message) or die "ERROR";
 #or
 rsa_verify_message(\$buffer_containing_pub_key, $signature, $message) or die "ERROR";
 #or
 rsa_verify_message($pub_key, $signature, $message, $hash_name) or die "ERROR";
 #or
 rsa_verify_message($pub_key, $signature, $message, $hash_name, $padding) or die "ERROR";
 #or
 rsa_verify_message($pub_key, $signature, $message, $hash_name, 'pss', $saltlen) or die "ERROR";

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 rsa_sign_hash

Generate RSA signature. See method L</sign_hash> below.

 my $sig = rsa_sign_hash($priv_key_filename, $message_hash);
 #or
 my $sig = rsa_sign_hash(\$buffer_containing_priv_key, $message_hash);
 #or
 my $sig = rsa_sign_hash($priv_key, $message_hash, $hash_name);
 #or
 my $sig = rsa_sign_hash($priv_key, $message_hash, $hash_name, $padding);
 #or
 my $sig = rsa_sign_hash($priv_key, $message_hash, $hash_name, 'pss', $saltlen);

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head2 rsa_verify_hash

Verify RSA signature. See method L</verify_hash> below.

 rsa_verify_hash($pub_key_filename, $signature, $message_hash) or die "ERROR";
 #or
 rsa_verify_hash(\$buffer_containing_pub_key, $signature, $message_hash) or die "ERROR";
 #or
 rsa_verify_hash($pub_key, $signature, $message_hash, $hash_name) or die "ERROR";
 #or
 rsa_verify_hash($pub_key, $signature, $message_hash, $hash_name, $padding) or die "ERROR";
 #or
 rsa_verify_hash($pub_key, $signature, $message_hash, $hash_name, 'pss', $saltlen) or die "ERROR";

 # $hash_name ............... 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest
 # $padding ................. 'pss' (DEFAULT) or 'v1.5'
 # $saltlen (only for pss) .. DEFAULT is 12

=head1 OpenSSL interoperability

 ### let's have:
 # RSA private key in PEM format - rsakey.priv.pem
 # RSA public key in PEM format  - rsakey.pub.pem
 # data file to be signed or encrypted - input.data

=head2 Encrypt by OpenSSL, decrypt by Crypt::PK::RSA

Create encrypted file (from commandline):

 openssl rsautl -encrypt -inkey rsakey.pub.pem -pubin -out input.encrypted.rsa -in input.data

Decrypt file (Perl code):

  use Crypt::PK::RSA;
  use File::Slurp 'read_file';

  my $pkrsa = Crypt::PK::RSA->new("rsakey.priv.pem");
  my $encfile = read_file("input.encrypted.rsa", binmode=>':raw');
  my $plaintext = $pkrsa->decrypt($encfile, 'v1.5');
  print $plaintext;

=head2 Encrypt by Crypt::PK::RSA, decrypt by OpenSSL

Create encrypted file (Perl code):

  use Crypt::PK::RSA;
  use File::Slurp 'write_file';

  my $plaintext = 'secret message';
  my $pkrsa = Crypt::PK::RSA->new("rsakey.pub.pem");
  my $encrypted = $pkrsa->encrypt($plaintext, 'v1.5');
  write_file("input.encrypted.rsa", {binmode=>':raw'}, $encrypted);

Decrypt file (from commandline):

 openssl rsautl -decrypt -inkey rsakey.priv.pem -in input.encrypted.rsa

=head2 Sign by OpenSSL, verify by Crypt::PK::RSA

Create signature (from commandline):

 openssl dgst -sha1 -sign rsakey.priv.pem -out input.sha1-rsa.sig input.data

Verify signature (Perl code):

 use Crypt::PK::RSA;
 use Crypt::Digest 'digest_file';
 use File::Slurp 'read_file';

 my $pkrsa = Crypt::PK::RSA->new("rsakey.pub.pem");
 my $signature = read_file("input.sha1-rsa.sig", binmode=>':raw');
 my $valid = $pkrsa->verify_hash($signature, digest_file("SHA1", "input.data"), "SHA1", "v1.5");
 print $valid ? "SUCCESS" : "FAILURE";

=head2 Sign by Crypt::PK::RSA, verify by OpenSSL

Create signature (Perl code):

 use Crypt::PK::RSA;
 use Crypt::Digest 'digest_file';
 use File::Slurp 'write_file';

 my $pkrsa = Crypt::PK::RSA->new("rsakey.priv.pem");
 my $signature = $pkrsa->sign_hash(digest_file("SHA1", "input.data"), "SHA1", "v1.5");
 write_file("input.sha1-rsa.sig", {binmode=>':raw'}, $signature);

Verify signature (from commandline):

 openssl dgst -sha1 -verify rsakey.pub.pem -signature input.sha1-rsa.sig input.data

=head2 Keys generated by Crypt::PK::RSA

Generate keys (Perl code):

 use Crypt::PK::RSA;
 use File::Slurp 'write_file';

 my $pkrsa = Crypt::PK::RSA->new;
 $pkrsa->generate_key(256, 65537);
 write_file("rsakey.pub.der",  {binmode=>':raw'}, $pkrsa->export_key_der('public'));
 write_file("rsakey.priv.der", {binmode=>':raw'}, $pkrsa->export_key_der('private'));
 write_file("rsakey.pub.pem",  $pkrsa->export_key_pem('public_x509'));
 write_file("rsakey.priv.pem", $pkrsa->export_key_pem('private'));
 write_file("rsakey-passwd.priv.pem", $pkrsa->export_key_pem('private', 'secret'));

Use keys by OpenSSL:

 openssl rsa -in rsakey.priv.der -text -inform der
 openssl rsa -in rsakey.priv.pem -text
 openssl rsa -in rsakey-passwd.priv.pem -text -inform pem -passin pass:secret
 openssl rsa -in rsakey.pub.der -pubin -text -inform der
 openssl rsa -in rsakey.pub.pem -pubin -text 

=head2 Keys generated by OpenSSL

Generate keys:

 openssl genrsa -out rsakey.priv.pem 1024
 openssl rsa -in rsakey.priv.pem -out rsakey.priv.der -outform der
 openssl rsa -in rsakey.priv.pem -out rsakey.pub.pem -pubout
 openssl rsa -in rsakey.priv.pem -out rsakey.pub.der -outform der -pubout
 openssl rsa -in rsakey.priv.pem -passout pass:secret -des3 -out rsakey-passwd.priv.pem

Load keys (Perl code):

 use Crypt::PK::RSA;
 use File::Slurp 'write_file';

 my $pkrsa = Crypt::PK::RSA->new;
 $pkrsa->import_key("rsakey.pub.der");
 $pkrsa->import_key("rsakey.priv.der");
 $pkrsa->import_key("rsakey.pub.pem");
 $pkrsa->import_key("rsakey.priv.pem");
 $pkrsa->import_key("rsakey-passwd.priv.pem", "secret");

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/RSA_%28algorithm%29|https://en.wikipedia.org/wiki/RSA_%28algorithm%29>

=back
