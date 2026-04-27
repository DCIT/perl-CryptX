package Crypt::PK::DSA;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( dsa_encrypt dsa_decrypt dsa_sign_message dsa_verify_message dsa_sign_hash dsa_verify_hash )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use Crypt::Misc qw(read_rawfile encode_b64 decode_b64 pem_to_der der_to_pem);
use Crypt::PK;

sub new {
  my $self = shift->_new();
  return @_ > 0 ? $self->import_key(@_) : $self;
}

sub generate_key {
  my $self = shift;
  return $self->_generate_key_size(@_) if @_ == 2;
  if (@_ == 1 && ref $_[0] eq 'HASH') {
    my $param = shift;
    my $p = $param->{p} or croak "FATAL: 'p' param not specified";
    my $q = $param->{q} or croak "FATAL: 'q' param not specified";
    my $g = $param->{g} or croak "FATAL: 'g' param not specified";
    $p =~ s/^0x//;
    $q =~ s/^0x//;
    $g =~ s/^0x//;
    croak "FATAL: 'p' param is empty after stripping '0x' prefix" unless length $p;
    croak "FATAL: 'q' param is empty after stripping '0x' prefix" unless length $q;
    croak "FATAL: 'g' param is empty after stripping '0x' prefix" unless length $g;
    return $self->_generate_key_pqg_hex($p, $q, $g);
  }
  elsif (@_ == 1 && ref $_[0] eq 'SCALAR') {
    my $data = ${$_[0]};
    if ($data =~ /-----BEGIN DSA PARAMETERS-----\s*(.+)\s*-----END DSA PARAMETERS-----/s) {
      $data = pem_to_der($data) or croak "FATAL: PEM/params decode failed";
    }
    return $self->_generate_key_dsaparam($data);
  }
  croak "FATAL: DSA generate_key - invalid args";
}

sub export_key_pem {
  my ($self, $type, $password, $cipher) = @_;
  # public_x509 uses the same DER as public, just different PEM header
  my $der_type = ($type || '') eq 'public_x509' ? 'public' : ($type || '');
  my $key = $self->export_key_der($der_type);
  return unless $key;
  return der_to_pem($key, "DSA PRIVATE KEY", $password, $cipher) if $type eq 'private';
  return der_to_pem($key, "DSA PUBLIC KEY") if $type eq 'public';
  return der_to_pem($key, "PUBLIC KEY") if $type eq 'public_x509';
}

sub import_key {
  my ($self, $key, $password) = @_;
  croak "FATAL: undefined key" unless $key;

  # special case
  if (ref($key) eq 'HASH') {
    if ($key->{p} && $key->{q} && $key->{g} && $key->{y}) {
      # hash exported via key2hash
      return $self->_import_hex($key->{p}, $key->{q}, $key->{g}, $key->{x}, $key->{y});
    }
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

  if ($data =~ /-----BEGIN (DSA PRIVATE|DSA PUBLIC|PRIVATE|ENCRYPTED PRIVATE|PUBLIC) KEY-----(.+?)-----END (DSA PRIVATE|DSA PUBLIC|PRIVATE|ENCRYPTED PRIVATE|PUBLIC) KEY-----/s) {
    return $self->_import_pem($data, $password);
  }
  elsif ($data =~ /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s) {
    return $self->_import_pem($data, undef);
  }
  elsif ($data =~ /-----BEGIN OPENSSH PRIVATE KEY-----(.+?)-----END OPENSSH PRIVATE KEY-----/s) {
    return $self->_import_openssh($data, $password);
  }
  elsif ($data =~ /---- BEGIN SSH2 PUBLIC KEY ----(.+?)---- END SSH2 PUBLIC KEY ----/s) {
    return $self->_import_openssh($data, undef);
  }
  elsif ($data =~ /ssh-dss\s+(\S+)/) {
    $data = decode_b64("$1");
    my ($typ, $p, $q, $g, $y) = Crypt::PK::_ssh_parse($data);
    return $self->_import_hex(unpack('H*',$p), unpack('H*',$q), unpack('H*',$g), undef, unpack('H*',$y)) if $typ && $p && $q && $g && $y && $typ eq 'ssh-dss';
  }
  else {
    my $rv = eval { $self->_import($data) } || eval { $self->_import_pkcs8($data, $password) };
    return $rv if $rv;
  }
  croak "FATAL: invalid or unsupported DSA key format";
}

### FUNCTIONS

sub dsa_encrypt { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->encrypt(@_);
}

sub dsa_decrypt { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->decrypt(@_);
}

sub dsa_sign_message { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_message(@_);
}

sub dsa_verify_message { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_message(@_);
}

sub dsa_sign_hash { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->sign_hash(@_);
}

sub dsa_verify_hash { # legacy/obsolete
  my $key = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $key = __PACKAGE__->new($key) unless ref $key;
  croak "FATAL: invalid 'key' param" unless ref($key) eq __PACKAGE__;
  return $key->verify_hash(@_);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::PK::DSA - Public key cryptography based on DSA

=head1 SYNOPSIS

 ### OO interface

 my $message = 'hello world';
 my $signer = Crypt::PK::DSA->new();
 $signer->generate_key(30, 256);

 my $signature = $signer->sign_message($message);
 my $public_der = $signer->export_key_der('public');
 my $verifier = Crypt::PK::DSA->new(\$public_der);
 $verifier->verify_message($signature, $message) or die "ERROR";

 my $ciphertext = $verifier->encrypt("secret message");
 my $plaintext = $signer->decrypt($ciphertext);

 my $private_der = $signer->export_key_der('private');
 my $private_pem = $signer->export_key_pem('private');
 my $public_pem = $verifier->export_key_pem('public');

=head1 DESCRIPTION

DSA is primarily a digital signature scheme. In this module, signing and
verification are the most common operations and therefore the primary examples.

Legacy function-style wrappers still exist in code for backwards compatibility,
but they are intentionally undocumented.

=head1 METHODS

=head2 new

  my $source = Crypt::PK::DSA->new();
  $source->generate_key(20, 128);

  my $public_der = $source->export_key_der('public');
  my $pub = Crypt::PK::DSA->new(\$public_der);

  my $private_pem = $source->export_key_pem('private', 'secret', 'AES-256-CBC');
  my $priv = Crypt::PK::DSA->new(\$private_pem, 'secret');

Passing C<$filename> or C<\$buffer> to C<new> is equivalent: both forms
immediately import the key material into the new object.

=head2 generate_key

Uses the bundled C<chacha20> PRNG via libtomcrypt's C<rng_make_prng>.
Returns the object itself (for chaining).

 $pk->generate_key($group_size, $modulus_size);
 # $group_size  ... [integer] size of the subgroup (q) in bytes; must satisfy: 15 < $group_size < 1024
 # $modulus_size .. [integer] size of the prime (p) in bytes; must satisfy: ($modulus_size - $group_size) < 512
 #                  $modulus_size must be >= $group_size
 #
 # The two-integer form uses Perl's usual numeric-to-integer coercion before
 # the XS call. Callers should therefore pass exact integers; values like
 # C<10.9> or C<"1e1"> will be coerced according to Perl's integer conversion.

 ### Common parameter pairs (group_size, modulus_size) => security level:
 # generate_key(20, 128)   => 80-bit security  (1024-bit p, 160-bit q)
 # generate_key(30, 256)   => 120-bit security (2048-bit p, 240-bit q)
 # generate_key(32, 256)   => 128-bit security (2048-bit p, 256-bit q)
 # generate_key(35, 384)   => ~140-bit security (3072-bit p, 280-bit q)
 # 140 bits  => generate_key(35, 384)
 # 160 bits  => generate_key(40, 512)

 ### Sizes according section 4.2 of FIPS 186-4
 # (L and N are the bit lengths of p and q respectively)
 # L = 1024, N = 160 => generate_key(20, 128)
 # L = 2048, N = 224 => generate_key(28, 256)
 # L = 2048, N = 256 => generate_key(32, 256)
 # L = 3072, N = 256 => generate_key(32, 384)

 $pk->generate_key($param_hash)
 # $param_hash is { p => $p, q => $q, g => $g }
 # where $p, $q, $g are hex strings

 $pk->generate_key(\$dsa_param)
 # $dsa_param is the content of DER or PEM file with DSA params
 # e.g. openssl dsaparam 2048

=head2 import_key

Loads private or public key in DER or PEM format.

  my $source = Crypt::PK::DSA->new();
  $source->generate_key(20, 128);

  my $public_der = $source->export_key_der('public');
  my $pub = Crypt::PK::DSA->new();
  $pub->import_key(\$public_der);

  my $private_pem = $source->export_key_pem('private', 'secret', 'AES-256-CBC');
  my $priv = Crypt::PK::DSA->new();
  $priv->import_key(\$private_pem, 'secret');

The same method also accepts filenames instead of buffers.

Loading private or public keys form perl hash:

 $pk->import_key($hashref);

 # where $hashref is a key exported via key2hash
 $pk->import_key({
   p => "AAF839A764E04D80824B79FA1F0496C093...", #prime modulus
   q => "D05C4CB45F29D353442F1FEC43A6BE2BE8...", #prime divisor
   g => "847E8896D12C9BF18FE283AE7AD58ED7F3...", #generator of a subgroup of order q in GF(p)
   x => "6C801901AC74E2DC714D75A9F6969483CF...", #private key, random  0 < x < q
   y => "8F7604D77FA62C7539562458A63C7611B7...", #public key, where y = g^x mod p
 });

Supported key formats:

=over

=item * DSA public keys

 -----BEGIN PUBLIC KEY-----
 MIIBtjCCASsGByqGSM44BAEwggEeAoGBAJKyu+puNMGLpGIhbD1IatnwlI79ePr4
 YHe2KBhRkheKxWUZRpN1Vd/+usS2IHSJ9op5cSWETiP05d7PMtJaitklw7jhudq3
 GxNvV/GRdCQm3H6d76FHP88dms4vcDYc6ry6wKERGfNEtZ+4BAKrMZK+gDYsF4Aw
 U6WVR969kYZhAhUA6w25FgSRmJ8W4XkvC60n8Wv3DpMCgYA4ZFE+3tLOM24PZj9Z
 rxuqUzZZdR+kIzrsIYpWN9ustbmdKLKwsqIaUIxc5zxHEhbAjAIf8toPD+VEQIpY
 7vgJgDhXuPq45BgN19iLTzOJwIhAFXPZvnAdIo9D/AnMw688gT6g6U8QCZwX2XYg
 ICiVcriYVNcjVKHSFY/X0Oi7CgOBhAACgYB4ZTn4OYT/pjUd6tNhGPtOS3CE1oaj
 5ScbetXg4ZDpceEyQi8VG+/ZTbs8var8X77JdEdeQA686cAxpOaVgW8V4odvcmfA
 BfueiGnPXjqGfppiHAyL1Ngyd+EsXKmKVXZYAVFVI0WuJKiZBSVURU7+ByxOfpGa
 fZhibr0SggWixQ==
 -----END PUBLIC KEY-----

=item * DSA private keys

 -----BEGIN DSA PRIVATE KEY-----
 MIIBuwIBAAKBgQCSsrvqbjTBi6RiIWw9SGrZ8JSO/Xj6+GB3tigYUZIXisVlGUaT
 dVXf/rrEtiB0ifaKeXElhE4j9OXezzLSWorZJcO44bnatxsTb1fxkXQkJtx+ne+h
 Rz/PHZrOL3A2HOq8usChERnzRLWfuAQCqzGSvoA2LBeAMFOllUfevZGGYQIVAOsN
 uRYEkZifFuF5LwutJ/Fr9w6TAoGAOGRRPt7SzjNuD2Y/Wa8bqlM2WXUfpCM67CGK
 VjfbrLW5nSiysLKiGlCMXOc8RxIWwIwCH/LaDw/lRECKWO74CYA4V7j6uOQYDdfY
 i08zicCIQBVz2b5wHSKPQ/wJzMOvPIE+oOlPEAmcF9l2ICAolXK4mFTXI1Sh0hWP
 19DouwoCgYB4ZTn4OYT/pjUd6tNhGPtOS3CE1oaj5ScbetXg4ZDpceEyQi8VG+/Z
 Tbs8var8X77JdEdeQA686cAxpOaVgW8V4odvcmfABfueiGnPXjqGfppiHAyL1Ngy
 d+EsXKmKVXZYAVFVI0WuJKiZBSVURU7+ByxOfpGafZhibr0SggWixQIVAL7Sia03
 8bvANjjL9Sitk8slrM6P
 -----END DSA PRIVATE KEY-----

=item * DSA private keys in password protected PEM format:

 -----BEGIN DSA PRIVATE KEY-----
 Proc-Type: 4,ENCRYPTED
 DEK-Info: DES-CBC,227ADC3AA0299491

 UISxBYAxPQMl2eK9LMAeHsssF6IxO+4G2ta2Jn8VE+boJrrH3iSTKeMXGjGaXl0z
 DwcLGV+KMR70y+cxtTb34rFy+uSpBy10dOQJhxALDbe1XfCDQIUfaXRfMNA3um2I
 JdZixUD/zcxBOUzao+MCr0V9XlJDgqBhJ5EEr53XHH07Eo5fhiBfbbR9NzdUPFrQ
 p2ASyZtFh7RXoIBUCQgg21oeLddcNWV7gd/Y46kghO9s0JbJ8C+IsuWEPRSq502h
 tSoDN6B0sxbVvOUICLLbQaxt7yduTAhRxVIJZ1PWATTVD7CZBVz9uIDZ7LOv+er2
 1q3vkwb8E9spPsA240+BnfD571XEop4jrawxC0VKQZ+3cPVLc6jhIsxvzzFQUt67
 g66v8GUgt7KF3KhVV7qEtntybQWDWb+K/uTIH9Ra8nP820d3Rnl61pPXDPlluteT
 WSLOvEMN2zRmkaxQNv/tLdT0SYpQtdjw74G3A6T7+KnvinKrjtp1a/AXkCF9hNEx
 DGbxOYo1UOmk8qdxWCrab34nO+Q8oQc9wjXHG+ZtRYIMoGMKREK8DeL4H1RPNkMf
 rwXWk8scd8QFmJAb8De1VQ==
 -----END DSA PRIVATE KEY-----

=item * SSH public DSA keys

 ssh-dss AAAAB3NzaC1kc3MAAACBAKU8/avmk...4XOwuEssAVhmwA==

=item * SSH public DSA keys (RFC-4716 format)

 ---- BEGIN SSH2 PUBLIC KEY ----
 Comment: "1024-bit DSA, converted from OpenSSH"
 AAAAB3NzaC1kc3MAAACBAKU8/avmkFeGnSqwYG7dZnQlG+01QNaxu3F5v0NcL/SRUW7Idp
 Uq8t14siK0mA6yjphLhOf5t8gugTEVBllP86ANSbFigH7WN3v6ydJWqm60pNhNHN//50cn
 NtIsXbxeq3VtsI64pkH1OJqeZDHLmu73k4T0EKOzsylSfF/wtVBJAAAAFQChpubLHViwPB
 +jSvUb8e4THS7PBQAAAIAJD1PMCiTCQa1xyD/NCWOajCufTOIzKAhm6l+nlBVPiKI+262X
 pYt127Ke4mPL8XJBizoTjSQN08uHMg/8L6W/cdO2aZ+mhkBnS1xAm83DAwqLrDraR1w/4Q
 RFxr5Vbyy8qnejrPjTJobBN1BGsv84wHkjmoCn6pFIfkGYeATlJgAAAIAHYPU1zMVBTDWr
 u7SNC4G2UyWGWYYLjLytBVHfQmBa51CmqrSs2kCfGLGA1ynfYENsxcJq9nsXrb4i17H5BH
 JFkH0g7BUDpeBeLr8gsK3WgfqWwtZsDkltObw9chUD/siK6q/dk/fSIB2Ho0inev7k68Z5
 ZkNI4XOwuEssAVhmwA==
 ---- END SSH2 PUBLIC KEY ----

=back

=head2 export_key_der

Returns the key as a binary DER-encoded string.

 my $private_der = $pk->export_key_der('private');
 #or
 my $public_der = $pk->export_key_der('public');

=head2 export_key_pem

Returns the key as a PEM-encoded string (ASCII).

 my $private_pem = $pk->export_key_pem('private');
 #or
 my $public_pem = $pk->export_key_pem('public');
 #or
 my $public_pem = $pk->export_key_pem('public_x509');

With parameter C<'public'> uses header and footer lines:

  -----BEGIN DSA PUBLIC KEY------
  -----END DSA PUBLIC KEY------

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

Returns the ciphertext as a binary string.

DSA is usually used for signatures. This helper is available because the
underlying library exposes a DSA-based encryption primitive.

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $ct = $pk->encrypt($message);
 #or
 my $ct = $pk->encrypt($message, $hash_name);

 # $hash_name .. [string] 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 decrypt

Returns the plaintext as a binary string.

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $pt = $pk->decrypt($ciphertext);

=head2 sign_message

Returns the signature as a binary string.

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $signature = $pk->sign_message($message);
 #or
 my $signature = $pk->sign_message($message, $hash_name);

 # $hash_name .. [string] 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 verify_message

Returns C<1> if the signature is valid, C<0> otherwise.

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $valid = $pk->verify_message($signature, $message);
 #or
 my $valid = $pk->verify_message($signature, $message, $hash_name);

 # $hash_name .. [string] 'SHA1' (DEFAULT), 'SHA256' or any other hash supported by Crypt::Digest

=head2 sign_hash

Returns the signature as a binary string.

 my $pk = Crypt::PK::DSA->new($priv_key_filename);
 my $signature = $pk->sign_hash($message_hash);

=head2 verify_hash

Returns C<1> if the signature is valid, C<0> otherwise.

 my $pk = Crypt::PK::DSA->new($pub_key_filename);
 my $valid = $pk->verify_hash($signature, $message_hash);

=head2 is_private

 my $rv = $pk->is_private;
 # 1 .. private key loaded
 # 0 .. public key loaded
 # undef .. no key loaded

=head2 size

 my $size = $pk->size;
 # returns key size (length of the prime p) in bytes or undef if key not loaded

=head2 size_q

 my $size = $pk->size_q;
 # returns length of the prime q in bytes or undef if key not loaded

=head2 key2hash

Returns a hashref with the key components, or C<undef> if no key is loaded.

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

=head1 OpenSSL interoperability

 ### let's have:
 # DSA private key in PEM format - dsakey.priv.pem
 # DSA public key in PEM format  - dsakey.pub.pem
 # data file to be signed - input.data

=head2 Sign by OpenSSL, verify by Crypt::PK::DSA

Create signature (from commandline):

 openssl dgst -sha1 -sign dsakey.priv.pem -out input.sha1-dsa.sig input.data

Verify signature (Perl code):

 use Crypt::PK::DSA;
 use Crypt::Digest 'digest_file';
 use Crypt::Misc 'read_rawfile';

 my $pkdsa = Crypt::PK::DSA->new("dsakey.pub.pem");
 my $signature = read_rawfile("input.sha1-dsa.sig");
 my $valid = $pkdsa->verify_hash($signature, digest_file("SHA1", "input.data"));
 print $valid ? "SUCCESS" : "FAILURE";

=head2 Sign by Crypt::PK::DSA, verify by OpenSSL

Create signature (Perl code):

 use Crypt::PK::DSA;
 use Crypt::Digest 'digest_file';
 use Crypt::Misc 'write_rawfile';

 my $pkdsa = Crypt::PK::DSA->new("dsakey.priv.pem");
 my $signature = $pkdsa->sign_hash(digest_file("SHA1", "input.data"));
 write_rawfile("input.sha1-dsa.sig", $signature);

Verify signature (from commandline):

 openssl dgst -sha1 -verify dsakey.pub.pem -signature input.sha1-dsa.sig input.data

=head2 Keys generated by Crypt::PK::DSA

Generate keys (Perl code):

 use Crypt::PK::DSA;
 use Crypt::Misc 'write_rawfile';

 my $pkdsa = Crypt::PK::DSA->new;
 $pkdsa->generate_key(20, 128);
 write_rawfile("dsakey.pub.der",  $pkdsa->export_key_der('public'));
 write_rawfile("dsakey.priv.der", $pkdsa->export_key_der('private'));
 write_rawfile("dsakey.pub.pem",  $pkdsa->export_key_pem('public_x509'));
 write_rawfile("dsakey.priv.pem", $pkdsa->export_key_pem('private'));
 write_rawfile("dsakey-passwd.priv.pem", $pkdsa->export_key_pem('private', 'secret'));

Use keys by OpenSSL:

 openssl dsa -in dsakey.priv.der -text -inform der
 openssl dsa -in dsakey.priv.pem -text
 openssl dsa -in dsakey-passwd.priv.pem -text -inform pem -passin pass:secret
 openssl dsa -in dsakey.pub.der -pubin -text -inform der
 openssl dsa -in dsakey.pub.pem -pubin -text

=head2 Keys generated by OpenSSL

Generate keys:

 openssl dsaparam -genkey -out dsakey.priv.pem 1024
 openssl dsa -in dsakey.priv.pem -out dsakey.priv.der -outform der
 openssl dsa -in dsakey.priv.pem -out dsakey.pub.pem -pubout
 openssl dsa -in dsakey.priv.pem -out dsakey.pub.der -outform der -pubout
 openssl dsa -in dsakey.priv.pem -passout pass:secret -des3 -out dsakey-passwd.priv.pem

Load keys (Perl code):

 use Crypt::PK::DSA;

 my $pkdsa = Crypt::PK::DSA->new;
 $pkdsa->import_key("dsakey.pub.der");
 $pkdsa->import_key("dsakey.priv.der");
 $pkdsa->import_key("dsakey.pub.pem");
 $pkdsa->import_key("dsakey.priv.pem");
 $pkdsa->import_key("dsakey-passwd.priv.pem", "secret");

=head1 SEE ALSO

=over

=item * L<https://en.wikipedia.org/wiki/Digital_Signature_Algorithm|https://en.wikipedia.org/wiki/Digital_Signature_Algorithm>

=back

=cut
