package Crypt::KeyWrap;

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw(aes_key_wrap aes_key_unwrap gcm_key_wrap gcm_key_unwrap pbes2_key_wrap pbes2_key_unwrap ecdh_key_wrap ecdh_key_unwrap rsa_key_wrap rsa_key_unwrap)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Crypt::Mode::ECB;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use Crypt::KeyDerivation qw(pbkdf2);

# JWS: https://tools.ietf.org/html/rfc7515
# JWE: https://tools.ietf.org/html/rfc7516
# JWK: https://tools.ietf.org/html/rfc7517
# JWA: https://tools.ietf.org/html/rfc7518 - !!! this is important !!!

sub _LSB {
  my ($bytes, $data) = @_;
  my $len = length $data;
  return $len > $bytes ? substr($data, $len-$bytes, $bytes) : $data;
}

sub _MSB {
  my ($bytes, $data) = @_;
  my $len = length $data;
  return $len > $bytes ? substr($data, 0, $bytes) : $data;
}

sub _N2RAW {
  my ($bytes, $n) = @_;
  return pack("N", $n>> 32) . pack("N", $n & 0xFFFFFFFF) if $bytes == 8;
  return pack("N", $n& 0xFFFFFFFF) if $bytes == 4;
}

sub aes_key_wrap {
  my ($kek, $pt_data, $cipher, $padding, $inverse) = @_;
  $cipher  = 'AES' unless defined $cipher;
  $padding = $cipher eq 'AES' ? 1 : 0 unless defined $padding;

  my ($A, $B, $P, $R);

  die "aes_key_wrap: no KEK"     unless defined $kek;
  die "aes_key_wrap: no PT data" unless defined $pt_data;
  my $klen = length $kek;
  die "aes_key_wrap: invalid KEK length" unless $klen == 16 || $klen == 24 || $klen == 32;
  die "aes_key_wrap: cipher must be AES or DES_EDE" unless $cipher eq 'AES' || $cipher eq 'DES_EDE';
  die "aes_key_wrap: padding not allowed with DES_EDE" if $padding && $cipher eq 'DES_EDE';

  my $ECB = Crypt::Mode::ECB->new($cipher, 0);
  my $blck = $cipher eq 'DES_EDE' ? 4 : 8; # semiblock size in bytes, for AES 8, for 3DES 4

  my $IV = pack("H*", "A6" x $blck);
  my $len = length $pt_data;
  if ($len % $blck > 0) {
    die "aes_key_wrap: pt_data length not multiply of $blck" if !$padding;
    $pt_data .= chr(0) x ($blck - ($len % $blck));
    $IV = pack("H*", "A65959A6") . pack("N", $len);
  }

  my $n = length($pt_data) / $blck;
  $P->[$_] = substr($pt_data, $_*$blck, $blck) for (0..$n-1);

  if ($n == 1) {
    return $inverse ? $ECB->decrypt($IV . $P->[0], $kek)
                    : $ECB->encrypt($IV . $P->[0], $kek);
  }

  $A = $IV;
  $R->[$_] = $P->[$_] for (0..$n-1);

  for my $j (0..5) {
    for my $i (0..$n-1) {
      $B = $inverse ? $ECB->decrypt($A . $R->[$i], $kek)
                    : $ECB->encrypt($A . $R->[$i], $kek);
      $A = _MSB($blck, $B) ^ _N2RAW($blck, ($n*$j)+$i+1);
      $R->[$i] = _LSB($blck, $B);
    }
  }

  my $rv = $A;
  $rv .= $R->[$_] for (0..$n-1);
  return $rv;
}

sub aes_key_unwrap {
  my ($kek, $ct_data, $cipher, $padding, $inverse) = @_;
  $cipher  = 'AES' unless defined $cipher;
  $padding = $cipher eq 'AES' ? 1 : 0 unless defined $padding;

  my ($A, $B, $C, $P, $R);

  die "aes_key_unwrap: no KEK"     unless defined $kek;
  die "aes_key_unwrap: no CT data" unless defined $ct_data;
  my $klen = length $kek;
  die "aes_key_unwrap: invalid KEK length" unless $klen == 16 || $klen == 24 || $klen == 32;
  die "aes_key_unwrap: cipher must be AES or DES_EDE" unless $cipher eq 'AES' || $cipher eq 'DES_EDE';
  die "aes_key_unwrap: padding not allowed with DES_EDE" if $padding && $cipher eq 'DES_EDE';

  my $ECB = Crypt::Mode::ECB->new($cipher, 0);
  my $blck = $cipher eq 'DES_EDE' ? 4 : 8; # semiblock size in bytes, for AES 8, for 3DES 4

  my $n = length($ct_data) / $blck - 1;
  $C->[$_] = substr($ct_data, $_*$blck, $blck) for (0..$n); # n+1 semiblocks

  if ($n==1) {
    $B = $inverse ? $ECB->encrypt($C->[0] . $C->[1], $kek)
                  : $ECB->decrypt($C->[0] . $C->[1], $kek);
    $A = _MSB($blck, $B);
    $R->[0] = _LSB($blck, $B);
  }
  else {
    $A = $C->[0];
    $R->[$_] = $C->[$_+1] for (0..$n-1);
    for(my $j=5; $j>=0; $j--) {
      for(my $i=$n-1; $i>=0; $i--) {
        $B = $inverse ? $ECB->encrypt(($A ^ _N2RAW($blck, $n*$j+$i+1)) . $R->[$i], $kek)
                      : $ECB->decrypt(($A ^ _N2RAW($blck, $n*$j+$i+1)) . $R->[$i], $kek);
        $A = _MSB($blck, $B);
        $R->[$i] = _LSB($blck, $B);
      }
    }
  }

  my $rv = '';
  $rv .= $R->[$_] for (0..$n-1);

  my $A_hex = unpack("H*", $A);
  if ($A_hex eq 'a6'x$blck) {
    return $rv;
  }
  elsif ($A_hex =~ /^a65959a6/ && $blck == 8) {
    warn "key_unwrap: unexpected padding" unless $padding;
    my $n = unpack("N", substr($A, 4, 4));
    my $z = length($rv) - $n;
    my $tail = unpack("H*", substr($rv, -$z));
    die "aes_key_unwrap: invalid data" unless $tail eq "00"x$z;
    return substr($rv, 0, $n);
  }
  die "aes_key_unwrap: unexpected data [$cipher/$A_hex]";
}

# see https://github.com/Spomky-Labs/jose/tree/master/lib/Algorithm/KeyEncryption
# see https://github.com/rohe/pyjwkest/blob/5c1e321237dd2affb8b8434f0ca2a15c4da5e2b1/src/jwkest/aes_gcm.py
# AES GCM KW - https://tools.ietf.org/html/rfc7518#section-4.7

sub gcm_key_wrap {
  my ($kek, $pt_data, $aad, $cipher, $iv) = @_;
  $cipher = 'AES' unless defined $cipher;
  $iv = random_bytes(Crypt::Cipher->blocksize($cipher)) unless defined $iv;
  my ($ct_data, $tag) = gcm_encrypt_authenticate($cipher, $kek, $iv, $aad, $pt_data);
  return ($ct_data, $tag, $iv);
}

sub gcm_key_unwrap {
  my ($kek, $ct_data, $tag, $iv, $aad, $cipher) = @_;
  $cipher ||= 'AES';
  my $pt_data = gcm_decrypt_verify($cipher, $kek, $iv, $aad, $ct_data, $tag);
  return $pt_data;
}

# PBES2/PBKDF2 KW - https://tools.ietf.org/html/rfc7518#section-4.8
# https://github.com/Spomky-Labs/jose/blob/master/lib/Algorithm/KeyEncryption/PBES2AESKW.php

sub pbes2_key_wrap {
  my ($kek, $pt_data, $alg, $salt, $iter) = @_;
  my ($hash_name, $len);
  if ($alg =~ /^PBES2-HS(256|384|512)\+A(128|192|256)KW$/) {
    $hash_name = "SHA$1";
    $len = $2/8;
    my $aes_key = pbkdf2($kek, $alg."\x00".$salt, $iter, $hash_name, $len);
    my $ct_data = aes_key_wrap($aes_key, $pt_data);
    return $ct_data;
  }
  die "pbes2_key_wrap: invalid alg '$alg'";
  return undef;
}

sub pbes2_key_unwrap {
  my ($kek, $ct_data, $alg, $salt, $iter) = @_;
  my ($hash_name, $len);
  if ($alg =~ /^PBES2-HS(256|384|512)\+A(128|192|256)KW$/) {
    $hash_name = "SHA$1";
    $len = $2/8;
    my $aes_key = pbkdf2($kek, $alg."\x00".$salt, $iter, $hash_name, $len);
    my $pt_data = aes_key_unwrap($aes_key, $ct_data);
    return $pt_data;
  }
  die "pbes2_key_unwrap: invalid alg '$alg'";
  return undef;
}

# RSA KW
# https://tools.ietf.org/html/rfc7518#section-4.2
# https://tools.ietf.org/html/rfc7518#section-4.3

sub _prepare_rsa_key {
  my ($key) = @_;
  # we need Crypt::PK::RSA object
  return $key                       if ref($key) eq 'Crypt::PK::RSA';
  return Crypt::PK::RSA->new($key)  if ref($key) eq 'HASH';
  return Crypt::PK::RSA->new(@$key) if ref($key) eq 'ARRAY';
  return Crypt::PK::RSA->new(\$key) if !ref($key);
  # handle also: Crypt::OpenSSL::RSA
  my $str;
  if (ref($key) eq 'Crypt::OpenSSL::RSA' && $key->is_private) {
    $str = $key->get_private_key_string 
  }
  elsif (ref($key) eq 'Crypt::OpenSSL::RSA' && !$key->is_private) {
    $str = $key->get_public_key_string;
  }
  return Crypt::PK::RSA->new(\$str) if !ref($str);
}

sub rsa_key_wrap {
  my ($kek_public, $pt_data, $alg) = @_;
  my $pk = _prepare_rsa_key($kek_public);
  my ($padding, $hash_name);
  if    ($alg eq 'RSA-OAEP')     { ($padding, $hash_name) = ('oaep', 'SHA1') }
  elsif ($alg eq 'RSA-OAEP-256') { ($padding, $hash_name) = ('oaep', 'SHA256') }
  elsif ($alg eq 'RSA1_5')       { $padding = 'v1.5' }
  die "rsa_key_wrap: invalid algorithm '$alg'" unless $padding;
  my $ct_data = $pk->encrypt($pt_data, $padding, $hash_name);
  return $ct_data;
}

sub rsa_key_unwrap {
  my ($kek_private, $ct_data, $alg) = @_;
  my $pk = _prepare_rsa_key($kek_private);
  die "rsa_key_unwrap: no private key" unless $pk->is_private;
  my ($padding, $hash_name);
  if    ($alg eq 'RSA-OAEP')     { ($padding, $hash_name) = ('oaep', 'SHA1') }
  elsif ($alg eq 'RSA-OAEP-256') { ($padding, $hash_name) = ('oaep', 'SHA256') }
  elsif ($alg eq 'RSA1_5')       { $padding = 'v1.5' }
  die "rsa_key_unwrap: invalid algorithm '$alg'" unless $padding;
  my $pt_data = $pk->decrypt($ct_data, $padding, $hash_name);
  return $pt_data;
}

# ConcatKDF - Concatenation Key Derivation Function
# https://code.google.com/p/openinfocard/source/browse/trunk/testsrc/org/xmldap/crypto/ConcatKeyDerivationFunction.java?r=770
# http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf

# ECDH KW - https://tools.ietf.org/html/rfc7518#section-4.6
# ConcatKDF
# http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
# https://code.google.com/p/openinfocard/source/browse/trunk/testsrc/org/xmldap/crypto/ConcatKeyDerivationFunction.java?r=770

sub ecdh_key_wrap {
  my ($kek_public, $pt_data, $xxx) = @_;
  my ($ct_data, $epk, $apu, $apv); # "epk" (Ephemeral Public Key), "apu" (Agreement PartyUInfo), "apv" (Agreement PartyVInfo)
  # ...
  die;
  return ($ct_data, $epk, $apu, $apv);
}

sub ecdh_key_unwrap {
  my ($kek_private, $ct_data, $epk, $apu, $apv, $xxx) = @_;
  my $pt_data;
  # ...
  die;
  return $pt_data;
}

1;

=pod

=head1 NAME

Crypt::KeyWrap - AES key wrap / unwrap functions

=head1 SYNOPSIS

   # wrapping
   use Crypt::KeyWrap qw(aes_key_wrap);
   my $kek     = pack("H*", "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"); # shared secret, keep private
   my $pt_data = pack("H*", "c37b7e6492584340bed12207808941155068f738");
   my $ct_data = aes_key_wrap($kek, $pt_data);

   # unwrapping
   use Crypt::KeyWrap qw(aes_key_unwrap);
   my $kek     = pack("H*", "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"); # shared secret, keep private
   my $ct_data = pack("H*", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
   my $pt_data = aes_key_unwrap($kek, $pt_data);

=head1 DESCRIPTION

Implements key management algorithms defined in L<https://tools.ietf.org/html/rfc7518>

BEWARE: experimental, interface of this module might change!

Currently supported algorithms:

 A128KW
 A192KW
 A256KW
 A128GCMKW
 A192GCMKW
 A256GCMKW
 PBES2-HS256+A128KW
 PBES2-HS384+A192KW
 PBES2-HS512+A256KW
 RSA-OAEP
 RSA-OAEP-256
 RSA1_5

Not supported yet:

 ECDH-ES+A128KW
 ECDH-ES+A192KW
 ECDH-ES+A256KW
 ECDH-ES

=head1 FUNCTIONS

=head2 aes_key_wrap

AES key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.4>
(implements algorithms C<A128KW>, C<A192KW>, C<A256KW>).

Implementation follows L<https://tools.ietf.org/html/rfc5649> and L<https://tools.ietf.org/html/rfc3394>.

The implementation is also compatible with L<http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf>
(it supports AES based KW, KWP + TDEA/DES_EDE based TKW).

AES Key Wrap algorithm.

   $ct_data = aes_key_wrap($kek, $pt_data);
   # or
   $ct_data = aes_key_wrap($kek, $pt_data, $cipher, $padding, $inverse);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $pt_data .. plaintext data
   # optional params:
   #  $cipher  .. 'AES' (default) or 'DES_EDE'
   #  $padding .. 1 (default) or 0 handle $pt_data padding (relevant for AES only)
   #  $inverse .. 0 (default) or 1 use cipher in inverse mode as defined by SP.800-38F

Values C<$ct_data>, C<$pt_data> and C<$kek> are binary octets. If you disable padding you have to make sure that
C<$pt_data> length is multiply of 8 (for AES) or multiply of 4 (for DES_EDE);

=head2 aes_key_unwrap

AES key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.4>
(implements algorithms C<A128KW>, C<A192KW>, C<A256KW>).

AES Key Unwrap algorithm.

   $pt_data = aes_key_unwrap($kek, $ct_data);
   # or
   $pt_data = aes_key_unwrap($kek, $ct_data, $cipher, $padding, $inverse);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $ct_data .. ciphertext data
   # optional params:
   #  $cipher  .. 'AES' (default) or 'DES_EDE'
   #  $padding .. 1 (default) or 0 - use $pt_data padding (relevant for AES only)
   #  $inverse .. 0 (default) or 1 - use cipher in inverse mode as defined by SP.800-38F

Values C<$ct_data>, C<$pt_data> and C<$kek> are binary octets.

=head2 gcm_key_wrap

AES GCM key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.7>
(implements algorithms C<A128GCMKW>, C<A192GCMKW>, C<A256GCMKW>).

   ($ct_data, $tag, $iv) = gcm_key_wrap($kek, $pt_data);
   #or
   ($ct_data, $tag, $iv) = gcm_key_wrap($kek, $pt_data, $aad);
   #or
   ($ct_data, $tag, $iv) = gcm_key_wrap($kek, $pt_data, $aad, $cipher, $iv);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $pt_data .. plaintext data
   # optional params:
   #  $aad     .. additional authenticated data, DEFAULT is '' (empty string)
   #  $cipher  .. cipher to be used by GCM, DEFAULT is 'AES'
   #  $iv      .. initialization vector (if not defined a random IV is generated)

Values C<$ct_data>, C<$pt_data>, C<$aad>, C<$iv>, C<$tag> and C<$kek> are binary octets.

=head2 gcm_key_unwrap

AES GCM key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.7>
(implements algorithms C<A128GCMKW>, C<A192GCMKW>, C<A256GCMKW>).

   $pt_data = gcm_key_unwrap($kek, $ct_data, $tag, $iv);
   # or
   $pt_data = gcm_key_unwrap($kek, $ct_data, $tag, $iv, $aad);
   # or
   $pt_data = gcm_key_unwrap($kek, $ct_data, $tag, $iv, $aad, $cipher);

   # params:
   #  $kek     .. key encryption key (16bytes for AES128, 24 for AES192, 32 for AES256)
   #  $ct_data .. ciphertext data
   #  $tag     .. GCM's tag
   #  $iv      .. initialization vector
   # optional params:
   #  $aad     .. additional authenticated data, DEFAULT is '' (empty string)
   #  $cipher  .. cipher to be used by GCM, DEFAULT is 'AES'

Values C<$ct_data>, C<$pt_data>, C<$aad>, C<$iv>, C<$tag> and C<$kek> are binary octets.

=head2 pbes2_key_wrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.8>
(implements algorithms C<PBES2-HS256+A128KW>, C<PBES2-HS384+A192KW>, C<PBES2-HS512+A256KW>).

   $ct_data = pbes2_key_wrap($kek, $pt_data, $alg, $salt, $iter) = @_;

   # params:
   #  $kek     .. key encryption key (arbitrary length)
   #  $pt_data .. plaintext data
   #  $alg     .. algorithm name e.g. 'PBES2-HS256+A128KW' (see rfc7518)
   #  $salt    .. pbkdf2 salt
   #  $iter    .. pbkdf2 iteration count

Values C<$ct_data>, C<$pt_data>, C<$salt> and C<$kek> are binary octets.

=head2 pbes2_key_unwrap

PBES2 key unwrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.8>
(implements algorithms C<PBES2-HS256+A128KW>, C<PBES2-HS384+A192KW>, C<PBES2-HS512+A256KW>).

   $pt_data = pbes2_key_unwrap($kek, $ct_data, $alg, $salt, $iter) = @_;

   # params:
   #  $kek     .. key encryption key (arbitrary length)
   #  $ct_data .. ciphertext data
   #  $alg     .. algorithm name e.g. 'PBES2-HS256+A128KW' (see rfc7518)
   #  $salt    .. pbkdf2 salt
   #  $iter    .. pbkdf2 iteration count

Values C<$ct_data>, C<$pt_data>, C<$salt> and C<$kek> are binary octets.

=head2 rsa_key_wrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.2> and
L<https://tools.ietf.org/html/rfc7518#section-4.3> (implements algorithms C<RSA1_5>, C<RSA-OAEP-256>, C<RSA-OAEP>).

   $ct_data = rsa_key_wrap($kek, $pt_data, $alg) = @_;

   # params:
   #  $kek     .. RSA public key
   #  $pt_data .. plaintext data
   #  $alg     .. algorithm name e.g. 'RSA-OAEP' (see rfc7518)

Values C<$ct_data> and C<$pt_data> are binary octets.

Parameter C<$kek> can be L<Crypt::PK::RSA> or L<Crypt::OpenSSL::RSA> instance, reference to JWK/JSON string or 
JWK perl hash, reference to a string with PEM or DER encoded key.

=head2 rsa_key_unwrap

PBES2 key wrap algorithm as defined in L<https://tools.ietf.org/html/rfc7518#section-4.2> and
L<https://tools.ietf.org/html/rfc7518#section-4.3> (implements algorithms C<RSA1_5>, C<RSA-OAEP-256>, C<RSA-OAEP>).

   $pt_data = rsa_key_unwrap($kek, $ct_data, $alg) = @_;

   # params:
   #  $kek     .. RSA private key
   #  $ct_data .. ciphertext data
   #  $alg     .. algorithm name e.g. 'RSA-OAEP' (see rfc7518)

Values C<$ct_data> and C<$pt_data> are binary octets.

Parameter C<$kek> can be L<Crypt::PK::RSA> or L<Crypt::OpenSSL::RSA> instance, reference to JWK/JSON string or 
JWK perl hash, reference to a string with PEM or DER encoded key.

=head1 SEE ALSO

L<Crypt::Cipher::AES>, L<Crypt::AuthEnc::GCM>, L<Crypt::PK::RSA>, L<Crypt::KeyDerivation>
