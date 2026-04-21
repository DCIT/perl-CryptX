package Crypt::KeyDerivation;

use strict;
use warnings;
our $VERSION = '0.087_005';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw(pbkdf1 pbkdf1_openssl pbkdf2 hkdf hkdf_expand hkdf_extract bcrypt_pbkdf scrypt_pbkdf argon2_pbkdf)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

1;

=pod

=head1 NAME

Crypt::KeyDerivation - PBKDF1, PBKDF2, HKDF, Bcrypt, Scrypt, Argon2 key derivation functions

=head1 SYNOPSIS

  use Crypt::KeyDerivation ':all';

  ### PBKDF1/2
  $derived_key1 = pbkdf1($password, $salt, $iteration_count, $hash_name, $len);
  $derived_key2 = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name, $len);
  $derived_key3 = pbkdf2($password, $salt, $iteration_count, $hash_name, $len);

  ### HKDF & co.
  $derived_key4 = hkdf($keying_material, $salt, $hash_name, $len, $info);
  $prk  = hkdf_extract($keying_material, $salt, $hash_name);
  $okm1 = hkdf_expand($prk, $hash_name, $len, $info);

  ### bcrypt / scrypt / argon2
  $derived_key4 = bcrypt_pbkdf($password, $salt, $rounds, $hash_name, $len);
  $derived_key5 = scrypt_pbkdf($password, $salt, $N, $r, $p, $len);
  $derived_key6 = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len, $secret, $ad);

=head1 DESCRIPTION

Provides an interface to key derivation functions:

=over

=item * PBKDF1 and PBKDF2 according to PKCS#5 v2.0 L<https://tools.ietf.org/html/rfc2898|https://tools.ietf.org/html/rfc2898>

=item * HKDF (+ related) according to L<https://tools.ietf.org/html/rfc5869|https://tools.ietf.org/html/rfc5869>

=item * Bcrypt-PBKDF as defined by the OpenBSD project

=item * Scrypt according to L<https://tools.ietf.org/html/rfc7914>

=item * Argon2 according to L<https://tools.ietf.org/html/rfc9106>

=back

While primarily designed for key derivation, the functions PBKDF2, Bcrypt, Scrypt and Argon2
are also widely used for password hashing. In that use case the derived key serves as the
stored password hash.

=head1 FUNCTIONS

=head2 pbkdf1

B<BEWARE:> if you are not sure, do not use C<pbkdf1> but rather choose C<pbkdf2>.

  $derived_key = pbkdf1($password, $salt, $iteration_count, $hash_name, $len);
  #or
  $derived_key = pbkdf1($password, $salt, $iteration_count, $hash_name);
  #or
  $derived_key = pbkdf1($password, $salt, $iteration_count);
  #or
  $derived_key = pbkdf1($password, $salt);

  # $password ......... input keying material  (password)
  # $salt ............. salt/nonce (expected length: 8)
  # $iteration_count .. optional, DEFAULT: 5000
  # $hash_name ........ optional, DEFAULT: 'SHA256'
  # $len .............. optional, derived key len, DEFAULT: 32

=head2 pbkdf1_openssl

I<Since: CryptX-0.100>

OpenSSL-compatible variant of PBKDF1 (implements C<EVP_BytesToKey>). Unlike strict
C<pbkdf1>, the output length is not limited to the hash size -- it can be arbitrarily
long by chaining hash blocks. OpenSSL defaults: C<MD5> hash, C<iteration_count=1>.

  $derived_key = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name, $len);
  #or
  $derived_key = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name);
  #or
  $derived_key = pbkdf1_openssl($password, $salt, $iteration_count);
  #or
  $derived_key = pbkdf1_openssl($password, $salt);

  # $password ......... input keying material (password)
  # $salt ............. salt/nonce (expected length: 8)
  # $iteration_count .. optional, DEFAULT: 5000
  # $hash_name ........ optional, DEFAULT: 'SHA256'
  # $len .............. optional, derived key len, DEFAULT: 32

=head2 pbkdf2

  $derived_key = pbkdf2($password, $salt, $iteration_count, $hash_name, $len);
  #or
  $derived_key = pbkdf2($password, $salt, $iteration_count, $hash_name);
  #or
  $derived_key = pbkdf2($password, $salt, $iteration_count);
  #or
  $derived_key = pbkdf2($password, $salt);

  # $password ......... input keying material (password)
  # $salt ............. salt/nonce
  # $iteration_count .. optional, DEFAULT: 5000
  # $hash_name ........ optional, DEFAULT: 'SHA256'
  # $len .............. optional, derived key len, DEFAULT: 32

=head2 hkdf

  $okm2 = hkdf($password, $salt, $hash_name, $len, $info);
  #or
  $okm2 = hkdf($password, $salt, $hash_name, $len);
  #or
  $okm2 = hkdf($password, $salt, $hash_name);
  #or
  $okm2 = hkdf($password, $salt);

  # $password ... input keying material (password)
  # $salt ....... salt/nonce, if undef defaults to HashLen zero octets
  # $hash_name .. optional, DEFAULT: 'SHA256'
  # $len ........ optional, derived key len, DEFAULT: 32
  # $info ....... optional context and application specific information, DEFAULT: ''

=head2 hkdf_extract

  $prk  = hkdf_extract($password, $salt, $hash_name);
  #or
  $prk  = hkdf_extract($password, $salt, $hash_name);

  # $password ... input keying material (password)
  # $salt ....... salt/nonce, if undef defaults to HashLen zero octets
  # $hash_name .. optional, DEFAULT: 'SHA256'


=head2 hkdf_expand

  $okm = hkdf_expand($pseudokey, $hash_name, $len, $info);
  #or
  $okm = hkdf_expand($pseudokey, $hash_name, $len);
  #or
  $okm = hkdf_expand($pseudokey, $hash_name);
  #or
  $okm = hkdf_expand($pseudokey);

  # $pseudokey .. input keying material
  # $hash_name .. optional, DEFAULT: 'SHA256'
  # $len ........ optional, derived key len, DEFAULT: 32
  # $info ....... optional context and application specific information, DEFAULT: ''

=head2 bcrypt_pbkdf

bcrypt-based key derivation as defined by the OpenBSD project.

I<Since: CryptX-0.100>


  $derived_key = bcrypt_pbkdf($password, $salt, $rounds, $hash_name, $len);
  #or
  $derived_key = bcrypt_pbkdf($password, $salt, $rounds, $hash_name);
  #or
  $derived_key = bcrypt_pbkdf($password, $salt, $rounds);
  #or
  $derived_key = bcrypt_pbkdf($password, $salt);

  # $password ... input keying material (password)
  # $salt ....... salt/nonce
  # $rounds ..... optional, number of rounds, DEFAULT: 16
  # $hash_name .. optional, DEFAULT: 'SHA512'
  # $len ........ optional, derived key len, DEFAULT: 32

=head2 scrypt_pbkdf

scrypt key derivation according to L<https://tools.ietf.org/html/rfc7914>.

I<Since: CryptX-0.100>


  $derived_key = scrypt_pbkdf($password, $salt, $N, $r, $p, $len);
  #or
  $derived_key = scrypt_pbkdf($password, $salt, $N, $r, $p);
  #or
  $derived_key = scrypt_pbkdf($password, $salt, $N);
  #or
  $derived_key = scrypt_pbkdf($password, $salt);

  # $password ... input keying material (password)
  # $salt ....... salt/nonce
  # $N .......... optional, CPU/memory cost parameter (power of 2), DEFAULT: 1024
  # $r .......... optional, block size, DEFAULT: 8
  # $p .......... optional, parallelization parameter, DEFAULT: 1
  # $len ........ optional, derived key len, DEFAULT: 32

=head2 argon2_pbkdf

Argon2 key derivation according to L<https://tools.ietf.org/html/rfc9106>.

I<Since: CryptX-0.100>


  $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len, $secret, $ad);
  #or
  $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len);
  #or
  $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism);
  #or
  $derived_key = argon2_pbkdf($type, $password, $salt);

  # $type        ... one of 'argon2d', 'argon2i', 'argon2id'
  # $password    ... input keying material (password)
  # $salt        ... salt/nonce
  # $t_cost      ... optional, time cost (number of iterations), DEFAULT: 3
  # $m_factor    ... optional, memory cost in kibibytes, DEFAULT: 65536
  # $parallelism ... optional, degree of parallelism, DEFAULT: 1
  # $len         ... optional, derived key len, DEFAULT: 32
  # $secret      ... optional, secret value, DEFAULT: ''
  # $ad          ... optional, associated data, DEFAULT: ''

=cut
