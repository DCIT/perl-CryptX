package Crypt::KeyDerivation;

use strict;
use warnings;
our $VERSION = '0.088_005';

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

  my $password = 'secret';
  my $salt = '12345678';
  my $iteration_count = 5000;
  my $hash_name = 'SHA256';
  my $len = 32;
  my $keying_material = 'input keying material';
  my $info = 'context';
  my $rounds = 16;
  my $N = 1024;
  my $r = 8;
  my $p = 1;
  my $type = 'argon2id';
  my $t_cost = 3;
  my $m_factor = 65536;
  my $parallelism = 1;
  my $secret = '';
  my $ad = '';

  ### PBKDF1/2
  my $pbkdf1_key = pbkdf1($password, $salt, $iteration_count, $hash_name, $len);
  my $openssl_pbkdf1_key = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name, $len);
  my $pbkdf2_key = pbkdf2($password, $salt, $iteration_count, $hash_name, $len);

  ### HKDF & co.
  my $hkdf_okm = hkdf($keying_material, $salt, $hash_name, $len, $info);
  my $prk = hkdf_extract($keying_material, $salt, $hash_name);
  my $expanded_okm = hkdf_expand($prk, $hash_name, $len, $info);

  ### bcrypt / scrypt / argon2
  my $bcrypt_key = bcrypt_pbkdf($password, $salt, $rounds, $hash_name, $len);
  my $scrypt_key = scrypt_pbkdf($password, $salt, $N, $r, $p, $len);
  my $argon2_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len, $secret, $ad);

=head1 DESCRIPTION

Provides an interface to key derivation functions:

=over

=item * PBKDF1 and PBKDF2 according to PKCS #5 v2.0
L<https://www.rfc-editor.org/rfc/rfc2898>

=item * HKDF (+ related) according to
L<https://www.rfc-editor.org/rfc/rfc5869>

=item * Bcrypt-PBKDF as defined by the OpenBSD project

=item * Scrypt according to L<https://www.rfc-editor.org/rfc/rfc7914>

=item * Argon2 according to L<https://www.rfc-editor.org/rfc/rfc9106>

=back

While primarily designed for key derivation, the functions PBKDF2, Bcrypt, Scrypt and Argon2
are also widely used for password hashing. In that use case the derived key serves as the
stored password hash.

All functions return raw bytes. Passing an output length of C<0> returns an
empty string in this wrapper API. Argument validation still happens first:
required password / input-keying-material arguments reject C<undef>, invalid
hash names and invalid Argon2 type names are still rejected, and malformed
optional scalar arguments still return C<undef> where applicable.

This zero-length behaviour is a C<Crypt::KeyDerivation> wrapper policy. The
underlying libtomcrypt functions do not all behave the same way: some accept
zero-length outputs, while others reject them with algorithm-specific checks.
Code calling libtomcrypt directly should not assume the wrapper behaviour.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::KeyDerivation qw(
    pbkdf1 pbkdf1_openssl pbkdf2
    hkdf hkdf_expand hkdf_extract
    bcrypt_pbkdf scrypt_pbkdf argon2_pbkdf
  );

Or all of them at once:

  use Crypt::KeyDerivation ':all';

=head1 FUNCTIONS

=head2 pbkdf1

B<BEWARE:> If you are not sure, do not use C<pbkdf1> - choose C<pbkdf2> instead.

  my $derived_key = pbkdf1($password, $salt, $iteration_count, $hash_name, $len);
  #or
  my $derived_key = pbkdf1($password, $salt, $iteration_count, $hash_name);
  #or
  my $derived_key = pbkdf1($password, $salt, $iteration_count);
  #or
  my $derived_key = pbkdf1($password, $salt);

  # $password ......... [binary string] input keying material (password)
  # $salt ............. [binary string] salt/nonce (expected length: 8 bytes)
  # $iteration_count .. [integer] optional, DEFAULT: 5000
  # $hash_name ........ [string]  optional, DEFAULT: 'SHA256'
  # $len .............. [integer] optional, derived key len in bytes, DEFAULT: 32

In strict PKCS #5 v1 mode, the derived key length must not exceed the selected
hash output size. For example, C<SHA1> allows at most 20 bytes.

The underlying algorithm uses only the first 8 bytes of C<$salt>. Shorter salts
are rejected; longer salts are accepted but truncated to 8 bytes.

=head2 pbkdf1_openssl

I<Since: CryptX-0.088>

OpenSSL-compatible variant of PBKDF1 (implements C<EVP_BytesToKey>). Unlike strict
C<pbkdf1>, the output length is not limited to the hash size -- it can be arbitrarily
long by chaining hash blocks.

B<Important:> this function implements the OpenSSL-compatible algorithm, but its
default parameters do B<not> match the historical C<openssl enc> defaults.
OpenSSL traditionally uses C<MD5> and C<iteration_count=1>, while this wrapper
defaults to C<SHA256> and C<5000>. If you need output compatible with the
traditional OpenSSL default behaviour, pass both values explicitly:

  my $derived_key = pbkdf1_openssl($password, $salt, 1, 'MD5', $len);

  my $derived_key = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name, $len);
  #or
  my $derived_key = pbkdf1_openssl($password, $salt, $iteration_count, $hash_name);
  #or
  my $derived_key = pbkdf1_openssl($password, $salt, $iteration_count);
  #or
  my $derived_key = pbkdf1_openssl($password, $salt);

  # $password ......... [binary string] input keying material (password)
  # $salt ............. [binary string] salt/nonce (expected length: 8 bytes)
  # $iteration_count .. [integer] optional, DEFAULT: 5000
  # $hash_name ........ [string]  optional, DEFAULT: 'SHA256'
  # $len .............. [integer] optional, derived key len in bytes, DEFAULT: 32

The underlying algorithm uses only the first 8 bytes of C<$salt>. Shorter salts
are rejected; longer salts are accepted but truncated to 8 bytes.

=head2 pbkdf2

  my $derived_key = pbkdf2($password, $salt, $iteration_count, $hash_name, $len);
  #or
  my $derived_key = pbkdf2($password, $salt, $iteration_count, $hash_name);
  #or
  my $derived_key = pbkdf2($password, $salt, $iteration_count);
  #or
  my $derived_key = pbkdf2($password, $salt);

  # $password ......... [binary string] input keying material (password)
  # $salt ............. [binary string] salt/nonce (any length; longer is better)
  # $iteration_count .. [integer] optional, DEFAULT: 5000
  # $hash_name ........ [string]  optional, DEFAULT: 'SHA256'
  # $len .............. [integer] optional, derived key len in bytes, DEFAULT: 32

=head2 hkdf

  my $okm = hkdf($password, $salt, $hash_name, $len, $info);
  #or
  my $okm = hkdf($password, $salt, $hash_name, $len);
  #or
  my $okm = hkdf($password, $salt, $hash_name);
  #or
  my $okm = hkdf($password, $salt);

  # $password ... [binary string] input keying material
  # $salt ....... [binary string | undef] salt; if undef defaults to HashLen zero octets
  # $hash_name .. [string]  optional, DEFAULT: 'SHA256'
  # $len ........ [integer] optional, derived key len in bytes, DEFAULT: 32
  # $info ....... [binary string] optional context/application info, DEFAULT: ''

Use C<hkdf> for one-shot extract+expand. For multi-step workflows, use
C<hkdf_extract> followed by C<hkdf_expand>.

The input keying material / pseudokey arguments must be string or
stringifiable scalars. Optional C<$salt> and C<$info> may be C<undef>.

=head2 hkdf_extract

  my $prk = hkdf_extract($password, $salt, $hash_name);
  #or
  my $prk = hkdf_extract($password, $salt);

  # $password ... [binary string] input keying material
  # $salt ....... [binary string | undef] salt; if undef defaults to HashLen zero octets
  # $hash_name .. [string]  optional, DEFAULT: 'SHA256'

Returns the pseudorandom key (PRK). Its length is the digest size of the
selected hash and it is intended to be passed to C<hkdf_expand>.


=head2 hkdf_expand

  my $okm = hkdf_expand($pseudokey, $hash_name, $len, $info);
  #or
  my $okm = hkdf_expand($pseudokey, $hash_name, $len);
  #or
  my $okm = hkdf_expand($pseudokey, $hash_name);
  #or
  my $okm = hkdf_expand($pseudokey);

  # $pseudokey .. [binary string] input keying material (normally from hkdf_extract)
  # $hash_name .. [string]  optional, DEFAULT: 'SHA256'
  # $len ........ [integer] optional, derived key len in bytes, DEFAULT: 32
  # $info ....... [binary string] optional context/application info, DEFAULT: ''

C<$pseudokey> is normally the PRK returned by C<hkdf_extract>.

=head2 bcrypt_pbkdf

bcrypt-based key derivation as defined by the OpenBSD project.

I<Since: CryptX-0.088>


  my $derived_key = bcrypt_pbkdf($password, $salt, $rounds, $hash_name, $len);
  #or
  my $derived_key = bcrypt_pbkdf($password, $salt, $rounds, $hash_name);
  #or
  my $derived_key = bcrypt_pbkdf($password, $salt, $rounds);
  #or
  my $derived_key = bcrypt_pbkdf($password, $salt);

  # $password ... [binary string] input keying material (password)
  # $salt ....... [binary string] salt/nonce
  # $rounds ..... [integer] optional, number of rounds, DEFAULT: 16
  # $hash_name .. [string]  optional, DEFAULT: 'SHA512'
  # $len ........ [integer] optional, derived key len in bytes, DEFAULT: 32

Larger C<$rounds> values increase CPU cost linearly.

=head2 scrypt_pbkdf

scrypt key derivation according to L<https://www.rfc-editor.org/rfc/rfc7914>.

I<Since: CryptX-0.088>


  my $derived_key = scrypt_pbkdf($password, $salt, $N, $r, $p, $len);
  #or
  my $derived_key = scrypt_pbkdf($password, $salt, $N, $r, $p);
  #or
  my $derived_key = scrypt_pbkdf($password, $salt, $N);
  #or
  my $derived_key = scrypt_pbkdf($password, $salt);

  # $password ... [binary string] input keying material (password)
  # $salt ....... [binary string] salt/nonce
  # $N .......... [integer] optional, CPU/memory cost (must be power of 2), DEFAULT: 1024
  # $r .......... [integer] optional, block size, DEFAULT: 8
  # $p .......... [integer] optional, parallelization parameter, DEFAULT: 1
  # $len ........ [integer] optional, derived key len in bytes, DEFAULT: 32

Use only power-of-two values for C<$N>. Larger C<$N>, C<$r>, and C<$p>
increase resource usage substantially; invalid combinations croak.

=head2 argon2_pbkdf

Argon2 key derivation according to L<https://www.rfc-editor.org/rfc/rfc9106>.

I<Since: CryptX-0.088>


  my $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len, $secret, $ad);
  #or
  my $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism, $len);
  #or
  my $derived_key = argon2_pbkdf($type, $password, $salt, $t_cost, $m_factor, $parallelism);
  #or
  my $derived_key = argon2_pbkdf($type, $password, $salt);

  # $type        ... [string]  one of 'argon2d', 'argon2i', 'argon2id'
  # $password    ... [binary string] input keying material (password)
  # $salt        ... [binary string] salt/nonce (recommended: at least 16 bytes)
  # $t_cost      ... [integer] optional, time cost (number of iterations), DEFAULT: 3
  # $m_factor    ... [integer] optional, memory cost in kibibytes (1 KiB = 1024 B), DEFAULT: 65536 (= 64 MiB)
  # $parallelism ... [integer] optional, degree of parallelism, DEFAULT: 1
  # $len         ... [integer] optional, derived key len in bytes, DEFAULT: 32
  # $secret      ... [binary string] optional, secret value, DEFAULT: ''
  # $ad          ... [binary string] optional, associated data, DEFAULT: ''

Increasing C<$t_cost>, C<$m_factor>, or C<$parallelism> increases work and
memory requirements. Invalid combinations croak. Optional C<$secret> and
C<$ad> may be C<undef>; otherwise they must be string or stringifiable scalars.

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * L<Crypt::Digest>, L<Crypt::Mac>, L<Crypt::PRNG>

=item * L<https://www.rfc-editor.org/rfc/rfc2898>

=item * L<https://www.rfc-editor.org/rfc/rfc5869>

=item * L<https://www.rfc-editor.org/rfc/rfc7914>

=item * L<https://www.rfc-editor.org/rfc/rfc9106>

=back

=cut
