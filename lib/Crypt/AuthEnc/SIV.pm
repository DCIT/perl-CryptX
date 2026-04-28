package Crypt::AuthEnc::SIV;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( siv_encrypt_authenticate siv_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

1;

=pod

=head1 NAME

Crypt::AuthEnc::SIV - Authenticated encryption in SIV mode

=head1 SYNOPSIS

  use Crypt::AuthEnc::SIV qw( siv_encrypt_authenticate siv_decrypt_verify );

  my $ciphertext = siv_encrypt_authenticate('AES', $key, $plaintext);
  my $ciphertext = siv_encrypt_authenticate('AES', $key, $plaintext, $adata);
  my $ciphertext = siv_encrypt_authenticate('AES', $key, $plaintext, [$ad1, $ad2, ...]);

  my $plaintext = siv_decrypt_verify('AES', $key, $ciphertext);
  my $plaintext = siv_decrypt_verify('AES', $key, $ciphertext, $adata);
  my $plaintext = siv_decrypt_verify('AES', $key, $ciphertext, [$ad1, $ad2, ...]); # undef on failure

=head1 DESCRIPTION

I<Since: CryptX-0.100>

SIV (Synthetic IV) is a deterministic authenticated encryption scheme defined in
L<RFC 5297|https://www.rfc-editor.org/rfc/rfc5297>. Unlike nonce-based modes, SIV derives
the authentication tag (the IV) synthetically from the key, associated data, and plaintext,
making it nonce-misuse resistant.

The output of C<siv_encrypt_authenticate> is the 16-byte SIV tag prepended to the ciphertext
(total output length is C<length($plaintext) + 16>).

B<BEWARE:> SIV requires a key that is twice the length of the underlying cipher key
(e.g. 256 bits for AES-128-SIV, 512 bits for AES-256-SIV).

If you pass associated data as an arrayref, at most 126 components are accepted.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::SIV qw( siv_encrypt_authenticate siv_decrypt_verify );

=head1 FUNCTIONS

=head2 siv_encrypt_authenticate

  my $ciphertext = siv_encrypt_authenticate($cipher, $key, $plaintext);
  #or
  my $ciphertext = siv_encrypt_authenticate($cipher, $key, $plaintext, $adata);
  #or
  my $ciphertext = siv_encrypt_authenticate($cipher, $key, $plaintext, [$ad1, $ad2, ...]);

  # $cipher    ... [string] cipher name (e.g. 'AES')
  # $key       ... [binary string] key (must be double the cipher's standard key length)
  # $plaintext ... [binary string] plaintext to encrypt
  # $adata     ... [binary string | arrayref] optional associated data: a scalar string or an arrayref of up to 126 string/buffer scalars

Returns a string of C<length($plaintext) + 16> bytes (16-byte SIV tag prepended to ciphertext).

The required C<$key> and C<$plaintext> arguments must be string/buffer scalars.
If C<$adata> is given as a scalar, it must also be a string/buffer scalar. If
it is given as an arrayref, each defined element must be a string/buffer scalar.
String-overloaded objects are accepted.

=head2 siv_decrypt_verify

  my $plaintext = siv_decrypt_verify($cipher, $key, $ciphertext);
  #or
  my $plaintext = siv_decrypt_verify($cipher, $key, $ciphertext, $adata);
  #or
  my $plaintext = siv_decrypt_verify($cipher, $key, $ciphertext, [$ad1, $ad2, ...]);

  # $cipher     ... [string] cipher name (e.g. 'AES')
  # $key        ... [binary string] key (must be double the cipher's standard key length)
  # $ciphertext ... [binary string] ciphertext with 16-byte SIV tag prepended
  # $adata      ... [binary string | arrayref] optional associated data: a scalar string or an arrayref of up to 126 string/buffer scalars

Returns the plaintext on success, or C<undef> if authentication fails.
Malformed ciphertext shorter than 16 bytes croaks because it cannot contain the required
prepended SIV tag.

The required C<$key> and C<$ciphertext> arguments must be string/buffer
scalars. If C<$adata> is given as a scalar, it must also be a
string/buffer scalar. If it is given as an arrayref, each defined element
must be a string/buffer scalar. String-overloaded objects are accepted.

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>

=item * L<RFC 5297|https://www.rfc-editor.org/rfc/rfc5297>

=back

=cut
