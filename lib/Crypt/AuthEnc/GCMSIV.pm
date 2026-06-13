package Crypt::AuthEnc::GCMSIV;

use strict;
use warnings;
our $VERSION = '0.090';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( gcm_siv_encrypt_authenticate gcm_siv_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

1;

=pod

=head1 NAME

Crypt::AuthEnc::GCMSIV - Authenticated encryption in AES-GCM-SIV mode (RFC 8452)

=head1 SYNOPSIS

  use Crypt::AuthEnc::GCMSIV qw( gcm_siv_encrypt_authenticate gcm_siv_decrypt_verify );

  my $ciphertext = gcm_siv_encrypt_authenticate('AES', $key, $nonce, $adata, $plaintext);
  my $plaintext  = gcm_siv_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext); # undef on failure

=head1 DESCRIPTION

I<Since: CryptX-0.090>

AES-GCM-SIV is a nonce-misuse-resistant authenticated encryption scheme defined in
L<RFC 8452|https://www.rfc-editor.org/rfc/rfc8452>. Reusing a nonce with the same key
no longer reveals the plaintext or the authentication key; it only reveals whether
the same (plaintext, AAD) pair was encrypted twice.

The output of C<gcm_siv_encrypt_authenticate> is the ciphertext with a 16-byte
authentication tag appended (total output length is C<length($plaintext) + 16>).

GCM-SIV is defined only for 128-bit block ciphers (i.e. AES); the nonce must be
exactly 12 bytes long and the key must be 16 or 32 bytes (AES-128 / AES-256).

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::GCMSIV qw( gcm_siv_encrypt_authenticate gcm_siv_decrypt_verify );

=head1 FUNCTIONS

=head2 gcm_siv_encrypt_authenticate

  my $ciphertext = gcm_siv_encrypt_authenticate($cipher, $key, $nonce, $adata, $plaintext);

  # $cipher    ... [string] cipher name (must be 'AES')
  # $key       ... [binary string] 16- or 32-byte key
  # $nonce     ... [binary string] 12-byte nonce
  # $adata     ... [binary string | undef] optional associated data
  # $plaintext ... [binary string] plaintext to encrypt

Returns a string of C<length($plaintext) + 16> bytes: ciphertext followed by the
16-byte authentication tag.

The required string/buffer arguments must be plain scalars; C<$adata> may be
C<undef> to indicate no associated data. String-overloaded objects are accepted.

=head2 gcm_siv_decrypt_verify

  my $plaintext = gcm_siv_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext);

  # $cipher     ... [string] cipher name (must be 'AES')
  # $key        ... [binary string] 16- or 32-byte key
  # $nonce      ... [binary string] 12-byte nonce
  # $adata      ... [binary string | undef] optional associated data (must match the value used during encryption)
  # $ciphertext ... [binary string] ciphertext with 16-byte tag appended

Returns the plaintext on success, or C<undef> if authentication fails.
Malformed input shorter than 16 bytes croaks because it cannot contain the
required appended tag.

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::SIV>

=item * L<RFC 8452|https://www.rfc-editor.org/rfc/rfc8452>

=back

=cut
