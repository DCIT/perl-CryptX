package Crypt::AuthEnc::ChaCha20Poly1305;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::ChaCha20Poly1305 - Authenticated encryption in ChaCha20-Poly1305 mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::ChaCha20Poly1305;

 my $key = '...';
 my $nonce = '...';
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $nonce);
 $ae_enc->adata_add('additional_authenticated_data1');
 $ae_enc->adata_add('additional_authenticated_data2');
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 $ct .= $ae_enc->encrypt_add('data3');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $nonce);
 $ae_dec->adata_add('additional_authenticated_data1');
 $ae_dec->adata_add('additional_authenticated_data2');
 my $pt = $ae_dec->decrypt_add('ciphertext1');
 $pt .= $ae_dec->decrypt_add('ciphertext2');
 $pt .= $ae_dec->decrypt_add('ciphertext3');
 my $computed_tag = $ae_dec->decrypt_done();
 die "decrypt failed" unless $computed_tag eq $expected_tag;

 #or
 my $result = $ae_dec->decrypt_done($expected_tag); # 0 or 1

 ### functional interface
 use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $plaintext = '...';

 my ($ciphertext, $tag) = chacha20poly1305_encrypt_authenticate($key, $nonce, $adata, $plaintext);
 my $decrypted = chacha20poly1305_decrypt_verify($key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

Provides authenticated encryption with ChaCha20-Poly1305 as defined in
L<RFC 7539|https://www.rfc-editor.org/rfc/rfc7539>.

This is a stateful API. Build one message by calling, in order:
C<new> or C<set_iv>, optional C<adata_add>, zero or more C<encrypt_add> or
C<decrypt_add> calls, then C<encrypt_done> or C<decrypt_done>.

Use a fresh object per message. If you construct with C<new($key)> you must
call C<set_iv($iv)> before adding AAD or processing plaintext/ciphertext.
When verifying, C<decrypt_done($expected_tag)> is the safer one-step form;
C<decrypt_done()> without arguments only returns the calculated tag.
The first C<encrypt_done> / C<decrypt_done> call finalizes the object. After that,
further C<set_iv>, C<set_iv_rfc7905>, C<adata_add>, C<encrypt_add>,
C<decrypt_add>, C<encrypt_done>, and C<decrypt_done> calls croak.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

=head1 FUNCTIONS

=head2 chacha20poly1305_encrypt_authenticate

 my ($ciphertext, $tag) = chacha20poly1305_encrypt_authenticate($key, $nonce, $adata, $plaintext);

 # $key ..... [binary string] key of proper length (128 or 256 bits / 16 or 32 bytes)
 # $nonce ... [binary string] nonce (64 or 96 bits / 8 or 12 bytes)
 # $adata ... [binary string] additional authenticated data (optional)

=head2 chacha20poly1305_decrypt_verify

 my $plaintext = chacha20poly1305_decrypt_verify($key, $nonce, $adata, $ciphertext, $tag);
 # on error returns undef

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $nonce);

=head2 new

 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key, $nonce);
 #or
 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key);

 # $key ..... [binary string] encryption key of proper length (128 or 256 bits / 16 or 32 bytes)
 # $nonce ... [binary string] nonce (64 or 96 bits / 8 or 12 bytes)

=head2 adata_add

Add B<additional authenticated data>.
Can be called only before the first C<encrypt_add> or C<decrypt_add>.
Returns the object itself (for chaining).

 $ae->adata_add($aad_data);                     # can be called multiple times

=head2 encrypt_add

Returns a binary string of ciphertext (raw bytes).

 my $ciphertext = $ae->encrypt_add($data);      # can be called multiple times

=head2 encrypt_done

Returns the authentication tag as a binary string (raw bytes).
This call finalizes the current message.

 my $tag = $ae->encrypt_done();                 # returns $tag value

=head2 decrypt_add

Returns a binary string of plaintext (raw bytes).

 my $plaintext = $ae->decrypt_add($ciphertext); # can be called multiple times

=head2 decrypt_done

Without argument returns the computed tag as a binary string. With C<$tag> argument returns C<1> (success) or C<0> (failure).
This call finalizes the current message.

 my $tag = $ae->decrypt_done;           # returns $tag value
 #or
 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)

=head2 set_iv

 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key)->set_iv($nonce);
 # $nonce ... [binary string] nonce (64 or 96 bits / 8 or 12 bytes)

Call C<set_iv> before the first C<adata_add>, C<encrypt_add>, or C<decrypt_add>
for a message.

=head2 set_iv_rfc7905

See L<RFC 7905|https://www.rfc-editor.org/rfc/rfc7905>.

 my $ae = Crypt::AuthEnc::ChaCha20Poly1305->new($key)->set_iv_rfc7905($nonce, $seqnum);
 # $nonce ... [binary string] nonce (96 bits / 12 bytes)
 # $seqnum .. [integer] 64bit integer (sequence number)

=head2 clone

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://www.rfc-editor.org/rfc/rfc7539>

=back

=cut
