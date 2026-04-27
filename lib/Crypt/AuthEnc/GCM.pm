package Crypt::AuthEnc::GCM;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( gcm_encrypt_authenticate gcm_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::GCM - Authenticated encryption in GCM mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::GCM;

 my $key = '...';
 my $iv = '...';
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::GCM->new("AES", $key, $iv);
 $ae_enc->adata_add('additional_authenticated_data1');
 $ae_enc->adata_add('additional_authenticated_data2');
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 $ct .= $ae_enc->encrypt_add('data3');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::GCM->new("AES", $key, $iv);
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
 use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

 my $key = '...';
 my $iv = '...';
 my $adata = '...';
 my $plaintext = '...';

 my ($ciphertext, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, $adata, $plaintext);
 my $decrypted = gcm_decrypt_verify('AES', $key, $iv, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

Galois/Counter Mode (GCM) - provides encryption and authentication.

Use a fresh object per message unless you intentionally reuse the same key via C<reset>.
The normal call order is: C<new>, one or more C<iv_add> calls, optional C<adata_add> calls,
zero or more C<encrypt_add> / C<decrypt_add> calls, then C<encrypt_done> / C<decrypt_done>.
The first C<encrypt_done> / C<decrypt_done> call finalizes the object. After that,
further C<iv_add>, C<adata_add>, C<encrypt_add>, C<decrypt_add>, C<encrypt_done>,
and C<decrypt_done> calls croak until you call C<reset>.

If you construct with C<new($cipher, $key)>, you must provide the IV via C<iv_add> before
adding authenticated data or payload data. After C<reset>, start a new message with the same
key by supplying the IV again, and re-add AAD if needed.

When verifying, C<decrypt_done($expected_tag)> is the safer form. The no-argument form of
C<decrypt_done> only returns the computed tag.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

=head1 FUNCTIONS

=head2 gcm_encrypt_authenticate

 my ($ciphertext, $tag) = gcm_encrypt_authenticate($cipher, $key, $iv, $adata, $plaintext);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] AES key of proper length (128/192/256bits)
 # $iv ...... [binary string] initialization vector
 # $adata ... [binary string] additional authenticated data

=head2 gcm_decrypt_verify

 my $plaintext = gcm_decrypt_verify($cipher, $key, $iv, $adata, $ciphertext, $tag);
 # on error returns undef

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::GCM->new($cipher, $key, $iv);

=head2 new

 my $ae = Crypt::AuthEnc::GCM->new($cipher, $key);
 #or
 my $ae = Crypt::AuthEnc::GCM->new($cipher, $key, $iv);

 # $cipher .. [string] 'AES' or name of any other cipher
 # $key ..... [binary string] encryption key of proper length
 # $iv ...... [binary string] initialization vector (optional, you can set it later via iv_add method)

=head2 iv_add

Set initialization vector (IV). Multiple calls are concatenated to form the
full IV (the data is appended, not replaced). Returns the object itself.

 $ae->iv_add($iv_data);                        # can be called multiple times before AAD/payload

Call C<iv_add> before the first C<adata_add>, C<encrypt_add>, or C<decrypt_add>. If you
reuse the object via C<reset>, provide the IV again for the new message.

=head2 adata_add

Add B<additional authenticated data>.
Can be called B<after> all C<iv_add> calls but before the first C<encrypt_add> or C<decrypt_add>.
Returns the object itself (for chaining).

 $ae->adata_add($aad_data);                    # can be called multiple times

=head2 encrypt_add

Returns a binary string of ciphertext (raw bytes).

 my $ciphertext = $ae->encrypt_add($data);     # can be called multiple times

=head2 encrypt_done

Returns the authentication tag as a binary string (raw bytes).
This call finalizes the current message.

 my $tag = $ae->encrypt_done();                # returns $tag value

=head2 decrypt_add

Returns a binary string of plaintext (raw bytes).

 my $plaintext = $ae->decrypt_add($ciphertext); # can be called multiple times

=head2 decrypt_done

Without argument returns the computed tag as a binary string. With C<$tag> argument returns C<1> (success) or C<0> (failure).
This call finalizes the current message.

 my $tag = $ae->decrypt_done;           # returns $tag value
 #or
 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)

Use the C<decrypt_done($tag)> form for authentication checks. The no-argument form only
returns the computed tag.

=head2 reset

 $ae->reset;

Start a new message with the same key. After C<reset>, call C<iv_add> again, then
C<adata_add> if needed, before processing payload data. C<reset> also clears the
finalized state set by C<encrypt_done> / C<decrypt_done>.

=head2 clone

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://en.wikipedia.org/wiki/Galois/Counter_Mode>

=item * L<https://csrc.nist.gov/pubs/sp/800/38/d/final>

=back

=cut
