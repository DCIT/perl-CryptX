package Crypt::AuthEnc::OCB;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( ocb_encrypt_authenticate ocb_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

# obsolete, only for backwards compatibility
sub aad_add { goto &adata_add }
sub blocksize { return 16 }

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::OCB - Authenticated encryption in OCBv3 mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::OCB;

 my $key = '...';
 my $nonce = '...';
 my $tag_len = 16;
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::OCB->new("AES", $key, $nonce, $tag_len);
 $ae_enc->adata_add('additional_authenticated_data1');
 $ae_enc->adata_add('additional_authenticated_data2');
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 $ct .= $ae_enc->encrypt_add('data3');
 $ct .= $ae_enc->encrypt_last('rest of data');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::OCB->new("AES", $key, $nonce, $tag_len);
 $ae_dec->adata_add('additional_authenticated_data1');
 $ae_dec->adata_add('additional_authenticated_data2');
 my $pt = $ae_dec->decrypt_add('ciphertext1');
 $pt .= $ae_dec->decrypt_add('ciphertext2');
 $pt .= $ae_dec->decrypt_add('ciphertext3');
 $pt .= $ae_dec->decrypt_last('rest of data');
 my $computed_tag = $ae_dec->decrypt_done();
 die "decrypt failed" unless $computed_tag eq $expected_tag;

 #or
 my $result = $ae_dec->decrypt_done($expected_tag); # 0 or 1

 ### functional interface
 use Crypt::AuthEnc::OCB qw(ocb_encrypt_authenticate ocb_decrypt_verify);

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $plaintext = '...';
 my $tag_len = 16;

 my ($ciphertext, $tag) = ocb_encrypt_authenticate('AES', $key, $nonce, $adata, $tag_len, $plaintext);
 my $decrypted = ocb_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

This module implements OCB v3 according to
L<https://www.rfc-editor.org/rfc/rfc7253>.

This is a stateful API. Build one message by calling, in order:
C<new>, optional C<adata_add>, zero or more C<encrypt_add> or C<decrypt_add>
calls for full blocks, one optional C<encrypt_last> or C<decrypt_last> for the
final partial block, then C<encrypt_done> or C<decrypt_done>.

Use a fresh object per message. When verifying, C<decrypt_done($expected_tag)>
is the safer one-step form; C<decrypt_done()> without arguments only returns
the calculated tag.
The first C<encrypt_done> / C<decrypt_done> call finalizes the object. After that,
further C<adata_add>, C<encrypt_add>, C<encrypt_last>, C<decrypt_add>,
C<decrypt_last>, C<encrypt_done>, and C<decrypt_done> calls croak.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::OCB qw(ocb_encrypt_authenticate ocb_decrypt_verify);

=head1 FUNCTIONS

=head2 ocb_encrypt_authenticate

 my ($ciphertext, $tag) = ocb_encrypt_authenticate($cipher, $key, $nonce, $adata, $tag_len, $plaintext);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] AES key of proper length (128/192/256bits)
 # $nonce ... [binary string] unique nonce/salt (no need to keep it secret)
 # $adata ... [binary string] additional authenticated data
 # $tag_len . [integer] required length of output tag

Use tag lengths from 4 to 16 bytes. Out-of-range values passed to this
functional helper are normalized to 16.

=head2 ocb_decrypt_verify

  my $plaintext = ocb_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext, $tag);
  # on error returns undef

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::OCB->new($cipher, $key, $nonce);

=head2 new

 my $ae = Crypt::AuthEnc::OCB->new($cipher, $key, $nonce, $tag_len);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] AES key of proper length (128/192/256bits)
 # $nonce ... [binary string] unique nonce/salt (no need to keep it secret)
 # $tag_len . [integer] required length of output tag

=head2 adata_add

Can be called only before the first C<encrypt_add>, C<encrypt_last>,
C<decrypt_add>, or C<decrypt_last>.
Returns the object itself (for chaining).

 $ae->adata_add($adata);                        #can be called multiple times

=head2 encrypt_add

Returns a binary string of ciphertext (raw bytes).

 my $ciphertext = $ae->encrypt_add($data);      # can be called multiple times

 #BEWARE: size of $data has to be multiple of blocklen (16 for AES)

=head2 encrypt_last

 my $ciphertext = $ae->encrypt_last($data);

=head2 encrypt_done

Returns the authentication tag as a binary string (raw bytes).
This call finalizes the current message.

 my $tag = $ae->encrypt_done();                 # returns $tag value

=head2 decrypt_add

Returns a binary string of plaintext (raw bytes).

 my $plaintext = $ae->decrypt_add($ciphertext); # can be called multiple times

 #BEWARE: size of $ciphertext has to be multiple of blocklen (16 for AES)

=head2 decrypt_last

 my $plaintext = $ae->decrypt_last($data);

=head2 decrypt_done

Without argument returns the computed tag as a binary string. With C<$tag> argument returns C<1> (success) or C<0> (failure).
This call finalizes the current message.

 my $tag = $ae->decrypt_done;           # returns $tag value
 #or
 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)

=head2 blocksize

 my $bs = $ae->blocksize;   # always returns 16

Returns the block size of the underlying cipher (always 16, since OCB requires
a 128-bit block cipher such as AES).

=head2 clone

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>

=item * L<https://en.wikipedia.org/wiki/OCB_mode>

=item * L<https://www.rfc-editor.org/rfc/rfc7253>

=back

=cut
