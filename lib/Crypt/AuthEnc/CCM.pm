package Crypt::AuthEnc::CCM;

use strict;
use warnings;
our $VERSION = '0.088_004';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( ccm_encrypt_authenticate ccm_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::CCM - Authenticated encryption in CCM mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::CCM;

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $tag_len = 16;
 my $pt_len = 15;
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::CCM->new("AES", $key, $nonce, $adata, $tag_len, $pt_len);
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 $ct .= $ae_enc->encrypt_add('data3');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::CCM->new("AES", $key, $nonce, $adata, $tag_len, $pt_len);
 my $pt = $ae_dec->decrypt_add('ciphertext1');
 $pt .= $ae_dec->decrypt_add('ciphertext2');
 $pt .= $ae_dec->decrypt_add('ciphertext3');
 my $computed_tag = $ae_dec->decrypt_done();
 die "decrypt failed" unless $computed_tag eq $expected_tag;

 #or
 my $result = $ae_dec->decrypt_done($expected_tag); # 0 or 1

 ### functional interface
 use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $plaintext = '...';
 my $tag_len = 16;

 my ($ciphertext, $tag) = ccm_encrypt_authenticate('AES', $key, $nonce, $adata, $tag_len, $plaintext);
 my $decrypted = ccm_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

CCM is a encrypt+authenticate mode that is centered around using AES (or any 16-byte cipher) as a primitive.
Unlike EAX and OCB mode, it is only meant for packet mode where the length of the input is known in advance.

Use a fresh object per message. The OO constructor requires all per-message parameters
up front: key, nonce, associated data, tag length, and the exact total plaintext/ciphertext
length that will be processed by C<encrypt_add> / C<decrypt_add>. If you have no associated
data in OO mode, pass C<''>.

When verifying, C<decrypt_done($expected_tag)> is the safer form. The no-argument form of
C<decrypt_done> only returns the computed tag.
The first C<encrypt_done> / C<decrypt_done> call finalizes the object. After that,
further C<encrypt_add>, C<decrypt_add>, C<encrypt_done>, and C<decrypt_done>
calls croak.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

 use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

=head1 FUNCTIONS

=head2 ccm_encrypt_authenticate

 my ($ciphertext, $tag) = ccm_encrypt_authenticate($cipher, $key, $nonce, $adata, $tag_len, $plaintext);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] key of proper length (e.g. 128/192/256bits for AES)
 # $nonce ... [binary string] unique nonce/salt (no need to keep it secret)
 # $adata ... [binary string] additional authenticated data (C<undef> is treated the same as C<''>)
 # $tag_len . [integer] required length of output tag

CCM parameters should follow
L<https://csrc.nist.gov/pubs/sp/800/38/c/final>

 # tag length:   4, 6, 8, 10, 12, 14, 16 (reasonable minimum is 8)
 # nonce length: 7, 8, 9, 10, 11, 12, 13 (if you are not sure, use 11)
 # BEWARE nonce length determines max. enc/dec data size: max_data_size = 2^(8*(15-nonce_len))

The functional helper normalizes out-of-range C<$tag_len> values to C<16>.

=head2 ccm_decrypt_verify

 my $plaintext = ccm_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext, $tag);
 # on error returns undef

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::CCM->new($cipher, $key, $nonce, $adata, $pt_len);

=head2 new

 my $ae = Crypt::AuthEnc::CCM->new($cipher, $key, $nonce, $adata, $tag_len, $pt_len);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] key of proper length (e.g. 128/192/256bits for AES)
 # $nonce ... [binary string] unique nonce/salt (no need to keep it secret)
 # $adata ... [binary string] additional authenticated data; must be a defined string scalar, use C<''> if none
 # $tag_len . [integer] tag length in bytes, validated as 1..16
 # $pt_len .. [integer] exact total plaintext/ciphertext length to encrypt/decrypt; must be >= 0

=head2 encrypt_add

Returns a binary string of ciphertext (raw bytes).

 my $ciphertext = $ae->encrypt_add($data);     # can be called multiple times

=head2 encrypt_done

Returns the authentication tag as a binary string (raw bytes).
This call finalizes the current message.

 my $tag = $ae->encrypt_done;                  # returns $tag value

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

=head2 clone

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::EAX|Crypt::AuthEnc::EAX>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://en.wikipedia.org/wiki/CCM_mode|https://en.wikipedia.org/wiki/CCM_mode>

=back

=cut
