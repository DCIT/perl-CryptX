package Crypt::AuthEnc::EAX;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( eax_encrypt_authenticate eax_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

# obsolete, only for backwards compatibility
sub header_add { goto &adata_add }
sub aad_add    { goto &adata_add }

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::EAX - Authenticated encryption in EAX mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::EAX;

 my $key = '...';
 my $nonce = '...';
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
 $ae_enc->adata_add('additional_authenticated_data1');
 $ae_enc->adata_add('additional_authenticated_data2');
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 $ct .= $ae_enc->encrypt_add('data3');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
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
 use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $plaintext = '...';

 my ($ciphertext, $tag) = eax_encrypt_authenticate('AES', $key, $nonce, $adata, $plaintext);
 my $decrypted = eax_decrypt_verify('AES', $key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

EAX is a mode that requires a cipher, CTR and OMAC support and provides encryption and authentication.
It is initialized with a random IV that can be shared publicly, additional authenticated data which can
be fixed and public, and a random secret symmetric key.

This is a stateful API. Build one message by calling, in order:
C<new>, optional extra C<adata_add>, zero or more C<encrypt_add> or
C<decrypt_add> calls, then C<encrypt_done> or C<decrypt_done>.

Use a fresh object per message. The optional C<$adata> argument to C<new> is
equivalent to adding initial AAD before processing any payload. When verifying,
C<decrypt_done($expected_tag)> is the safer one-step form; C<decrypt_done()>
without arguments only returns the calculated tag.
The first C<encrypt_done> / C<decrypt_done> call finalizes the object. After that,
further C<adata_add>, C<encrypt_add>, C<decrypt_add>, C<encrypt_done>, and
C<decrypt_done> calls croak.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);

=head1 FUNCTIONS

=head2 eax_encrypt_authenticate

 my ($ciphertext, $tag) = eax_encrypt_authenticate($cipher, $key, $nonce, $adata, $plaintext);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] AES key of proper length (128/192/256bits)
 # $nonce ... [binary string] unique nonce (no need to keep it secret)
 # $adata ... [binary string] additional authenticated data

=head2 eax_decrypt_verify

 my $plaintext = eax_decrypt_verify($cipher, $key, $nonce, $adata, $ciphertext, $tag);
 # on error returns undef

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::EAX->new($cipher, $key, $nonce);

=head2 new

 my $ae = Crypt::AuthEnc::EAX->new($cipher, $key, $nonce);
 #or
 my $ae = Crypt::AuthEnc::EAX->new($cipher, $key, $nonce, $adata);

 # $cipher .. [string] 'AES' or name of any other cipher with 16-byte block len
 # $key ..... [binary string] AES key of proper length (128/192/256bits)
 # $nonce ... [binary string] unique nonce (no need to keep it secret)
 # $adata ... [binary string] additional authenticated data (optional)

=head2 adata_add

Can be called only before the first C<encrypt_add> or C<decrypt_add>.
Returns the object itself (for chaining).

 $ae->adata_add($adata);                        # can be called multiple times

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

=head2 clone

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::AuthEnc::CCM|Crypt::AuthEnc::CCM>, L<Crypt::AuthEnc::GCM|Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::OCB|Crypt::AuthEnc::OCB>

=item * L<https://en.wikipedia.org/wiki/EAX_mode|https://en.wikipedia.org/wiki/EAX_mode>

=item * L<https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf>

=back

=cut
