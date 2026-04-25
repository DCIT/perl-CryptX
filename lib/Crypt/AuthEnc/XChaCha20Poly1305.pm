package Crypt::AuthEnc::XChaCha20Poly1305;

use strict;
use warnings;
our $VERSION = '0.088_001';

require Exporter; our @ISA = qw(Exporter Crypt::AuthEnc::ChaCha20Poly1305); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( xchacha20poly1305_encrypt_authenticate xchacha20poly1305_decrypt_verify )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::AuthEnc::ChaCha20Poly1305 ();

sub _check_nonce {
  my ($nonce) = @_;
  croak "FATAL: undefined nonce" unless defined $nonce;
  croak "FATAL: nonce must be string/buffer scalar" if ref($nonce);
  croak "FATAL: XChaCha20Poly1305 nonce length must be 24 bytes" unless length($nonce) == 24;
}

sub _check_key {
  my ($key) = @_;
  croak "FATAL: undefined key" unless defined $key;
  croak "FATAL: key must be string/buffer scalar" if ref($key);
  croak "FATAL: XChaCha20Poly1305 key length must be 32 bytes" unless length($key) == 32;
}

sub new {
  my ($class, $key, $nonce) = @_;
  _check_key($key);
  _check_nonce($nonce) if @_ > 2;
  my $self = @_ > 2
           ? Crypt::AuthEnc::ChaCha20Poly1305->new($key, $nonce)
           : Crypt::AuthEnc::ChaCha20Poly1305->new($key);
  return bless $self, $class;
}

sub clone {
  my ($self) = @_;
  return bless Crypt::AuthEnc::ChaCha20Poly1305::clone($self), ref($self) || $self;
}

sub set_iv {
  my ($self, $nonce) = @_;
  _check_nonce($nonce);
  Crypt::AuthEnc::ChaCha20Poly1305::set_iv($self, $nonce);
  return $self;
}

sub xchacha20poly1305_encrypt_authenticate {
  my ($key, $nonce, $adata, $plaintext) = @_;
  _check_key($key);
  _check_nonce($nonce);
  return Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_encrypt_authenticate($key, $nonce, $adata, $plaintext);
}

sub xchacha20poly1305_decrypt_verify {
  my ($key, $nonce, $adata, $ciphertext, $tag) = @_;
  _check_key($key);
  _check_nonce($nonce);
  return Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_decrypt_verify($key, $nonce, $adata, $ciphertext, $tag);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::AuthEnc::XChaCha20Poly1305 - Authenticated encryption in XChaCha20-Poly1305 mode

=head1 SYNOPSIS

 ### OO interface
 use Crypt::AuthEnc::XChaCha20Poly1305;

 my $key = '...';
 my $nonce = '...';
 my $expected_tag = '...';

 # encrypt and authenticate
 my $ae_enc = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
 $ae_enc->adata_add('additional_authenticated_data1');
 $ae_enc->adata_add('additional_authenticated_data2');
 my $ct = $ae_enc->encrypt_add('data1');
 $ct .= $ae_enc->encrypt_add('data2');
 my $tag = $ae_enc->encrypt_done();

 # decrypt and verify
 my $ae_dec = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
 $ae_dec->adata_add('additional_authenticated_data1');
 my $pt = $ae_dec->decrypt_add($ct);
 die "decrypt failed" unless $ae_dec->decrypt_done($tag);

 ### functional interface
 use Crypt::AuthEnc::XChaCha20Poly1305 qw(
   xchacha20poly1305_encrypt_authenticate
   xchacha20poly1305_decrypt_verify
 );

 my $key = '...';
 my $nonce = '...';
 my $adata = '...';
 my $plaintext = '...';

 my ($ciphertext, $tag) = xchacha20poly1305_encrypt_authenticate($key, $nonce, $adata, $plaintext);
 my $decrypted = xchacha20poly1305_decrypt_verify($key, $nonce, $adata, $ciphertext, $tag);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides encryption and authentication based on XChaCha20 + Poly1305 using
the extended 192-bit (24-byte) nonce variant of ChaCha20-Poly1305.

This is a stateful API. Build one message by calling, in order:
C<new> or C<set_iv>, optional C<adata_add>, zero or more C<encrypt_add> or
C<decrypt_add> calls, then C<encrypt_done> or C<decrypt_done>.

Use a fresh object per message. If you construct with C<new($key)> you must
call C<set_iv($nonce)> before adding AAD or processing plaintext/ciphertext.
When verifying, C<decrypt_done($expected_tag)> is the safer one-step form;
C<decrypt_done()> without arguments only returns the calculated tag.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::AuthEnc::XChaCha20Poly1305 qw(
    xchacha20poly1305_encrypt_authenticate
    xchacha20poly1305_decrypt_verify
  );

=head1 FUNCTIONS

=head2 xchacha20poly1305_encrypt_authenticate

I<Since: CryptX-0.100>

 my ($ciphertext, $tag) = xchacha20poly1305_encrypt_authenticate($key, $nonce, $adata, $plaintext);

 # $key ..... [binary string] encryption key (256 bits / 32 bytes)
 # $nonce ... [binary string] extended nonce (192 bits / 24 bytes)
 # $adata ... [binary string] additional authenticated data (optional)

Invalid key or nonce lengths croak.

=head2 xchacha20poly1305_decrypt_verify

I<Since: CryptX-0.100>

 my $plaintext = xchacha20poly1305_decrypt_verify($key, $nonce, $adata, $ciphertext, $tag);
 # on error returns undef

Invalid key or nonce lengths croak.

=head1 METHODS

Unless noted otherwise, assume C<$ae> is an existing AEAD object created via
C<new>, for example:

 my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);

=head2 new

I<Since: CryptX-0.100>

 my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
 my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key);

 # $key ..... [binary string] encryption key (256 bits / 32 bytes)
 # $nonce ... [binary string] extended nonce (192 bits / 24 bytes)

=head2 adata_add

I<Since: CryptX-0.100>

Add B<additional authenticated data>.
Can be called only before the first C<encrypt_add> or C<decrypt_add>.
Returns the object itself (for chaining).

 $ae->adata_add($aad_data);                     # can be called multiple times

=head2 encrypt_add

I<Since: CryptX-0.100>

Returns a binary string of ciphertext (raw bytes).

 my $ciphertext = $ae->encrypt_add($data);      # can be called multiple times

=head2 encrypt_done

I<Since: CryptX-0.100>

Returns the authentication tag as a binary string (raw bytes).

 my $tag = $ae->encrypt_done();                 # returns $tag value

=head2 decrypt_add

I<Since: CryptX-0.100>

Returns a binary string of plaintext (raw bytes).

 my $plaintext = $ae->decrypt_add($ciphertext); # can be called multiple times

=head2 decrypt_done

I<Since: CryptX-0.100>

Without argument returns the computed tag as a binary string. With C<$tag> argument returns C<1> (success) or C<0> (failure).

 my $tag = $ae->decrypt_done;           # returns $tag value
 #or
 my $result = $ae->decrypt_done($tag);  # returns 1 (success) or 0 (failure)

=head2 set_iv

I<Since: CryptX-0.100>

 my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key)->set_iv($nonce);
 # $nonce ... [binary string] extended nonce (192 bits / 24 bytes)

Call C<set_iv> before the first C<adata_add>, C<encrypt_add>, or C<decrypt_add>
for a message.

=head2 clone

I<Since: CryptX-0.100>

Returns a copy of the AEAD object in its current state.

 my $ae_new = $ae->clone;

=head1 SEE ALSO

=over

=item * L<Crypt::AuthEnc::ChaCha20Poly1305>, L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::CCM>

=item * L<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>

=back

=cut
