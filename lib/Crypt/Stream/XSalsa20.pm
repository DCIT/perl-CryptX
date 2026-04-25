package Crypt::Stream::XSalsa20;

use strict;
use warnings;
our $VERSION = '0.087_004';

use CryptX;

1;

=pod

=head1 NAME

Crypt::Stream::XSalsa20 - Stream cipher XSalsa20

=head1 SYNOPSIS

   use Crypt::Stream::XSalsa20;

   # encrypt
   my $key    = "12345678901234567890123456789012";  # 32 bytes
   my $nonce  = "123456789012345678901234";          # 24 bytes
   my $enc_stream = Crypt::Stream::XSalsa20->new($key, $nonce);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::XSalsa20->new($key, $nonce);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to the XSalsa20 stream cipher, an extended-nonce
variant of Salsa20 with a 192-bit (24-byte) nonce. The larger nonce
makes random nonce generation safe in practice.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::XSalsa20->new($key, $nonce);

=head2 new

I<Since: CryptX-0.100>

 my $stream = Crypt::Stream::XSalsa20->new($key, $nonce);
 #or
 my $stream = Crypt::Stream::XSalsa20->new($key, $nonce, $rounds);

 # $key    .. [binary string] 32 bytes
 # $nonce  .. [binary string] 24 bytes
 # $rounds .. [integer] optional, rounds (DEFAULT: 20)

=head2 crypt

I<Since: CryptX-0.100>

Encrypts or decrypts data. The output has the same length as the input.
Returns a binary string (raw bytes).

 my $ciphertext = $stream->crypt($plaintext);
 #or
 my $plaintext = $stream->crypt($ciphertext);

=head2 keystream

I<Since: CryptX-0.100>

Returns C<$length> bytes of raw keystream as a binary string.

 my $random_bytes = $stream->keystream($length);

=head2 clone

I<Since: CryptX-0.100>

Returns a copy of the stream cipher object in its current state.

 my $stream2 = $stream->clone;

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::Salsa20>, L<Crypt::Stream::ChaCha>

=item * L<https://cr.yp.to/snuffle/xsalsa-20110204.pdf>

=back

=cut
