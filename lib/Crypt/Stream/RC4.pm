package Crypt::Stream::RC4;

use strict;
use warnings;
our $VERSION = '0.088_001';

use CryptX;

1;

=pod

=head1 NAME

Crypt::Stream::RC4 - Stream cipher RC4

=head1 SYNOPSIS

   use Crypt::Stream::RC4;

   # encrypt
   my $key = "1234567890123456";
   my $enc_stream = Crypt::Stream::RC4->new($key);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::RC4->new($key);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the RC4 stream cipher.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::RC4->new($key);

=head2 new

 my $stream = Crypt::Stream::RC4->new($key);
 # $key .. [binary string] length 5-256 bytes (40 - 2048 bits)

=head2 crypt

Encrypts or decrypts data. The output has the same length as the input.
Returns a binary string (raw bytes).

 my $ciphertext = $stream->crypt($plaintext);
 #or
 my $plaintext = $stream->crypt($ciphertext);

=head2 keystream

Returns C<$length> bytes of raw keystream as a binary string.

 my $random_key = $stream->keystream($length);

=head2 clone

Returns a copy of the stream cipher object in its current state.

 my $stream2 = $stream->clone();

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::ChaCha>, L<Crypt::Stream::Sober128>, L<Crypt::Stream::Salsa20>, L<Crypt::Stream::Sosemanuk>

=item * L<https://en.wikipedia.org/wiki/RC4_cipher|https://en.wikipedia.org/wiki/RC4_cipher>

=back

=cut
