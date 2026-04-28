package Crypt::Stream::XChaCha;

use strict;
use warnings;
our $VERSION = '0.088_005';

use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Stream::XChaCha - Stream cipher XChaCha20

=head1 SYNOPSIS

   use Crypt::Stream::XChaCha;

   # encrypt
   my $key    = "12345678901234567890123456789012";  # 32 bytes
   my $nonce  = "123456789012345678901234";          # 24 bytes
   my $enc_stream = Crypt::Stream::XChaCha->new($key, $nonce);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::XChaCha->new($key, $nonce);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to the XChaCha20 stream cipher, an extended-nonce
variant of ChaCha20 using a 192-bit (24-byte) nonce.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::XChaCha->new($key, $nonce);

=head2 new

 my $stream = Crypt::Stream::XChaCha->new($key, $nonce);
 #or
 my $stream = Crypt::Stream::XChaCha->new($key, $nonce, $rounds);

 # $key    .. [binary string] 32 bytes
 # $nonce  .. [binary string] 24 bytes
 # $rounds .. [integer] optional, rounds (DEFAULT: 20)

=head2 crypt

Encrypts or decrypts data. The output has the same length as the input.
Returns a binary string (raw bytes).

The input is converted using Perl's usual scalar stringification. Passing
C<undef> is treated as an empty string with the usual warning, and numeric
scalars are stringified before processing.

 my $ciphertext = $stream->crypt($plaintext);
 #or
 my $plaintext = $stream->crypt($ciphertext);

=head2 keystream

Returns C<$length> bytes of raw keystream as a binary string.

The length is taken using Perl's usual numeric coercion. Values that coerce to
an oversized unsigned length are rejected as too large.

 my $random_bytes = $stream->keystream($length);

=head2 clone

Returns a copy of the stream cipher object in its current state.

 my $stream2 = $stream->clone;

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::ChaCha>, L<Crypt::Stream::XSalsa20>

=item * L<https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha>

=back

=cut
