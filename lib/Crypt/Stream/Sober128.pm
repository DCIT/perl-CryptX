package Crypt::Stream::Sober128;

use strict;
use warnings;
our $VERSION = '0.088_003';

use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Stream::Sober128 - Stream cipher Sober128

=head1 SYNOPSIS

   use Crypt::Stream::Sober128;

   # encrypt
   my $key = "1234567890123456";
   my $iv  = "123456789012";
   my $enc_stream = Crypt::Stream::Sober128->new($key, $iv);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::Sober128->new($key, $iv);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the Sober128 stream cipher.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::Sober128->new($key, $iv);

=head2 new

 my $stream = Crypt::Stream::Sober128->new($key, $iv);
 # $key .. [binary string] keylen must be multiple of 4 bytes
 # $iv  .. [binary string] ivlen must be multiple of 4 bytes

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

 my $random_key = $stream->keystream($length);

=head2 clone

Returns a copy of the stream cipher object in its current state.

 my $stream2 = $stream->clone();

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::RC4>, L<Crypt::Stream::ChaCha>, L<Crypt::Stream::Salsa20>, L<Crypt::Stream::Sosemanuk>

=item * L<https://en.wikipedia.org/wiki/SOBER-128|https://en.wikipedia.org/wiki/SOBER-128>

=back

=cut
