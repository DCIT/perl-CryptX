package Crypt::Stream::Salsa20;

use strict;
use warnings;
our $VERSION = '0.088_002';

use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Stream::Salsa20 - Stream cipher Salsa20

=head1 SYNOPSIS

   use Crypt::Stream::Salsa20;

   # encrypt
   my $key = "1234567890123456";
   my $nonce  = "12345678";
   my $enc_stream = Crypt::Stream::Salsa20->new($key, $nonce);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::Salsa20->new($key, $nonce);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the Salsa20 stream cipher.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::Salsa20->new($key, $nonce);

=head2 new

 my $stream = Crypt::Stream::Salsa20->new($key, $nonce);
 #or
 my $stream = Crypt::Stream::Salsa20->new($key, $nonce, $counter, $rounds);

 # $key     .. [binary string] 32 or 16 bytes
 # $nonce   .. [binary string] 8 bytes
 # $counter .. [integer] initial counter value (DEFAULT: 0)
 # $rounds  .. [integer] rounds (DEFAULT: 20)

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

=item * L<Crypt::Stream::ChaCha>, L<Crypt::Stream::RC4>, L<Crypt::Stream::Sober128>, L<Crypt::Stream::Sosemanuk>

=item * L<https://cr.yp.to/snuffle/spec.pdf>

=back

=cut
