package Crypt::Stream::ChaCha;

use strict;
use warnings;
our $VERSION = '0.088_001';

use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Stream::ChaCha - Stream cipher ChaCha

=head1 SYNOPSIS

   use Crypt::Stream::ChaCha;

   # encrypt
   my $key = "12345678901234567890123456789012";  # 32 bytes
   my $nonce  = "123456789012";                      # 12 bytes
   my $enc_stream = Crypt::Stream::ChaCha->new($key, $nonce);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::ChaCha->new($key, $nonce);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the ChaCha stream cipher.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::ChaCha->new($key, $nonce);

=head2 new

 my $stream = Crypt::Stream::ChaCha->new($key, $nonce);
 #or
 my $stream = Crypt::Stream::ChaCha->new($key, $nonce, $counter, $rounds);

 # $key     .. [binary string] 32 or 16 bytes
 # $nonce   .. [binary string] 8 or 12 bytes
 # $counter .. [integer] initial counter value (DEFAULT: 0)
 #             for 12-byte nonces the counter must be <= 0xFFFFFFFF
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

=item * L<Crypt::Stream::RC4>, L<Crypt::Stream::Sober128>, L<Crypt::Stream::Salsa20>, L<Crypt::Stream::Sosemanuk>

=item * L<https://www.rfc-editor.org/rfc/rfc7539>

=back

=cut
