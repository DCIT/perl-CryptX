package Crypt::Stream::Rabbit;

use strict;
use warnings;
our $VERSION = '0.088_003';

use CryptX;

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Stream::Rabbit - Stream cipher Rabbit

=head1 SYNOPSIS

   use Crypt::Stream::Rabbit;

   # encrypt
   my $key = "1234567890123456";
   my $iv  = "12345678";
   my $enc_stream = Crypt::Stream::Rabbit->new($key, $iv);
   my $ct = $enc_stream->crypt("plain message");

   # decrypt
   my $dec_stream = Crypt::Stream::Rabbit->new($key, $iv);
   my $pt = $dec_stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the Rabbit stream cipher.

=head1 METHODS

Unless noted otherwise, assume C<$stream> is an existing stream object created
via C<new>, for example:

 my $stream = Crypt::Stream::Rabbit->new($key, $iv);

=head2 new

 my $stream = Crypt::Stream::Rabbit->new($key, $iv);
 # $key .. [binary string] keylen must be up to 16 bytes
 # $iv  .. [binary string] ivlen must be up to 8 bytes

 my $stream = Crypt::Stream::Rabbit->new($key);
 #BEWARE: new($key) skips IV setup entirely, while new($key, "") performs
 #        IV setup with a zero-length IV - these produce different keystreams

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

=item * L<Crypt::Stream::RC4>, L<Crypt::Stream::ChaCha>, L<Crypt::Stream::Salsa20>, L<Crypt::Stream::Sober128>

=item * L<https://en.wikipedia.org/wiki/Rabbit_(cipher)>

=item * L<https://www.rfc-editor.org/rfc/rfc4503>

=back

=cut
