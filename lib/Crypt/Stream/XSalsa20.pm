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
   $key    = "12345678901234567890123456789012";  # 32 bytes
   $nonce  = "123456789012345678901234";          # 24 bytes
   $stream = Crypt::Stream::XSalsa20->new($key, $nonce);
   $ct = $stream->crypt("plain message");

   # decrypt
   $stream = Crypt::Stream::XSalsa20->new($key, $nonce);
   $pt = $stream->crypt($ct);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to the XSalsa20 stream cipher, an extended-nonce
variant of Salsa20 with a 192-bit (24-byte) nonce. The larger nonce
makes random nonce generation safe in practice.

=head1 METHODS

=head2 new

I<Since: CryptX-0.100>

 $stream = Crypt::Stream::XSalsa20->new($key, $nonce);
 #or
 $stream = Crypt::Stream::XSalsa20->new($key, $nonce, $rounds);

 # $key    .. 32 bytes
 # $nonce  .. 24 bytes
 # $rounds .. optional, rounds (DEFAULT: 20)

=head2 crypt

I<Since: CryptX-0.100>

 $ciphertext = $stream->crypt($plaintext);
 #or
 $plaintext = $stream->crypt($ciphertext);

=head2 keystream

I<Since: CryptX-0.100>

 $random_bytes = $stream->keystream($length);

=head2 clone

I<Since: CryptX-0.100>

 $stream2 = $stream->clone;

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::Salsa20>, L<Crypt::Stream::ChaCha>

=back

=cut
