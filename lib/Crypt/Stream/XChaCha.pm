package Crypt::Stream::XChaCha;

use strict;
use warnings;
our $VERSION = '0.088_001';

use CryptX;

1;

=pod

=head1 NAME

Crypt::Stream::XChaCha - Stream cipher XChaCha20

=head1 SYNOPSIS

   use Crypt::Stream::XChaCha;

   # encrypt
   $key    = "12345678901234567890123456789012";  # 32 bytes
   $nonce  = "123456789012345678901234";          # 24 bytes
   $stream = Crypt::Stream::XChaCha->new($key, $nonce);
   $ct = $stream->crypt("plain message");

   # decrypt
   $stream = Crypt::Stream::XChaCha->new($key, $nonce);
   $pt = $stream->crypt($ct);

=head1 DESCRIPTION

Provides an interface to the XChaCha20 stream cipher, an extended-nonce
variant of ChaCha20 using a 192-bit (24-byte) nonce.

=head1 METHODS

=head2 new

 $stream = Crypt::Stream::XChaCha->new($key, $nonce);
 #or
 $stream = Crypt::Stream::XChaCha->new($key, $nonce, $rounds);

 # $key    .. 32 bytes
 # $nonce  .. 24 bytes
 # $rounds .. optional, rounds (DEFAULT: 20)

=head2 crypt

 $ciphertext = $stream->crypt($plaintext);
 #or
 $plaintext = $stream->crypt($ciphertext);

=head2 keystream

 $random_bytes = $stream->keystream($length);

=head2 clone

 $stream2 = $stream->clone;

=head1 SEE ALSO

=over

=item * L<Crypt::Stream::ChaCha>, L<Crypt::Stream::XSalsa20>

=back

=cut
