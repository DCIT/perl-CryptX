package Crypt::Mode::XTS;

### hand-written module - unlike other Crypt::Mode::* this file is NOT generated

use strict;
use warnings;
our $VERSION = '0.091';

use CryptX;

# new, encrypt, decrypt are implemented in XS

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Mode::XTS - Block cipher mode XTS [XEX-based tweaked-codebook mode with ciphertext stealing]

=head1 SYNOPSIS

   use Crypt::Mode::XTS;

   my $xts = Crypt::Mode::XTS->new('AES', $key);   # $key = key1 || key2

   # one complete data unit (sector) per call; same object does both directions
   my $ct = $xts->encrypt($plaintext,  $tweak);
   my $pt = $xts->decrypt($ciphertext, $tweak);

   # tweak: 16-byte string, or a data-unit number
   my $ct1 = $xts->encrypt($sector, "\x02" . "\x00" x 15);
   my $ct2 = $xts->encrypt($sector, 2);            # same thing (64-bit LE, zero-padded)

   # the canonical loop - key schedules computed exactly once, in new()
   my $unit = 0;
   while (my $n = sysread $in, my $sector, 4096) {
     syswrite $out, $xts->encrypt($sector, $unit++);
   }

=head1 DESCRIPTION

This module implements the XTS cipher mode as specified by IEEE 1619-2007 and
NIST SP 800-38E, including ciphertext stealing for data units that are not a
multiple of the block size. B<Note:> It works only with 128-bit block ciphers
from L<CryptX> ('AES', 'Twofish', 'Serpent', 'Camellia', 'ARIA', 'SM4', ...).

B<BEWARE: XTS provides confidentiality only - no integrity, no authentication.>
A bit-flip in the ciphertext garbles exactly the corresponding 16-byte
plaintext block, predictably positioned - that's malleability by design. XTS
is for encrypting storage in place, where the tweak is implicit in the
location and there is no room for a MAC. For anything that travels - files,
messages, backups - use an AEAD mode (C<Crypt::AuthEnc::*>) instead. Also be
aware that an attacker with two snapshots of the same device sees which
blocks changed.

Unlike the other C<Crypt::Mode::*> modules, XTS is not an online mode
(ciphertext stealing needs the complete data unit), so there is no
C<start_encrypt>/C<add>/C<finish> API and this module does not subclass
L<Crypt::Mode>. One C<encrypt>/C<decrypt> call processes exactly one complete
data unit. Ciphertext length always equals plaintext length.

=head1 METHODS

=head2 new

   my $xts = Crypt::Mode::XTS->new($cipher, $key);
   #or
   my $xts = Crypt::Mode::XTS->new($cipher, $key, $cipher_rounds);

   # $cipher .......... [string] cipher with 128-bit blocks, e.g. 'AES', 'Twofish',
   #                    'Serpent', 'Camellia', 'ARIA', 'SM4'
   #                    or any <NAME> for which there is a Crypt::Cipher::<NAME>
   #                    module with a 16-byte block size
   # $key ............. [binary string] key1 || key2, each half a valid key for the
   #                    cipher; for AES that means 32, 48 or 64 bytes total
   # $cipher_rounds ... [integer] optional, number of rounds for the given cipher
   #                    (0 or omitted = the cipher's standard number of rounds)

Both key schedules are computed here, exactly once; C<encrypt>/C<decrypt>
only use the schedules. The raw key is not stored in the object and the
schedules are zeroized on object destruction.

Croaks if the cipher does not have 128-bit blocks, if either key half is not
a valid key size for the cipher, and - per FIPS 140 Implementation Guidance
A.9 - if C<key1> equals C<key2> (that configuration degrades XTS toward ECB
on single-block data units).

The returned object is direction-free: the same object encrypts and decrypts.

=head2 encrypt

   my $ct = $xts->encrypt($plaintext, $tweak);

Encrypts one complete data unit (e.g. one disk sector). Returns the
ciphertext as a binary string of the same length as the plaintext.

C<$plaintext> must be at least 16 bytes (one full cipher block); any length
above that is fine, including lengths that are not a multiple of 16
(ciphertext stealing handles the final partial block). Croaks above 2^20
blocks (16MiB) - the NIST SP 800-38E bound per data unit.

C<$tweak> is either exactly 16 binary bytes, or a non-negative integer
< 2^64 that is encoded as 64-bit little-endian and zero-padded to 16 bytes
(the "data unit sequence number" convention - identical to dm-crypt plain64
and to what OpenSSL and kernel test vectors use). B<Note:> a 16-byte string
is always taken as a raw binary tweak, even if it consists of digits.

=head2 decrypt

   my $pt = $xts->decrypt($ciphertext, $tweak);

Decrypts one complete data unit. Returns the plaintext as a binary string of
the same length as the ciphertext. Same rules for C<$ciphertext> and
C<$tweak> as in L</encrypt>.

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Cipher>

=item * L<Crypt::AuthEnc::GCM>, L<Crypt::AuthEnc::ChaCha20Poly1305> - authenticated encryption, for data that travels

=item * L<https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS>

=item * L<https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf>

=back

=cut
