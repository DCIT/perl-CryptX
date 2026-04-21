use strict;
use warnings;

use Test::More tests => 7;

use Crypt::AuthEnc::SIV qw( siv_encrypt_authenticate siv_decrypt_verify );

{ ### RFC 5297 - A.1. Deterministic Authenticated Encryption Example
  my $key = pack("H*", "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  my $ad  = pack("H*", "101112131415161718191a1b1c1d1e1f2021222324252627");
  my $pt  = pack("H*", "112233445566778899aabbccddee");

  my $ct = siv_encrypt_authenticate('AES', $key, $pt, $ad);
  is(unpack('H*', $ct), "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
     "RFC5297 A.1 encrypt");

  my $pt2 = siv_decrypt_verify('AES', $key, $ct, $ad);
  is($pt2, $pt, "RFC5297 A.1 decrypt");

  substr($ct, 0, 1) ^= "\x01"; # tamper with the SIV tag
  my $pt3 = siv_decrypt_verify('AES', $key, $ct, $ad);
  is($pt3, undef, "RFC5297 A.1 decrypt with tampered ciphertext");
}

{ ### RFC 5297 - A.2. Nonce-Based Authenticated Encryption Example (multiple AD)
  my $key = pack("H*", "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
  my $ad1 = pack("H*", "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100");
  my $ad2 = pack("H*", "102030405060708090a0");
  my $ad3 = pack("H*", "09f911029d74e35bd84156c5635688c0");
  my $pt  = pack("H*", "7468697320697320736f6d6520706c61696e7465787420746f20656e63727970742075" .
                        "73696e67205349562d414553");

  my $ct = siv_encrypt_authenticate('AES', $key, $pt, [$ad1, $ad2, $ad3]);
  is(unpack('H*', $ct), "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17" .
                        "dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d",
     "RFC5297 A.2 encrypt (multiple AD)");

  my $pt2 = siv_decrypt_verify('AES', $key, $ct, [$ad1, $ad2, $ad3]);
  is($pt2, $pt, "RFC5297 A.2 decrypt (multiple AD)");
}

{ ### RFC 5297 limits SIV to 126 associated-data components
  my $key = pack("H*", "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  my $ad0 = pack("H*", "101112131415161718191a1b1c1d1e1f2021222324252627");
  my $pt  = pack("H*", "112233445566778899aabbccddee");
  my @ad  = ("\x00") x 127;

  eval { siv_encrypt_authenticate('AES', $key, $pt, \@ad) };
  like($@, qr/too many associated data components/, "encrypt rejects more than 126 AD components");

  my $ct = siv_encrypt_authenticate('AES', $key, $pt, $ad0);
  eval { siv_decrypt_verify('AES', $key, $ct, \@ad) };
  like($@, qr/too many associated data components/, "decrypt rejects more than 126 AD components");
}
