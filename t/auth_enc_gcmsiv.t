use strict;
use warnings;

use Test::More tests => 23;

use Crypt::AuthEnc::GCMSIV qw( gcm_siv_encrypt_authenticate gcm_siv_decrypt_verify );

{
  package Local::Stringy;
  use overload q{""} => sub { $_[0]->{value} }, fallback => 1;
  sub new { bless { value => $_[1] }, $_[0] }
}

### RFC 8452 - Appendix C.1 (AEAD_AES_128_GCM_SIV)
my $K128   = pack("H*", "01000000000000000000000000000000");
my $NONCE  = pack("H*", "030000000000000000000000");

{ # tcId 1: empty plaintext, empty AAD
  my $out = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, undef, "");
  is(unpack("H*", $out), "dc20e2d83f25705bb49e439eca56de25",
     "RFC8452 C.1 tcId=1 (empty pt/aad)");
}

{ # tcId 2: 8-byte plaintext, no AAD
  my $pt  = pack("H*", "0100000000000000");
  my $out = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, undef, $pt);
  is(unpack("H*", $out),
     "b5d839330ac7b786578782fff6013b815b287c22493a364c",
     "RFC8452 C.1 tcId=2");
  is(gcm_siv_decrypt_verify('AES', $K128, $NONCE, undef, $out), $pt,
     "RFC8452 C.1 tcId=2 roundtrip");
}

{ # tcId 8: with AAD
  my $pt  = pack("H*", "0200000000000000");
  my $aad = pack("H*", "01");
  my $out = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, $aad, $pt);
  is(unpack("H*", $out),
     "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508",
     "RFC8452 C.1 tcId=8 (with AAD)");
  is(gcm_siv_decrypt_verify('AES', $K128, $NONCE, $aad, $out), $pt,
     "RFC8452 C.1 tcId=8 roundtrip");
}

{ # tcId 4: 16-byte plaintext, no AAD
  my $pt  = pack("H*", "01000000000000000000000000000000");
  my $out = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, "", $pt);
  is(unpack("H*", $out),
     "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4",
     "RFC8452 C.1 tcId=4");
}

### RFC 8452 - Appendix C.2 (AEAD_AES_256_GCM_SIV)
my $K256 = pack("H*", "0100000000000000000000000000000000000000000000000000000000000000");

{ # tcId 100: empty pt/aad with 256-bit key
  my $out = gcm_siv_encrypt_authenticate('AES', $K256, $NONCE, undef, "");
  is(unpack("H*", $out), "07f5f4169bbf55a8400cd47ea6fd400f",
     "RFC8452 C.2 tcId=100 (AES-256, empty)");
}

{ # tcId 101: AES-256, 8-byte plaintext
  my $pt  = pack("H*", "0100000000000000");
  my $out = gcm_siv_encrypt_authenticate('AES', $K256, $NONCE, undef, $pt);
  is(unpack("H*", $out),
     "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28",
     "RFC8452 C.2 tcId=101");
  is(gcm_siv_decrypt_verify('AES', $K256, $NONCE, undef, $out), $pt,
     "RFC8452 C.2 tcId=101 roundtrip");
}

{ # tcId 107: AES-256 with AAD
  my $pt  = pack("H*", "0200000000000000");
  my $aad = pack("H*", "01");
  my $out = gcm_siv_encrypt_authenticate('AES', $K256, $NONCE, $aad, $pt);
  is(unpack("H*", $out),
     "1de22967237a813291213f267e3b452f02d01ae33e4ec854",
     "RFC8452 C.2 tcId=107 (AES-256 + AAD)");
}

### Tamper detection
{
  my $pt  = pack("H*", "0100000000000000");
  my $aad = pack("H*", "01");
  my $ct  = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, $aad, $pt);

  # Tamper with last byte (tag region)
  my $tampered_tag = $ct;
  substr($tampered_tag, -1) ^= chr(0x01);
  is(gcm_siv_decrypt_verify('AES', $K128, $NONCE, $aad, $tampered_tag), undef,
     "tampered tag rejected");

  # Tamper with first byte (ciphertext region)
  my $tampered_ct = $ct;
  substr($tampered_ct, 0, 1) ^= chr(0x01);
  is(gcm_siv_decrypt_verify('AES', $K128, $NONCE, $aad, $tampered_ct), undef,
     "tampered ciphertext rejected");

  # Wrong AAD
  is(gcm_siv_decrypt_verify('AES', $K128, $NONCE, "wrong", $ct), undef,
     "wrong AAD rejected");

  # Wrong nonce
  my $bad_nonce = pack("H*", "040000000000000000000000");
  is(gcm_siv_decrypt_verify('AES', $K128, $bad_nonce, $aad, $ct), undef,
     "wrong nonce rejected");
}

### Argument validation
{
  eval { gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, undef, "") };
  is($@, "", "empty plaintext + undef AAD accepted");

  eval { gcm_siv_decrypt_verify('AES', $K128, $NONCE, undef, "x" x 8) };
  like($@, qr/ciphertext too short/, "short ciphertext croaks");

  # Bad nonce length (must be exactly 12 bytes)
  eval { gcm_siv_encrypt_authenticate('AES', $K128, "short", undef, "data") };
  like($@, qr/gcm_siv_memory\(encrypt\) failed/, "wrong nonce length croaks");

  # Bad key length (must be 16 or 32)
  eval { gcm_siv_encrypt_authenticate('AES', "short", $NONCE, undef, "data") };
  like($@, qr/gcm_siv_memory\(encrypt\) failed/, "wrong key length croaks");

  # Non-string key
  eval { gcm_siv_encrypt_authenticate('AES', [], $NONCE, undef, "data") };
  like($@, qr/key must be string\/buffer scalar/, "non-string key rejected");
}

### Overload support
{
  my $pt  = pack("H*", "0100000000000000");
  my $aad = pack("H*", "01");
  my $plain_ct = gcm_siv_encrypt_authenticate('AES', $K128, $NONCE, $aad, $pt);

  my $over_ct = gcm_siv_encrypt_authenticate('AES',
                  Local::Stringy->new($K128),
                  Local::Stringy->new($NONCE),
                  Local::Stringy->new($aad),
                  Local::Stringy->new($pt));
  is($over_ct, $plain_ct, "overloaded scalar args produce same ciphertext");

  my $pt2 = gcm_siv_decrypt_verify('AES',
                  Local::Stringy->new($K128),
                  Local::Stringy->new($NONCE),
                  Local::Stringy->new($aad),
                  Local::Stringy->new($plain_ct));
  is($pt2, $pt, "overloaded scalar args decrypt");
}

### Random AAD/PT roundtrip
{
  my $key = pack("H*", "0f0e0d0c0b0a09080706050403020100");
  my $non = pack("H*", "0a0b0c0d0e0f000102030405");
  my $aad = "Authenticated but not encrypted data \x{00}\xff";
  utf8::encode($aad);
  my $pt  = "Hello, GCM-SIV! \x{00}" x 8;
  utf8::encode($pt);
  my $ct  = gcm_siv_encrypt_authenticate('AES', $key, $non, $aad, $pt);
  is(length($ct), length($pt) + 16, "ciphertext = plaintext + 16-byte tag");
  is(gcm_siv_decrypt_verify('AES', $key, $non, $aad, $ct), $pt, "random roundtrip");
}
