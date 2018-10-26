use strict;
use warnings;

use Test::More tests => 14;

use Crypt::AuthEnc::ChaCha20Poly1305 qw( chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify );

my $key   = "12345678901234561234567890123456";

{
  my $pt    = "plain_half";
  my $ct;

  my $m1 = Crypt::AuthEnc::ChaCha20Poly1305->new($key, "123456789012");
  $m1->adata_add("adata-123456789012");
  $ct = $m1->encrypt_add($pt);
  $ct .= $m1->encrypt_add($pt);
  my $tag = $m1->encrypt_done;

  is(unpack('H*', $ct), "92dc41021189e1660d5dd4bbee2fd00cc9047fdf", "enc: ciphertext");
  is(unpack('H*', $tag), "e6f20b492b7bf34c914c72717af6f232", "enc: tag");

  my $d1 = Crypt::AuthEnc::ChaCha20Poly1305->new($key, "123456789012");
  $d1->adata_add("adata-123456789012");
  my $pt2 = $d1->decrypt_add($ct);
  my $tag2 = $d1->decrypt_done();

  is($pt2, "plain_halfplain_half", "dec1: plaintext");
  is(unpack('H*', $tag2), "e6f20b492b7bf34c914c72717af6f232", "dec1: tag");

  my $d2 = Crypt::AuthEnc::ChaCha20Poly1305->new($key, "123456789012");
  $d2->adata_add("adata-123456789012");
  my $pt3;
  $pt3 .= $d2->decrypt_add(substr($ct,$_-1,1)) for (1..length($ct));
  my $tag3 = $d2->decrypt_done();

  is($pt3, "plain_halfplain_half", "dec2: plaintext");
  is(unpack('H*', $tag3), "e6f20b492b7bf34c914c72717af6f232", "dec2: tag");
}

{
  my ($ct, $tag) = chacha20poly1305_encrypt_authenticate($key, "123456789012", "", "plain_halfplain_half");
  is(unpack('H*', $ct), "92dc41021189e1660d5dd4bbee2fd00cc9047fdf", "chacha20poly1305_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "d081beb3c3fe560c77f6c4e0da1d0dac", "chacha20poly1305_encrypt_authenticate: tag (no header)");
  my $pt = chacha20poly1305_decrypt_verify($key, "123456789012", "", $ct, $tag);
  is($pt, "plain_halfplain_half", "chacha20poly1305_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = chacha20poly1305_decrypt_verify($key, "123456789012", "", $ct, $tag);
  is($pt, undef, "chacha20poly1305_decrypt_verify: plaintext (no header) / bad tag");
}

{
  my ($ct, $tag) = chacha20poly1305_encrypt_authenticate($key, "123456789012", "adata-123456789012", "plain_halfplain_half");
  is(unpack('H*', $ct), "92dc41021189e1660d5dd4bbee2fd00cc9047fdf", "chacha20poly1305_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "e6f20b492b7bf34c914c72717af6f232", "chacha20poly1305_encrypt_authenticate: tag (no header)");
  my $pt = chacha20poly1305_decrypt_verify($key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, "plain_halfplain_half", "chacha20poly1305_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = chacha20poly1305_decrypt_verify($key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, undef, "chacha20poly1305_decrypt_verify: plaintext (no header) / bad tag");
}
