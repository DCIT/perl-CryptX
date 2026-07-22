use strict;
use warnings;

use Test::More tests => 23;

use Crypt::AuthEnc::EAX qw( eax_encrypt_authenticate eax_decrypt_verify );

my $nonce = "random-nonce";
my $key   = "12345678901234561234567890123456";

{
  my $pt    = "plain_half";
  my $ct;

  my $m1 = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
  $m1->header_add("a");
  $m1->header_add("b");
  $m1->header_add("c");
  $ct = $m1->encrypt_add($pt);
  $ct .= $m1->encrypt_add($pt);
  my $tag = $m1->encrypt_done;

  is(unpack('H*', $ct), "4b88b8819481fbc39839890fedf3e31cef7ea2a9", "enc: ciphertext");
  is(unpack('H*', $tag), "f83d77e5cf20979b3325266ff2fe342c", "enc: tag");

  my $d1 = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
  $d1->header_add("abc");
  my $pt2 = $d1->decrypt_add($ct);
  my $tag2 = $d1->decrypt_done();

  is($pt2, "plain_halfplain_half", "dec1: plaintext");
  is(unpack('H*', $tag2), "f83d77e5cf20979b3325266ff2fe342c", "dec1: tag");

  my $d2 = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
  $d2->header_add("a");
  $d2->header_add("b");
  $d2->header_add("c");
  my $pt3;
  $pt3 .= $d2->decrypt_add(substr($ct,$_-1,1)) for (1..length($ct));
  my $tag3 = $d2->decrypt_done();

  is($pt3, "plain_halfplain_half", "dec2: plaintext");
  is(unpack('H*', $tag3), "f83d77e5cf20979b3325266ff2fe342c", "dec2: tag");
}

{
  my ($ct, $tag) = eax_encrypt_authenticate('AES', $key, $nonce, "abc", "plain_halfplain_half");
  is(unpack('H*', $ct), "4b88b8819481fbc39839890fedf3e31cef7ea2a9", "eax_encrypt_authenticate: ciphertext");
  is(unpack('H*', $tag), "f83d77e5cf20979b3325266ff2fe342c", "eax_encrypt_authenticate: tag");
  my $pt = eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $tag);
  is($pt, "plain_halfplain_half", "eax_decrypt_verify: plaintext");
  $pt = eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $tag . ("A" x 200));
  is($pt, undef, "eax_decrypt_verify: plaintext / oversized tag");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $tag);
  is($pt, undef, "eax_decrypt_verify: plaintext / bad tag");
}

{
  my ($ct, $tag) = eax_encrypt_authenticate('AES', $key, $nonce, "", "plain_halfplain_half");
  is(unpack('H*', $ct), "4b88b8819481fbc39839890fedf3e31cef7ea2a9", "eax_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "e5ad22aa2ba3b30cd50eb59593364f1b", "eax_encrypt_authenticate: tag (no header)");
  my $pt = eax_decrypt_verify('AES', $key, $nonce, "", $ct, $tag);
  is($pt, "plain_halfplain_half", "eax_decrypt_verify: plaintext (no header)");
  $pt = eax_decrypt_verify('AES', $key, $nonce, "", $ct, $tag . ("A" x 200));
  is($pt, undef, "eax_decrypt_verify: plaintext (no header) / oversized tag");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = eax_decrypt_verify('AES', $key, $nonce, "", $ct, $tag);
  is($pt, undef, "eax_decrypt_verify: plaintext (no header) / bad tag");
}

{
  # EAX tag-length: 0..16 (16 == AES blocklen)
  my ($ct, $tag) = eax_encrypt_authenticate('AES', $key, $nonce, "abc", "data_data_data_data");
  my $empty = "";
  my $short = substr($tag, 0, 3);
  is(eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $empty), "data_data_data_data", "eax_decrypt_verify: empty tag accepted");
  is(eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $short), "data_data_data_data", "eax_decrypt_verify: truncated tag accepted");
  is(eax_decrypt_verify('AES', $key, $nonce, "abc", $ct, $tag),   "data_data_data_data", "eax_decrypt_verify: full tag accepted");
  is(eax_decrypt_verify('AES', $key, "123456789012", "", $ct, $tag . ("A" x 200)), undef, "ocb_decrypt_verify: over-long tag rejected");
}

{
  # EAX imposes no nonce-length restriction
  for my $nlen (0, 1, 64) {
    my $n = "N" x $nlen;
    my ($ct, $tag) = eax_encrypt_authenticate('AES', $key, $n, "", "data");
    is(eax_decrypt_verify('AES', $key, $n, "", $ct, $tag), "data", "eax_decrypt_verify: nonce length $nlen accepted");
  }
}
