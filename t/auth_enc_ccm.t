use strict;
use warnings;

use Test::More tests => 15;

use Crypt::AuthEnc::CCM qw( ccm_encrypt_authenticate ccm_decrypt_verify );

my $nonce = "random-nonce";
my $key   = "12345678901234561234567890123456";

{
  my $pt    = "plain_half";
  my $ct;

  my $m1 = Crypt::AuthEnc::CCM->new("AES", $key, $nonce, "abc", 16, 20);
  $ct = $m1->encrypt_add($pt);
  $ct .= $m1->encrypt_add($pt);
  my $tag = $m1->encrypt_done;

  is(unpack('H*', $ct), "96b0114ff47da72e92631aadce84f203a8168b20", "enc: ciphertext");
  is(unpack('H*', $tag), "fdc41ec07673ec132f1910ba771b9530", "enc: tag");

  my $d1 = Crypt::AuthEnc::CCM->new("AES", $key, $nonce, "abc", 16, 20);
  my $pt2 = $d1->decrypt_add($ct);
  my $tag2 = $d1->decrypt_done();

  is($pt2, "plain_halfplain_half", "dec1: plaintext");
  is(unpack('H*', $tag2), "fdc41ec07673ec132f1910ba771b9530", "dec1: tag");

  my $d2 = Crypt::AuthEnc::CCM->new("AES", $key, $nonce, "abc", 16, 20);
  my $pt3;
  $pt3 .= $d2->decrypt_add(substr($ct,$_-1,1)) for (1..length($ct));
  my $tag3 = $d2->decrypt_done();

  is($pt3, "plain_halfplain_half", "dec2: plaintext");
  is(unpack('H*', $tag3), "fdc41ec07673ec132f1910ba771b9530", "dec2: tag");
}

{
  my ($ct, $tag) = ccm_encrypt_authenticate('AES', $key, $nonce, "header-abc", 16, "plain_halfplain_half");
  is(unpack('H*', $ct), "96b0114ff47da72e92631aadce84f203a8168b20", "ccm_encrypt_authenticate: ciphertext");
  is(unpack('H*', $tag), "9485c6d5709b43431a4f05370cc22603", "ccm_encrypt_authenticate: tag");
  my $pt = ccm_decrypt_verify('AES', $key, $nonce, "header-abc", $ct, $tag);
  is($pt, "plain_halfplain_half", "ccm_decrypt_verify: plaintext");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = ccm_decrypt_verify('AES', $key, $nonce, "header-abc", $ct, $tag);
  is($pt, undef, "ccm_decrypt_verify: plaintext / bad tag");
}

{
  my ($ct, $tag)   = ccm_encrypt_authenticate('AES', $key, $nonce, "", 16, "plain_halfplain_half");
  my ($ct2, $tag2) = ccm_encrypt_authenticate('AES', $key, $nonce, undef, 16, "plain_halfplain_half");
  ok($ct eq $ct2 && $tag eq $tag2, "header '' vs. undef");
  is(unpack('H*', $ct), "96b0114ff47da72e92631aadce84f203a8168b20", "ccm_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "9e9cba5dd4939d0d8e2687c85c5d3b89", "ccm_encrypt_authenticate: tag (no header)");
  my $pt = ccm_decrypt_verify('AES', $key, $nonce, "", $ct, $tag);
  is($pt, "plain_halfplain_half", "ccm_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = ccm_decrypt_verify('AES', $key, $nonce, "", $ct, $tag);
  is($pt, undef, "ccm_decrypt_verify: plaintext (no header) / bad tag");
}
