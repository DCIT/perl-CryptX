use strict;
use warnings;

use Test::More tests => 14;

use Crypt::AuthEnc::GCM qw( gcm_encrypt_authenticate gcm_decrypt_verify );

my $key   = "12345678901234561234567890123456";

{
  my $pt    = "plain_half";
  my $ct;

  my $m1 = Crypt::AuthEnc::GCM->new("AES", $key);
  $m1->iv_add("123456789012");
  $m1->adata_add("adata-123456789012");
  $ct = $m1->encrypt_add($pt);
  $ct .= $m1->encrypt_add($pt);
  my $tag = $m1->encrypt_done;

  is(unpack('H*', $ct), "1d56d8e991a7fc707135a79842ef9b57d885485d", "enc: ciphertext");
  is(unpack('H*', $tag), "d225e849d4d076cf9e85d5303450e793", "enc: tag");

  my $d1 = Crypt::AuthEnc::GCM->new("AES", $key);
  $d1->iv_add("123456789012");
  $d1->adata_add("adata-123456789012");
  my $pt2 = $d1->decrypt_add($ct);
  my $tag2 = $d1->decrypt_done();

  is($pt2, "plain_halfplain_half", "dec1: plaintext");
  is(unpack('H*', $tag2), "d225e849d4d076cf9e85d5303450e793", "dec1: tag");

  my $d2 = Crypt::AuthEnc::GCM->new("AES", $key);
  $d2->iv_add("123456789012");
  $d2->adata_add("adata-123456789012");
  my $pt3;
  $pt3 .= $d2->decrypt_add(substr($ct,$_-1,1)) for (1..length($ct));
  my $tag3 = $d2->decrypt_done();

  is($pt3, "plain_halfplain_half", "dec2: plaintext");
  is(unpack('H*', $tag3), "d225e849d4d076cf9e85d5303450e793", "dec2: tag");
}

{
  my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, "123456789012", "", "plain_halfplain_half");
  is(unpack('H*', $ct), "1d56d8e991a7fc707135a79842ef9b57d885485d", "gcm_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "1685ba0eda059ace4aab6539980c30c0", "gcm_encrypt_authenticate: tag (no header)");
  my $pt = gcm_decrypt_verify('AES', $key, "123456789012", "", $ct, $tag);
  is($pt, "plain_halfplain_half", "gcm_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = gcm_decrypt_verify('AES', $key, "123456789012", "", $ct, $tag);
  is($pt, undef, "gcm_decrypt_verify: plaintext (no header) / bad tag");
}

{
  my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, "123456789012", "adata-123456789012", "plain_halfplain_half");
  is(unpack('H*', $ct), "1d56d8e991a7fc707135a79842ef9b57d885485d", "gcm_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "d225e849d4d076cf9e85d5303450e793", "gcm_encrypt_authenticate: tag (no header)");
  my $pt = gcm_decrypt_verify('AES', $key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, "plain_halfplain_half", "gcm_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = gcm_decrypt_verify('AES', $key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, undef, "gcm_decrypt_verify: plaintext (no header) / bad tag");
}
