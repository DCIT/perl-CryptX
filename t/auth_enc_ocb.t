use strict;
use warnings;

use Test::More tests => 12;

use Crypt::AuthEnc::OCB qw( ocb_encrypt_authenticate ocb_decrypt_verify );

my $key   = "12345678901234561234567890123456";

{
  my $pt    = "plain_half_12345";
  my $ct;

  my $m1 = Crypt::AuthEnc::OCB->new("AES", $key, "123456789012", 16);
  $m1->adata_add("adata-123456789012");
  $ct = $m1->encrypt_add($pt);
  $ct .= $m1->encrypt_last($pt);
  my $tag = $m1->encrypt_done;

  is(unpack('H*', $ct), "4c85b38952e71220ecc323253547ae9b446f5a518717759ef8b0f24d5c4809a6", "enc: ciphertext");
  is(unpack('H*', $tag), "bd7a6a0aaf24420f97bf239ea5740a40", "enc: tag");

  my $d1 = Crypt::AuthEnc::OCB->new("AES", $key, "123456789012", 16);
  $d1->adata_add("adata-123456789012");
  my $pt2 = $d1->decrypt_last($ct);
  my $tag2 = $d1->decrypt_done();

  is($pt2, "plain_half_12345plain_half_12345", "dec1: plaintext");
  is(unpack('H*', $tag2), "bd7a6a0aaf24420f97bf239ea5740a40", "dec1: tag");
}

{
  my ($ct, $tag) = ocb_encrypt_authenticate('AES', $key, "123456789012", "", 16, "plain_half_12345plain_half_12345");
  is(unpack('H*', $ct), "4c85b38952e71220ecc323253547ae9b446f5a518717759ef8b0f24d5c4809a6", "ocb_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "dfdfab80aca060268c0cc467040af4f9", "ocb_encrypt_authenticate: tag (no header)");
  my $pt = ocb_decrypt_verify('AES', $key, "123456789012", "", $ct, $tag);
  is($pt, "plain_half_12345plain_half_12345", "ocb_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = ocb_decrypt_verify('AES', $key, "123456789012", "", $ct, $tag);
  is($pt, undef, "ocb_decrypt_verify: plaintext (no header) / bad tag");
}

{
  my ($ct, $tag) = ocb_encrypt_authenticate('AES', $key, "123456789012", "adata-123456789012", 16, "plain_half_12345plain_half_12345");
  is(unpack('H*', $ct), "4c85b38952e71220ecc323253547ae9b446f5a518717759ef8b0f24d5c4809a6", "ocb_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "bd7a6a0aaf24420f97bf239ea5740a40", "ocb_encrypt_authenticate: tag (no header)");
  my $pt = ocb_decrypt_verify('AES', $key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, "plain_half_12345plain_half_12345", "ocb_decrypt_verify: plaintext (no header)");
  substr($tag, 0, 1) = pack("H2", "AA");
  $pt = ocb_decrypt_verify('AES', $key, "123456789012", "adata-123456789012", $ct, $tag);
  is($pt, undef, "ocb_decrypt_verify: plaintext (no header) / bad tag");
}
