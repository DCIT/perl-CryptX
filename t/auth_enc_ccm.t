use strict;
use warnings;

use Test::More tests => 6;

use Crypt::AuthEnc::CCM qw( ccm_encrypt_authenticate ccm_decrypt_verify );

my $nonce = "random-nonce";
my $key   = "12345678901234561234567890123456";

{
  my ($ct, $tag) = ccm_encrypt_authenticate('AES', $key, $nonce, "header-abc", 16, "plain_halfplain_half");
  is(unpack('H*', $ct), "96b0114ff47da72e92631aadce84f203a8168b20", "ccm_encrypt_authenticate: ciphertext");
  is(unpack('H*', $tag), "9485c6d5709b43431a4f05370cc22603", "ccm_encrypt_authenticate: tag");
  my $pt = ccm_decrypt_verify('AES', $key, $nonce, "header-abc", $ct, $tag);
  is($pt, "plain_halfplain_half", "ccm_decrypt_verify: plaintext");
}

{
  my ($ct, $tag) = ccm_encrypt_authenticate('AES', $key, $nonce, "", 16, "plain_halfplain_half");
  is(unpack('H*', $ct), "96b0114ff47da72e92631aadce84f203a8168b20", "ccm_encrypt_authenticate: ciphertext (no header)");
  is(unpack('H*', $tag), "9e9cba5dd4939d0d8e2687c85c5d3b89", "ccm_encrypt_authenticate: tag (no header)");
  my $pt = ccm_decrypt_verify('AES', $key, $nonce, "", $ct, $tag);
  is($pt, "plain_halfplain_half", "ccm_decrypt_verify: plaintext (no header)");
}