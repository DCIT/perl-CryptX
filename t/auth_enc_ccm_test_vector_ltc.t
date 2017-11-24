use strict;
use warnings;

use Test::More tests => 16;

use Crypt::AuthEnc::CCM qw( ccm_encrypt_authenticate ccm_decrypt_verify );

sub do_test {
  my %a = @_;

  my $key = pack("H*", $a{key});
  my $nonce = pack("H*", $a{nonce});
  my $header = pack("H*", $a{header});
  my $plaintext = pack("H*", $a{plaintext});
  my $ciphertext = pack("H*", $a{ciphertext});
  my $tag = pack("H*", $a{tag});

  my ($ct3, $tag3) = ccm_encrypt_authenticate('AES', $key, $nonce, $header, length($tag), $plaintext);
  is(unpack('H*', $ct3), $a{ciphertext}, "enc: ciphertext");
  is(unpack('H*', $tag3), $a{tag}, "enc: tag");
  my $pt3 = ccm_decrypt_verify('AES', $key, $nonce, $header, $ciphertext, $tag);
  is(unpack('H*', $pt3), $a{plaintext}, "dec: plaintext");
  ok(!defined ccm_decrypt_verify('AES', $key, $nonce, $header, $ciphertext, "BAD__TAG"));
}

do_test(%$_) for (
  #/* 13 byte nonce, 8 byte auth, 23 byte pt */
  {
     key=>'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
     nonce=>'00000003020100a0a1a2a3a4a5',
     header=>'0001020304050607',
     plaintext=>'08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
     ciphertext=>'588c979a61c663d2f066d0c2c0f989806d5f6b61dac384',
     tag=>'17e8d12cfdf926e0',
  },

  #/* 13 byte nonce, 12 byte header, 19 byte pt */
  {
     key=>'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
     nonce=>'00000006050403a0a1a2a3a4a5',
     header=>'000102030405060708090a0b',
     plaintext=>'0c0d0e0f101112131415161718191a1b1c1d1e',
     ciphertext=>'a28c6865939a9a79faaa5c4c2a9d4a91cdac8c',
     tag=>'96c861b9c9e61ef1',
  },

  #/* supplied by Brian Gladman */
  {
     key=>'404142434445464748494a4b4c4d4e4f',
     nonce=>'10111213141516',
     header=>'0001020304050607',
     plaintext=>'20212223',
     ciphertext=>'7162015b',
     tag=>'4dac255d',
  },

  {
     key=>'c97c1f67ce371185514a8a19f2bdd52f',
     nonce=>'005030f1844408b5039776e70c',
     header=>'08400fd2e128a57c5030f1844408abaea5b8fcba0000',
     plaintext=>'f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050',
     ciphertext=>'f3d0a2fe9a3dbf2342a643e43246e80c3c04d019',
     tag=>'7845ce0b16f97623',
  },
);
