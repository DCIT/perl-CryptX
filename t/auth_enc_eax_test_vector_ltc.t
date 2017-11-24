use strict;
use warnings;

use Test::More tests => 56;

use Crypt::AuthEnc::EAX qw( eax_encrypt_authenticate eax_decrypt_verify );

sub do_test {
  my %a = @_;

  my $key = pack("H*", $a{key});
  my $nonce = pack("H*", $a{nonce});
  my $header = pack("H*", $a{header});
  my $plaintext = pack("H*", $a{plaintext});
  my $ciphertext = pack("H*", $a{ciphertext});
  my $tag = pack("H*", $a{tag});

  # encrypt
  my $m1 = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
  $m1->header_add($header);
  my $ct = $m1->encrypt_add($plaintext);
  my $tag1 = $m1->encrypt_done;

  is(unpack('H*', $ct), $a{ciphertext}, "enc: ciphertext");
  is(unpack('H*', $tag1), $a{tag}, "enc: tag");

  # decrypt
  my $d1 = Crypt::AuthEnc::EAX->new("AES", $key, $nonce);
  $d1->header_add($header);
  my $pt = $d1->decrypt_add($ciphertext);
  my $tag2 = $d1->decrypt_done();

  is(unpack('H*', $pt), $a{plaintext}, "dec: plaintext");
  is(unpack('H*', $tag2), $a{tag}, "dec: tag");

  # all-in-one
  my ($ct3, $tag3) = eax_encrypt_authenticate('AES', $key, $nonce, $header, $plaintext);
  is(unpack('H*', $ct3), $a{ciphertext}, "enc: ciphertext");
  is(unpack('H*', $tag3), $a{tag}, "enc: tag");
  my $pt3 = eax_decrypt_verify('AES', $key, $nonce, $header, $ciphertext, $tag);
  is(unpack('H*', $pt3), $a{plaintext}, "dec: plaintext");

}

do_test(%$_) for (
  #/* NULL message */
  {
     #16, 0, 0, 0,
     key => '000102030405060708090a0b0c0d0e0f',
     nonce => '',
     header => '',
     plaintext => '',
     ciphertext => '',
     tag => '9ad07e7dbff301f505de596b9615dfff',
  },
  #/* test with nonce */
  {
     #16, 16, 0, 0,
     key => '000102030405060708090a0b0c0d0e0f',
     nonce => '000102030405060708090a0b0c0d0e0f',
     header => '',
     plaintext => '',
     ciphertext => '',
     tag => '1ce10d3effd4cadbe2e44b58d60ab9ec',
  },
  #/* test with header [no nonce]  */
  {
     #16, 0, 16, 0,
     key => '000102030405060708090a0b0c0d0e0f',
     nonce => '',
     header => '000102030405060708090a0b0c0d0e0f',
     plaintext => '',
     ciphertext => '',
     tag => '3a698f7a270e51b0f65b3d3e47193cff',
  },
  #/* test with header + nonce + plaintext */
  {
     #16, 16, 16, 32,
     key => '000102030405060708090a0b0c0d0e0f',
     nonce => '000102030405060708090a0b0c0d0e0f',
     header => '000102030405060708090a0b0c0d0e0f',
     plaintext => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
     ciphertext => '29d878d1a3be857b6fb8c8ea5950a778331fbf2ccf33986f35e8cf121dcb30bc',
     tag => '4fbe0338be1c8c7e1d7ae7e45b92c587',
  },
  #/* test with header + nonce + plaintext [not even sizes!] */
  {
     #16, 15, 14, 29,
     key => '000102030405060708090a0b0c0d0e0f',
     nonce => '000102030405060708090a0b0c0d0e',
     header => '000102030405060708090a0b0c0d',
     plaintext => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c',
     ciphertext => 'dd25c754c5b17c5928b69b73155f7bb8888faf37091ad92c8a24db868b',
     tag => '0d1a14e52224ffd23a05fa02cdef52da',
  },

  #/* Vectors from Brian Gladman */
  {
     #16, 16, 8, 0,
     key => '233952dee4d5ed5f9b9c6d6ff80ff478',
     nonce => '62ec67f9c3a4a407fcb2a8c49031a8b3',
     header => '6bfb914fd07eae6b',
     plaintext => '',
     ciphertext => '',
     tag => 'e037830e8389f27b025a2d6527e79d01',
  },
  {
     #16, 16, 8, 2,
     key => '91945d3f4dcbee0bf45ef52255f095a4',
     nonce => 'becaf043b0a23d843194ba972c66debd',
     header => 'fa3bfd4806eb53fa',
     plaintext => 'f7fb',
     ciphertext => '19dd',
     tag => '5c4c9331049d0bdab0277408f67967e5',
  },
  {
     #16, 16, 8, 5,
     key => '01f74ad64077f2e704c0f60ada3dd523',
     nonce => '70c3db4f0d26368400a10ed05d2bff5e',
     header => '234a3463c1264ac6',
     plaintext => '1a47cb4933',
     ciphertext => 'd851d5bae0',
     tag => '3a59f238a23e39199dc9266626c40f80',
  },
);
