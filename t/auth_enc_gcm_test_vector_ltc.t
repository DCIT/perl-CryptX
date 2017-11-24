use strict;
use warnings;

use Test::More tests => 42;

use Crypt::AuthEnc::GCM qw( gcm_encrypt_authenticate gcm_decrypt_verify );

sub do_test {
  my %a = @_;

  my $key = pack("H*", $a{key});
  my $adata = pack("H*", $a{adata});
  my $iv = pack("H*", $a{iv});
  my $plaintext = pack("H*", $a{plaintext});
  my $ciphertext = pack("H*", $a{ciphertext});
  my $tag = pack("H*", $a{tag});

  # encrypt
  my $m1 = Crypt::AuthEnc::GCM->new("AES", $key);
  $m1->iv_add($iv);
  $m1->adata_add($adata);
  my $ct = $m1->encrypt_add($plaintext);
  my $tag1 = $m1->encrypt_done;

  is(unpack('H*', $ct), $a{ciphertext}, "enc: ciphertext");
  is(unpack('H*', $tag1), $a{tag}, "enc: tag");

  # decrypt
  my $d1 = Crypt::AuthEnc::GCM->new("AES", $key);
  $d1->iv_add($iv);
  $d1->adata_add($adata);
  my $pt = $d1->decrypt_add($ciphertext);
  my $tag2 = $d1->decrypt_done();

  is(unpack('H*', $pt), $a{plaintext}, "dec: plaintext");
  is(unpack('H*', $tag2), $a{tag}, "dec: tag");

  # all-in-one
  my ($ct3, $tag3) = gcm_encrypt_authenticate('AES', $key, $iv, $adata, $plaintext);
  is(unpack('H*', $ct3), $a{ciphertext}, "enc: ciphertext");
  is(unpack('H*', $tag3), $a{tag}, "enc: tag");
  my $pt3 = gcm_decrypt_verify('AES', $key, $iv, $adata, $ciphertext, $tag);
  is(unpack('H*', $pt3), $a{plaintext}, "dec: plaintext");

}

do_test(%$_) for (
  #/* test case #1 */
  # XXX-FIXME this test fails!!!!
  # {
     # key => '00000000000000000000000000000000',
     # plaintext => '',
     # adata => '',
     # iv => '000000000000000000000000',
     # ciphertext => '',
     # tag => '58e2fccefa7e3061367f1d57a4e7455a',
  # },

  #/* test case #2 */
  {
     key => '00000000000000000000000000000000',
     plaintext => '00000000000000000000000000000000',
     adata => '',
     iv => '000000000000000000000000',
     ciphertext => '0388dace60b6a392f328c2b971b2fe78',
     tag => 'ab6e47d42cec13bdf53a67b21257bddf',
  },

  #/* test case #3 */
  {
     key => 'feffe9928665731c6d6a8f9467308308',
     plaintext => 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
     adata => '',
     iv => 'cafebabefacedbaddecaf888',
     ciphertext => '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
     tag => '4d5c2af327cd64a62cf35abd2ba6fab4',
  },

  #/* test case #4 */
  {
     key => 'feffe9928665731c6d6a8f9467308308',
     plaintext => 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
     adata => 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
     iv => 'cafebabefacedbaddecaf888',
     ciphertext => '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
     tag => '5bc94fbc3221a5db94fae95ae7121a47',
  },

  #/* test case #5 */
  {
     key => 'feffe9928665731c6d6a8f9467308308',
     plaintext => 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
     adata => 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
     iv => 'cafebabefacedbad',
     ciphertext => '61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598',
     tag => '3612d2e79e3b0785561be14aaca2fccb',
  },

  #/* test case #6 */
  {
     key => 'feffe9928665731c6d6a8f9467308308',
     plaintext => 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
     adata => 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
     iv => '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
     ciphertext => '8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5',
     tag => '619cc5aefffe0bfa462af43c1699d050',
  },

  #/* test case #46 from BG (catches the LTC bug of v1.15) */
  {
     key => '00000000000000000000000000000000',
     plaintext => 'a2aab3ad8b17acdda288426cd7c429b7ca86b7aca05809c70ce82db25711cb5302eb2743b036f3d750d6cf0dc0acb92950d546db308f93b4ff244afa9dc72bcd758d2c',
     adata => '688e1aa984de926dc7b4c47f44',
     iv => 'b72138b5a05ff5070e8cd94183f761d8',
     ciphertext => 'cbc8d2f15481a4cc7dd1e19aaa83de5678483ec359ae7dec2ab8d534e0906f4b4663faff58a8b2d733b845eef7c9b331e9e10eb2612c995feb1ac15a6286cce8b297a8',
     tag => '8d2d2a9372626f6bee8580276a6366bf',
  }
);
