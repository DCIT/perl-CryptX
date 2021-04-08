use strict;
use warnings;
use Test::More tests => 52;

use Crypt::PK::RSA qw(rsa_encrypt rsa_decrypt rsa_sign_message rsa_verify_message rsa_sign_hash rsa_verify_hash);

{
  my $k;

  $k = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa1.der');
  ok($k, 'load cryptx_priv_rsa1.der');
  ok($k->is_private, 'is_private cryptx_priv_rsa1.der');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{q}), 'FC07E46B163CAB6A83B8E467D169534B2077DCDEECAE8FCFC0C3AD2EBA2C4B02D2372369990C62A923D22E10719CED191E231C4832FB4896ECDC2E1F39688D226C7B46E35F93CBD83B1F56A30B6660E0BEE43E719C9F533EFB8A0618EC2D164CC0AE64F20AFB888C14EAFF8C8E889FF1227A31152B3E23432B40A11C6541BBE3', 'key2hash');

  $k = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa2.der');
  ok($k, 'load cryptx_priv_rsa2.der');
  ok($k->is_private, 'is_private cryptx_priv_rsa2.der');

  $k = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa1.der');
  ok($k, 'load cryptx_pub_rsa1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_rsa1.der');

  $k = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa2.der');
  ok($k, 'load cryptx_pub_rsa2.der');
  ok(!$k->is_private, 'is_private cryptx_pub_rsa2.der');

  $k = Crypt::PK::RSA->new('t/data/openssl_rsa1.der');
  ok($k, 'load openssl_rsa1.der');
  ok($k->is_private, 'is_private openssl_rsa1.der');

  $k = Crypt::PK::RSA->new('t/data/openssl_rsa2.der');
  ok($k, 'load openssl_rsa2.der');
  ok($k->is_private, 'is_private openssl_rsa2.der');

  $k = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa1.pem');
  ok($k, 'load cryptx_priv_rsa1.pem');
  ok($k->is_private, 'is_private cryptx_priv_rsa1.pem');

  $k = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa2.pem');
  ok($k, 'load cryptx_priv_rsa2.pem');
  ok($k->is_private, 'is_private cryptx_priv_rsa2.pem');

  $k = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa1.pem');
  ok($k, 'load cryptx_pub_rsa1.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_rsa1.pem');

  $k = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa2.pem');
  ok($k, 'load cryptx_pub_rsa2.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_rsa2.pem');

  $k = Crypt::PK::RSA->new('t/data/openssl_rsa1.pem');
  ok($k, 'load openssl_rsa1.pem');
  ok($k->is_private, 'is_private openssl_rsa1.pem');

  $k = Crypt::PK::RSA->new('t/data/openssl_rsa2.pem');
  ok($k, 'load openssl_rsa2.pem');
  ok($k->is_private, 'is_private openssl_rsa2.pem');

  # X509
  $k = Crypt::PK::RSA->new('t/data/openssl_rsa-x509.pem');
  ok($k, 'openssl_rsa-x509.pem');
  ok(!$k->is_private, 'not private openssl_rsa-x509.pem');
  $k = Crypt::PK::RSA->new('t/data/openssl_rsa-x509.der');
  ok($k, 'openssl_rsa-x509.der');
  ok(!$k->is_private, 'not private openssl_rsa-x509.der');
}

{
  my $pr1 = Crypt::PK::RSA->new;
  $pr1->import_key('t/data/cryptx_priv_rsa1.der');
  my $pu1 = Crypt::PK::RSA->new;
  $pu1->import_key('t/data/cryptx_pub_rsa1.der');

  my $ct = $pu1->encrypt("secret message");
  my $pt = $pr1->decrypt($ct);
  ok(length $ct > 200, 'encrypt ' . length($ct));
  is($pt, "secret message", 'decrypt');

  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash');
}
#XXX-FIXME somwhere here a crash happens on solaris - http://ppm4.activestate.com/sun4-solaris/5.14/1400/M/MI/MIK/CryptX-0.017.d/log-20130924T103600.txt
{
  my $k = Crypt::PK::RSA->new;
  $k->generate_key(256, 65537);
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_pem('public_x509'), 'export_key_pem pub_x509');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $ct = rsa_encrypt('t/data/cryptx_pub_rsa1.der', 'test string', 'none');
  ok($ct, 'rsa_encrypt');
  my $pt = rsa_decrypt('t/data/cryptx_priv_rsa1.der', $ct, 'none');
  ok($pt, 'rsa_decrypt');
  my $sig = rsa_sign_message('t/data/cryptx_priv_rsa1.der', 'test string');
  ok($sig, 'rsa_sign_message');
  ok(rsa_verify_message('t/data/cryptx_pub_rsa1.der', $sig, 'test string'), 'rsa_verify_message');
  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = rsa_sign_hash('t/data/cryptx_priv_rsa1.der', $hash, 'SHA1');
  ok($sig, 'rsa_sign_hash');
  ok(rsa_verify_hash('t/data/cryptx_pub_rsa1.der', $sig, $hash, 'SHA1'), 'rsa_verify_hash');
}

{
  ## https://github.com/DCIT/perl-CryptX/issues/69

  # my $priv = Crypt::PK::RSA->new({
  #   e => "03",
  #   N => "E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230".
  #        "AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306".
  #        "E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A".
  #        "2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88".
  #        "D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7",
  #   d => "009b771db6c374e59227006de8f9c5ba85cf98c63754505f9f30939803afc1498eda44b1b1e32c7eb51519edbd9591ea4fce0f81".
  #        "75ca528e09939e48f37088a07059c36332f74368c06884f718c9f8114f1b8d4cb790c63b09d46778bfdc41348fb4cd9feab3d242".
  #        "04992c6dd9ea824fbca591cd64cf68a233ad0526775c9848fafa31528177e1f8df9181a8b945081106fd58bd3d73799b229575c4".
  #        "f3b29101a03ee1f05472b3615784d9244ce0ed639c77e8e212ab52abddf4a928224b6b6f74b7114786dd6071bd9113d7870c6b52".
  #        "c0bc8b9c102cfe321dac357e030ed6c580040ca41c13d6b4967811807ef2a225983ea9f88d67faa42620f42a4f5bdbe03b",
  # });
  # my $sig_hex = unpack("H*", $priv->sign_message('hello world!', 'SHA256', 'v1.5'));

  my $pub = Crypt::PK::RSA->new({
    e => "03",
    N => "E932AC92252F585B3A80A4DD76A897C8B7652952FE788F6EC8DD640587A1EE5647670A8AD4C2BE0F9FA6E49C605ADF77B5174230".
         "AF7BD50E5D6D6D6D28CCF0A886A514CC72E51D209CC772A52EF419F6A953F3135929588EBE9B351FCA61CED78F346FE00DBB6306".
         "E5C2A4C6DFC3779AF85AB417371CF34D8387B9B30AE46D7A5FF5A655B8D8455F1B94AE736989D60A6F2FD5CADBFFBD504C5A756A".
         "2E6BB5CECC13BCA7503F6DF8B52ACE5C410997E98809DB4DC30D943DE4E812A47553DCE54844A78E36401D13F77DC650619FED88".
         "D8B3926E3D8E319C80C744779AC5D6ABE252896950917476ECE5E8FC27D5F053D6018D91B502C4787558A002B9283DA7",
  });

  my $sig1 = pack("H*", "8df69d774c6ac8b5f8aa16576ca37a4f948706c5daecb3c15cfd247a7657616b2bbb786b50158cac8c23e3".
                        "289d300d3fbb82380b8746d929df36bdaf43a5fc5d1d04c61c98d47c22de02d051be3ba9e42b1c47aa5192".
                        "66d4cae244e5ce99b24771a13a7c8c7b08868a3eccf70b4bc7570d5131a1ac8943d91b0151c39da2ad75cd".
                        "1b9a697d100eef6747217df581b272cfd1f549a901ff4951036a4eb28fd2ea1e9df3fa9fa457663f4259be".
                        "8e5f2f2fb84f831a0ca5320e2b79f04a17830f43062c4c8fc0d0b1ff90567f3342d524f682ca26661caadf".
                        "4272f2585e6013a92bfa68de72fe6174096890e4296aedd72da43aa508007df53fb852bd7162ab635b");

  my $sig2 = pack("H*", "1ee08947536e6b11d8923c3b00061d26a6933b5345077ea0214fdcbcc1ad68395008ff709117047e6b01dd".
                        "2a371dfa032c0732abc86ab2e0273bbd0dfe6b1c769e21bb9079982801d8f72e01be3244959312ab09bb8f".
                        "88572dc23216719b9810c73edf826749604feb8da1345f83f0209271aca462c1235b4cb4ba538f85a9c03d".
                        "d1dde1856fe73fd86b95566df2dfe8b0895c34489b97e02c8e48dabad7067619edec6267a776fa416fbcac".
                        "0fcacf3efa7852ce33ed63a9149c685c303d98c3dc37ee87521bc5b130377345fc95c87aa48505470deaf6".
                        "fb1064df041e3f03322b1ec90d3608deb17bf77f47066ecc6c511bfba69eed6da42881dcce603fcb2a");

  my $sig3 = pack("H*", "02364fdabb83d98118fe3d3bb86866038de4dc6e569f59fd6dc0360d3785e7fbded2f5a4c6d87052aeab25".
                        "c451a91f8dccbc0d6db3b59ddd57368180091183369221b67a399a96ca5d318a908575462fe42d1aabba27".
                        "7b7b5bb2aae43567ecd671dfc1d8b935c7dc06d0058a45dadabfc21b1cbae3cb719f3bca8b1365576e2eb9".
                        "54cba048beba174e515a919148ac4a9ae3505b3a8ad6326b63757d1dd59a9f83df60bb295b32d90053b016".
                        "b4cd2745eb29f12a2aad86c05f04ebd3cca3a8c63c752ccad07d7fd4e6e2adab4f353efbda04a6b5b7f4a6".
                        "d540c085e7ddc90f1665adb048dfc707eac2db28246e1bffe53f115a02f7c74defccafa7213cb22245");

  is($pub->verify_message($sig1, 'hello world!', 'SHA256', 'v1.5'), 0, "github issue 69 - invalid signature/1");
  is($pub->verify_message($sig2, 'hello world!', 'SHA256', 'v1.5'), 0, "github issue 69 - invalid signature/2");
  is($pub->verify_message($sig3, 'hello world!', 'SHA256', 'v1.5'), 1, "github issue 69 - valid signature/3");
}
