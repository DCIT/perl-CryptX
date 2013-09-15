use strict;
use warnings;
use Test::More;

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

{
  my $k = Crypt::PK::RSA->new;
  $k->generate_key(256, 65537);
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
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

done_testing;