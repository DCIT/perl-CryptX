use strict;
use warnings;
use Test::More;

use Crypt::PK::DSA qw(dsa_encrypt dsa_decrypt dsa_sign dsa_verify);

{
  my $k;

  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.der');
  ok($k, 'load cryptx_priv_dsa1.der');
  ok($k->is_private, 'is_private cryptx_priv_dsa1.der');

  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa2.der');
  ok($k, 'load cryptx_priv_dsa2.der');
  ok($k->is_private, 'is_private cryptx_priv_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa1.der');
  ok($k, 'load cryptx_pub_dsa1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa1.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa2.der');
  ok($k, 'load cryptx_pub_dsa2.der');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa1.der');
  ok($k, 'load openssl_dsa1.der');
  ok($k->is_private, 'is_private openssl_dsa1.der');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa2.der');
  ok($k, 'load openssl_dsa2.der');
  ok($k->is_private, 'is_private openssl_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.pem');
  ok($k, 'load cryptx_priv_dsa1.pem');
  ok($k->is_private, 'is_private cryptx_priv_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa2.pem');
  ok($k, 'load cryptx_priv_dsa2.pem');
  ok($k->is_private, 'is_private cryptx_priv_dsa2.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa1.pem');
  ok($k, 'load cryptx_pub_dsa1.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa2.pem');
  ok($k, 'load cryptx_pub_dsa2.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa2.pem');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa1.pem');
  ok($k, 'load openssl_dsa1.pem');
  ok($k->is_private, 'is_private openssl_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa2.pem');
  ok($k, 'load openssl_dsa2.pem');
  ok($k->is_private, 'is_private openssl_dsa2.pem');
}

{
 my $pr1 = Crypt::PK::DSA->new;
 $pr1->import_key('t/data/cryptx_priv_dsa1.der');
 my $pu1 = Crypt::PK::DSA->new;
 $pu1->import_key('t/data/cryptx_pub_dsa1.der');
 
 my $ct = $pu1->encrypt("secret message");
 my $pt = $pr1->decrypt($ct);
 ok(length $ct > 200, 'encrypt ' . length($ct));
 is($pt, "secret message", 'decrypt');
 
 my $sig = $pr1->sign("message");
 ok(length $sig > 60, 'sign ' . length($sig));
 ok($pu1->verify($sig, "message"), 'verify');
 
  my $pr2 = Crypt::PK::DSA->new;
 $pr2->import_key('t/data/cryptx_priv_dsa2.der');
 my $pu2 = Crypt::PK::DSA->new;
 $pu2->import_key('t/data/cryptx_pub_dsa2.der');
 
 #my $ss1 = $pr1->shared_secret($pu2);
 #my $ss2 = $pr2->shared_secret($pu1);
 #is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::DSA->new;
  $k->generate_key(20, 128);
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
  is($k->size, 128, 'size');
}

{
  my $ct = dsa_encrypt('t/data/cryptx_pub_dsa1.der', 'test string');
  ok($ct, 'dsa_encrypt');
  my $pt = dsa_decrypt('t/data/cryptx_priv_dsa1.der', $ct);
  ok($pt, 'dsa_decrypt');
  my $sig = dsa_sign('t/data/cryptx_priv_dsa1.der', 'test string');
  ok($sig, 'dsa_sign');
  ok(dsa_verify('t/data/cryptx_pub_dsa1.der', $sig, 'test string'), 'dsa_verify');
}

done_testing;