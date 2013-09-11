use strict;
use warnings;
use Test::More;

use Crypt::PK::ECC qw(ecc_encrypt ecc_decrypt ecc_sign_message ecc_verify_message ecc_shared_secret);

{
  my $k;

  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc1.der');
  ok($k, 'load cryptx_priv_ecc1.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc1.der');
  is($k->size, 32, 'size');

  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc2.der');
  ok($k, 'load cryptx_priv_ecc2.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc2.der');
  
  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc1.der');
  ok($k, 'load cryptx_pub_ecc1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc1.der');
  
  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc2.der');
  ok($k, 'load cryptx_pub_ecc2.der');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc2.der');
   
  # $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc1.pem');
  # ok($k, 'load cryptx_priv_ecc1.pem');
  # ok($k->is_private, 'is_private cryptx_priv_ecc1.pem');
  
  # $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc2.pem');
  # ok($k, 'load cryptx_priv_ecc2.pem');
  # ok($k->is_private, 'is_private cryptx_priv_ecc2.pem');
  
  # $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc1.pem');
  # ok($k, 'load cryptx_pub_ecc1.pem');
  # ok(!$k->is_private, 'is_private cryptx_pub_ecc1.pem');
  
  # $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc2.pem');
  # ok($k, 'load cryptx_pub_ecc2.pem');
  # ok(!$k->is_private, 'is_private cryptx_pub_ecc2.pem');
}

{
  my $pr1 = Crypt::PK::ECC->new;
  $pr1->import_key('t/data/cryptx_priv_ecc1.der');
  my $pu1 = Crypt::PK::ECC->new;
  $pu1->import_key('t/data/cryptx_pub_ecc1.der');
 
  my $ct = $pu1->encrypt("secret message");
  my $pt = $pr1->decrypt($ct);
  ok(length $ct > 100, 'encrypt ' . length($ct));
  is($pt, "secret message", 'decrypt');
 
  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify');
 
  my $pr2 = Crypt::PK::ECC->new;
  $pr2->import_key('t/data/cryptx_priv_ecc2.der');
  my $pu2 = Crypt::PK::ECC->new;
  $pu2->import_key('t/data/cryptx_pub_ecc2.der');
 
  my $ss1 = $pr1->shared_secret($pu2);
  my $ss2 = $pr2->shared_secret($pu1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::ECC->new;
  $k->generate_key(32);
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  #ok($k->export_key_pem('private'), 'export_key_pem pri');
  #ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $ct = ecc_encrypt('t/data/cryptx_pub_ecc1.der', 'test string');
  ok($ct, 'ecc_encrypt');
  my $pt = ecc_decrypt('t/data/cryptx_priv_ecc1.der', $ct);
  ok($pt, 'ecc_decrypt');
  my $sig = ecc_sign_message('t/data/cryptx_priv_ecc1.der', 'test string');
  ok($sig, 'ecc_sign_message');
  ok(ecc_verify_message('t/data/cryptx_pub_ecc1.der', $sig, 'test string'), 'ecc_verify_message');
  
  my $ss1 = ecc_shared_secret('t/data/cryptx_priv_ecc1.der', 't/data/cryptx_pub_ecc2.der');
  my $ss2 = ecc_shared_secret('t/data/cryptx_priv_ecc2.der', 't/data/cryptx_pub_ecc1.der');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

done_testing;