use strict;
use warnings;
use Test::More;

use Crypt::PK::RSA qw(rsa_encrypt rsa_decrypt rsa_sign rsa_verify);

{
  my $k;

  $k = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa1.der');
  ok($k, 'load cryptx_priv_rsa1.der');
  ok($k->is_private, 'is_private cryptx_priv_rsa1.der');

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
 
 my $sig = $pr1->sign("message");
 ok(length $sig > 60, 'sign ' . length($sig));
 ok($pu1->verify($sig, "message"), 'verify');
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
  is($k->size, 256, 'size');
}

{
  my $ct = rsa_encrypt('t/data/cryptx_pub_rsa1.der', 'test string', 'none');
  ok($ct, 'rsa_encrypt');
  my $pt = rsa_decrypt('t/data/cryptx_priv_rsa1.der', $ct, 'none');
  ok($pt, 'rsa_decrypt');
  my $sig = rsa_sign('t/data/cryptx_priv_rsa1.der', 'test string');
  ok($sig, 'rsa_sign');
  ok(rsa_verify('t/data/cryptx_pub_rsa1.der', $sig, 'test string'), 'rsa_verify');
}

done_testing;