use strict;
use warnings;
use Test::More tests => 44;

use Crypt::PK::DSA qw(dsa_encrypt dsa_decrypt dsa_sign_message dsa_verify_message dsa_sign_hash dsa_verify_hash);

{
  my $k;

  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.der');
  ok($k, 'load cryptx_priv_dsa1.der');
  ok($k->is_private, 'is_private cryptx_priv_dsa1.der');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{x}), '6C801901AC74E2DC714D75A9F6969483CF0239D142AB7E3F329ED8D49E07', 'key2hash');

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
  #XXX-FIXME somwhere here a crash happens on solaris - http://ppm4.activestate.com/sun4-solaris/5.14/1400/M/MI/MIK/CryptX-0.017.d/log-20130924T103600.txt
  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash'); 
 
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
}

{
  my $ct = dsa_encrypt('t/data/cryptx_pub_dsa1.der', 'test string');
  ok($ct, 'dsa_encrypt');
  my $pt = dsa_decrypt('t/data/cryptx_priv_dsa1.der', $ct);
  ok($pt, 'dsa_decrypt');
  my $sig = dsa_sign_message('t/data/cryptx_priv_dsa1.der', 'test string');
  ok($sig, 'dsa_sign_message');
  ok(dsa_verify_message('t/data/cryptx_pub_dsa1.der', $sig, 'test string'), 'dsa_verify_message');
  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = dsa_sign_hash('t/data/cryptx_priv_dsa1.der', $hash, 'SHA1');
  ok($sig, 'dsa_sign_hash');
  ok(dsa_verify_hash('t/data/cryptx_pub_dsa1.der', $sig, $hash, 'SHA1'), 'dsa_verify_hash');
}
