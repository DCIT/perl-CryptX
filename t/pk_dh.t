use strict;
use warnings;
use Test::More;

use Crypt::PK::DH qw(dh_encrypt dh_decrypt dh_sign dh_verify dh_shared_secret);

{
  my $k;

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh1.bin');
  ok($k, 'load cryptx_priv_dh1.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh1.bin');

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh2.bin');
  ok($k, 'load cryptx_priv_dh2.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh2.bin');
  
  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh1.bin');
  ok($k, 'load cryptx_pub_dh1.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh1.bin');
  
  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh2.bin');
  ok($k, 'load cryptx_pub_dh2.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh2.bin');
}

{
 my $pr1 = Crypt::PK::DH->new;
 $pr1->import_key('t/data/cryptx_priv_dh1.bin');
 my $pu1 = Crypt::PK::DH->new;
 $pu1->import_key('t/data/cryptx_pub_dh1.bin');
 
 my $ct = $pu1->encrypt("secret message");
 my $pt = $pr1->decrypt($ct);
 ok(length $ct > 100, 'encrypt ' . length($ct));
 is($pt, "secret message", 'decrypt');
 
 my $sig = $pr1->sign("message");
 ok(length $sig > 60, 'sign ' . length($sig));
 ok($pu1->verify($sig, "message"), 'verify');
 
  my $pr2 = Crypt::PK::DH->new;
 $pr2->import_key('t/data/cryptx_priv_dh2.bin');
 my $pu2 = Crypt::PK::DH->new;
 $pu2->import_key('t/data/cryptx_pub_dh2.bin');
 
 my $ss1 = $pr1->shared_secret($pu2);
 my $ss2 = $pr2->shared_secret($pu1);
 is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key(256);
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
  is($k->size, 256, 'size');
}

{
  my $ct = dh_encrypt('t/data/cryptx_pub_dh1.bin', 'test string');
  ok($ct, 'dh_encrypt');
  my $pt = dh_decrypt('t/data/cryptx_priv_dh1.bin', $ct);
  ok($pt, 'dh_decrypt');
  my $sig = dh_sign('t/data/cryptx_priv_dh1.bin', 'test string');
  ok($sig, 'dh_sign');
  ok(dh_verify('t/data/cryptx_pub_dh1.bin', $sig, 'test string'), 'dh_verify');
  
  my $ss1 = dh_shared_secret('t/data/cryptx_priv_dh1.bin', 't/data/cryptx_pub_dh2.bin');
  my $ss2 = dh_shared_secret('t/data/cryptx_priv_dh2.bin', 't/data/cryptx_pub_dh1.bin');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

done_testing;