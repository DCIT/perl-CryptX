use strict;
use warnings;
use Test::More;

use Crypt::PK::ECC qw(ecc_encrypt ecc_decrypt ecc_sign_message ecc_verify_message ecc_sign_hash ecc_verify_hash ecc_shared_secret);

{
  my $k;

  $k = Crypt::PK::ECC->new->import_key_backcompat('t/data/cryptx_priv_ecc1.der');       #XXX-TODO-FIXME
  ok($k, 'load cryptx_priv_ecc1.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc1.der');
  is($k->size, 32, 'size');
  is(uc($k->key2hash->{pub_x}), 'AB53ED5D16CE550BAAF16BA4F161332AAD56D63790629C27871ED515D4FC229C', 'key2hash');

  $k = Crypt::PK::ECC->new->import_key_backcompat('t/data/cryptx_priv_ecc2.der');       #XXX-TODO-FIXME
  ok($k, 'load cryptx_priv_ecc2.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc2.der');
  
  $k = Crypt::PK::ECC->new->import_key_backcompat('t/data/cryptx_pub_ecc1.der');        #XXX-TODO-FIXME
  ok($k, 'load cryptx_pub_ecc1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc1.der');
  
  $k = Crypt::PK::ECC->new->import_key_backcompat('t/data/cryptx_pub_ecc2.der');        #XXX-TODO-FIXME
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
  $pr1->import_key_backcompat('t/data/cryptx_priv_ecc1.der');                   #XXX-TODO-FIXME
  my $pu1 = Crypt::PK::ECC->new;
  $pu1->import_key_backcompat('t/data/cryptx_pub_ecc1.der');                    #XXX-TODO-FIXME
 
  my $ct = $pu1->encrypt("secret message");
  my $pt = $pr1->decrypt($ct);
  ok(length $ct > 100, 'encrypt ' . length($ct));
  is($pt, "secret message", 'decrypt');
 
  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash'); 
 
  my $pr2 = Crypt::PK::ECC->new;
  $pr2->import_key_backcompat('t/data/cryptx_priv_ecc2.der');                   #XXX-TODO-FIXME
  my $pu2 = Crypt::PK::ECC->new;
  $pu2->import_key_backcompat('t/data/cryptx_pub_ecc2.der');                    #XXX-TODO-FIXME
 
  my $ss1 = $pr1->shared_secret($pu2);
  my $ss2 = $pr2->shared_secret($pu1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::ECC->new;
  $k->generate_key('secp224r1');
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  #ok($k->export_key_pem('private'), 'export_key_pem pri');
  #ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

#{
#XXX-TODO-FIXME keys t/data/* has to be in new format
#  my $ct = ecc_encrypt('t/data/cryptx_pub_ecc1.der', 'test string');
#  ok($ct, 'ecc_encrypt');
#  my $pt = ecc_decrypt('t/data/cryptx_priv_ecc1.der', $ct);
#  ok($pt, 'ecc_decrypt');
#  my $sig = ecc_sign_message('t/data/cryptx_priv_ecc1.der', 'test string');
#  ok($sig, 'ecc_sign_message');
#  ok(ecc_verify_message('t/data/cryptx_pub_ecc1.der', $sig, 'test string'), 'ecc_verify_message');
#  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
#  $sig = ecc_sign_hash('t/data/cryptx_priv_ecc1.der', $hash, 'SHA1');
#  ok($sig, 'ecc_sign_hash');
#  ok(ecc_verify_hash('t/data/cryptx_pub_ecc1.der', $sig, $hash, 'SHA1'), 'ecc_verify_hash');
#  
#  my $ss1 = ecc_shared_secret('t/data/cryptx_priv_ecc1.der', 't/data/cryptx_pub_ecc2.der');
#  my $ss2 = ecc_shared_secret('t/data/cryptx_priv_ecc2.der', 't/data/cryptx_pub_ecc1.der');
#  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
#}

done_testing;