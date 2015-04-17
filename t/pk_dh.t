use strict;
use warnings;
use Test::More;

use Crypt::PK::DH qw(dh_encrypt dh_decrypt dh_sign_message dh_verify_message dh_sign_hash dh_verify_hash dh_shared_secret);

{
  my $k;

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh1.bin');
  ok($k, 'load cryptx_priv_dh1.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh1.bin');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{x}), 'FBC1062F73B9A17BB8473A2F5A074911FA7F20D28FBF5D7F4DAF58016CE03A391BA57CB80067EB2D59AD1AA66869F5F37A1B57D440428F67881085F7C1484FADC3A54E39703CE679068417269651DD3438EDBF7827A09419F88A326B76EF04D81145D87D7D2DCF1B24902202B971BBF2EEF956A1EA1A88770097B94C859AE4F06DDDEB9ED31084004815F97D4F6F74C791CF1EC1836013DF835B653E8704981D52FF2323F7AFE22915B82CBA7EBF0558ACA6A182A6F3D631B843B72137D4E5B07603A7517F6768B375FC6C38F7B767C63E5A3DD99CD9EA0992C236EB827EAD4E877430F260020E64CBA26DAA8DEEF5D216C11941C48F76FE2B097BB5D504FBCF', 'key2hash');
  
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
 
  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash'); 
 
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
}

{
  my $ct = dh_encrypt('t/data/cryptx_pub_dh1.bin', 'test string');
  ok($ct, 'dh_encrypt');
  my $pt = dh_decrypt('t/data/cryptx_priv_dh1.bin', $ct);
  ok($pt, 'dh_decrypt');
  my $sig = dh_sign_message('t/data/cryptx_priv_dh1.bin', 'test string');
  ok($sig, 'dh_sign_message');
  ok(dh_verify_message('t/data/cryptx_pub_dh1.bin', $sig, 'test string'), 'dh_verify_message');
  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = dh_sign_hash('t/data/cryptx_priv_dh1.bin', $hash, 'SHA1');
  ok($sig, 'dh_sign_hash');
  ok(dh_verify_hash('t/data/cryptx_pub_dh1.bin', $sig, $hash, 'SHA1'), 'dh_verify_hash');

  my $ss1 = dh_shared_secret('t/data/cryptx_priv_dh1.bin', 't/data/cryptx_pub_dh2.bin');
  my $ss2 = dh_shared_secret('t/data/cryptx_priv_dh2.bin', 't/data/cryptx_pub_dh1.bin');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

done_testing;