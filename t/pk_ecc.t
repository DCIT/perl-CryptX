use strict;
use warnings;
use Test::More tests => 121;

use Crypt::PK::ECC qw(ecc_encrypt ecc_decrypt ecc_sign_message ecc_verify_message ecc_sign_hash ecc_verify_hash ecc_shared_secret);
use Crypt::Misc qw(read_rawfile);

{
  my ($k, $k2);

  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc1.der');
  ok($k, 'load cryptx_priv_ecc1.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc1.der');
  is($k->size, 32, 'size');
  is(uc($k->key2hash->{pub_x}), 'C068B754877A4AB328A569BAC6D464A81B17E527D2D652572ABB11BDA3572D50', 'key2hash');
  is(uc($k->curve2hash->{prime}), 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'curve2hash');

  $k2 = Crypt::PK::ECC->new;
  $k2->import_key(\$k->export_key_pem('private'));
  is($k->export_key_der('private'), $k2->export_key_der('private'), 'import_key priv pem');

  $k2 = Crypt::PK::ECC->new;
  $k2->import_key(\$k->export_key_pem('public'));
  is($k->export_key_der('public'), $k2->export_key_der('public'), 'import_key pub pem');

  $k2 = Crypt::PK::ECC->new;
  $k2->import_key($k->key2hash);
  is($k->export_key_der('private'), $k2->export_key_der('private'), 'import_key hash');

  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc2.der');
  ok($k, 'load cryptx_priv_ecc2.der');
  ok($k->is_private, 'is_private cryptx_priv_ecc2.der');

  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc1.der');
  ok($k, 'load cryptx_pub_ecc1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc1.der');

  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc2.der');
  ok($k, 'load cryptx_pub_ecc2.der');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc2.der');

  ### XXX-TODO regenerate keys
  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc1.pem');
  ok($k, 'load cryptx_priv_ecc1.pem');
  ok($k->is_private, 'is_private cryptx_priv_ecc1.pem');

  $k = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc2.pem');
  ok($k, 'load cryptx_priv_ecc2.pem');
  ok($k->is_private, 'is_private cryptx_priv_ecc2.pem');

  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc1.pem');
  ok($k, 'load cryptx_pub_ecc1.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc1.pem');

  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc2.pem');
  ok($k, 'load cryptx_pub_ecc2.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_ecc2.pem');
  $k = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc2.pem');

  for (qw( cryptx_pub_ecc1.der cryptx_pub_ecc1.pem cryptx_pub_ecc2.der cryptx_pub_ecc2.pem )) {
    $k = Crypt::PK::ECC->new("t/data/$_");
    is($k->export_key_der('public'), read_rawfile("t/data/$_"), 'export_key_der public') if (substr($_, -3) eq "der");
    is($k->export_key_pem('public'), read_rawfile("t/data/$_"), 'export_key_pem public') if (substr($_, -3) eq "pem");
  }

  for (qw( cryptx_priv_ecc1.der cryptx_priv_ecc1.pem cryptx_priv_ecc2.der cryptx_priv_ecc2.pem )) {
    $k = Crypt::PK::ECC->new("t/data/$_");
    is($k->export_key_der('private'), read_rawfile("t/data/$_"), 'export_key_der private') if (substr($_, -3) eq "der");
    is($k->export_key_pem('private'), read_rawfile("t/data/$_"), 'export_key_pem private') if (substr($_, -3) eq "pem");
  }

  for (qw( openssl_ec1.pub.pem openssl_ec1.pub.der openssl_ec1.pubc.der openssl_ec1.pubc.pem
           cryptx_pub_ecc1_OLD.der cryptx_pub_ecc1_OLD.pem cryptx_pub_ecc2_OLD.der cryptx_pub_ecc2_OLD.pem )) {
    $k = Crypt::PK::ECC->new("t/data/$_");
    ok($k, "load $_");
    ok(!$k->is_private, "is_private $_");
  }
  for (qw( openssl_ec1.pri.der openssl_ec1.pri.pem openssl_ec1.pric.der openssl_ec1.pric.pem openssl_ec1.key.pem
           cryptx_priv_ecc1_OLD.der cryptx_priv_ecc1_OLD.pem cryptx_priv_ecc2_OLD.der cryptx_priv_ecc2_OLD.pem )) {
    $k = Crypt::PK::ECC->new("t/data/$_");
    ok($k, "load $_");
    ok($k->is_private, "is_private $_");
  }
}

{
  my $pr1 = Crypt::PK::ECC->new;
  $pr1->import_key('t/data/cryptx_priv_ecc1.der');
  my $pu1 = Crypt::PK::ECC->new;
  $pu1->import_key('t/data/cryptx_pub_ecc1.der');

  my $ct = $pu1->encrypt("secret message");
  my $pt = $pr1->decrypt($ct);
  ok(length $ct > 30, 'encrypt ' . length($ct));
  is($pt, "secret message", 'decrypt');

  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $sig_rfc7518 = $pr1->sign_message_rfc7518("message");
  ok(length $sig_rfc7518 > 60, 'sign_message_rfc7518 ' . length($sig_rfc7518));
  ok($pu1->verify_message_rfc7518($sig_rfc7518, "message"), 'verify_message_rfc7518');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash');

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
  $k->generate_key('secp224r1');
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  #ok($k->export_key_pem('private'), 'export_key_pem pri');
  #ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
  ok($k->export_key_der('private_short'), 'export_key_der pri_short');
  ok($k->export_key_der('public_short'), 'export_key_der pub_short');
}

{
  my $ct = ecc_encrypt('t/data/cryptx_pub_ecc1.der', 'test string');
  ok($ct, 'ecc_encrypt');
  my $pt = ecc_decrypt('t/data/cryptx_priv_ecc1.der', $ct);
  ok($pt, 'ecc_decrypt');
  my $sig = ecc_sign_message('t/data/cryptx_priv_ecc1.der', 'test string');
  ok($sig, 'ecc_sign_message');
  ok(ecc_verify_message('t/data/cryptx_pub_ecc1.der', $sig, 'test string'), 'ecc_verify_message');
  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = ecc_sign_hash('t/data/cryptx_priv_ecc1.der', $hash, 'SHA1');
  ok($sig, 'ecc_sign_hash');
  ok(ecc_verify_hash('t/data/cryptx_pub_ecc1.der', $sig, $hash, 'SHA1'), 'ecc_verify_hash');

  my $ss1 = ecc_shared_secret('t/data/cryptx_priv_ecc1.der', 't/data/cryptx_pub_ecc2.der');
  my $ss2 = ecc_shared_secret('t/data/cryptx_priv_ecc2.der', 't/data/cryptx_pub_ecc1.der');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

for my $priv (qw/openssl_ec-short.pem openssl_ec-short.der/) {
  my $f = "t/data/$priv";
  my $k = Crypt::PK::ECC->new($f);
  ok($k, "load $priv");
  ok($k->is_private, "is_private $priv");
  is($k->size, 32, "size $priv");
  is(uc($k->key2hash->{pub_x}), 'A01532A3C0900053DE60FBEFEFCCA58793301598D308B41E6F4E364E388C2711', "key2hash $priv");
  is(uc($k->curve2hash->{prime}), 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', "curve2hash $priv");
  is($k->key2hash->{curve_name}, "secp256r1", "EC curve_name is lowercase");
  is($k->export_key_der('private_short'), read_rawfile($f), 'export_key_der private_oid') if (substr($priv, -3) eq "der");
  is($k->export_key_pem('private_short'), read_rawfile($f), 'export_key_pem private_oid') if (substr($priv, -3) eq "pem");
}

for my $pub (qw/openssl_ec-short.pub.pem openssl_ec-short.pub.der/) {
  my $f = "t/data/$pub";
  my $k = Crypt::PK::ECC->new($f);
  ok($k, "load $pub");
  ok(!$k->is_private, "is_private $pub");
  is($k->size, 32, "$pub size");
  is(uc($k->key2hash->{pub_x}), 'A01532A3C0900053DE60FBEFEFCCA58793301598D308B41E6F4E364E388C2711', "key2hash $pub");
  is($k->key2hash->{curve_name}, "secp256r1", "EC curve_name is lowercase");
  is($k->export_key_der('public_short'), read_rawfile($f), 'export_key_der public_short') if (substr($pub, -3) eq "der");
  is($k->export_key_pem('public_short'), read_rawfile($f), 'export_key_pem public_short') if (substr($pub, -3) eq "pem");
}

{
  my $k = Crypt::PK::ECC->new;
  eval { $k->export_key_pem('public'); };
  ok($@, 'key not generated');

  # known curves lookup
  my $params = { # NIST P-384
      prime    => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
      A        => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
      B        => "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
      Gx       => "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
      Gy       => "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
      order    => "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
      cofactor => 1,
  };
  $k = Crypt::PK::ECC->new;
  ok($k->generate_key($params), "generate_key hash params");
  is($k->key2hash->{curve_name}, 'secp384r1',    "key2hash curve_name");
  is($k->key2hash->{curve_oid},  '1.3.132.0.34', "key2hash curve_oid");
  ok($k->export_key_der('private_short'), "export_key_der auto oid");

  $k = Crypt::PK::ECC->new;
  ok($k->generate_key({ %$params, cofactor => 6 }), "generate_key invalid auto oid");
  ok(!exists($k->key2hash->{curve_name}) || $k->key2hash->{curve_name} eq 'custom', "key2hash custom curve_name");
  ok(!exists($k->key2hash->{curve_oid}), "key2hash curve_oid doesn't exist");
  eval { $k->export_key_der('private_short'); };
  ok($@, "export_key_der invalid auto oid");
}
