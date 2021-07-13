use strict;
use warnings;

use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
plan tests => 69;

use Crypt::PK::X25519;
use Crypt::Misc qw(read_rawfile);

{
  my ($k, $k2);

  # t/data/openssl_x25519_sk.pem
  # X25519 Private-Key:
  # priv = 002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651 == AC-T0Qulco2N2OlSdyHaujJhwLsb7957S72sYx1FRlE
  # pub  = EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41 == 6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE

  my $sk_data = pack("H*", "002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651");
  $k = Crypt::PK::X25519->new->import_key_raw($sk_data, 'private');
  ok($k, 'new+import_key_raw raw-priv');
  ok($k->is_private, 'is_private raw-priv');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} raw-priv');
  is(uc($k->key2hash->{pub}),  'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} raw-priv');
  is($k->export_key_raw('private'), $sk_data, 'export_key_raw private');

  $k2 = Crypt::PK::X25519->new->import_key($k->key2hash);
  ok($k2->is_private, 'is_private raw-priv');
  is($k->export_key_der('private'), $k2->export_key_der('private'), 'import_key hash');

  my $pk_data = pack("H*", "EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41");
  $k = Crypt::PK::X25519->new->import_key_raw($pk_data, 'public');
  ok($k, 'new+import_key_raw raw-pub');
  ok(!$k->is_private, '!is_private raw-pub');
  is(uc($k->key2hash->{pub}),  'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} raw-pub');
  is($k->export_key_raw('public'), $pk_data, 'export_key_raw public');

  $k2 = Crypt::PK::X25519->new->import_key($k->key2hash);
  ok(!$k2->is_private, 'is_private raw-priv');
  is($k->export_key_der('public'), $k2->export_key_der('public'), 'import_key hash');

  my $sk_jwk = { kty=>"OKP",crv=>"X25519",d=>"AC-T0Qulco2N2OlSdyHaujJhwLsb7957S72sYx1FRlE",x=>"6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE" };
  $k = Crypt::PK::X25519->new($sk_jwk);
  ok($k, 'new JWKHASH/priv');
  ok($k->is_private, 'is_private JWKHASH/priv');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} JWKHASH/priv');
  ok(eq_hash($sk_jwk, $k->export_key_jwk('private', 1)), 'JWKHASH export private');

  my $pk_jwk = { kty=>"OKP",crv=>"X25519",x=>"6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE"};
  $k = Crypt::PK::X25519->new($pk_jwk);
  ok($k, 'new JWKHASH/pub');
  ok(!$k->is_private, '!is_private JWKHASH/pub');
  is(uc($k->key2hash->{pub}), 'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} JWKHASH/pub');
  ok(eq_hash($pk_jwk, $k->export_key_jwk('public', 1)), 'JWKHASH export public');

  $k = Crypt::PK::X25519->new('t/data/jwk_x25519-priv1.json');
  ok($k, 'new JWK/priv');
  ok($k->is_private, 'is_private JWK/priv');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} JWK/priv');

  $k = Crypt::PK::X25519->new('t/data/jwk_x25519-pub1.json');
  ok($k, 'new JWK/pub');
  ok(!$k->is_private, '!is_private JWK/pub');
  is(uc($k->key2hash->{pub}), 'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} JWK/pub');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk.der');
  ok($k, 'new openssl_x25519_sk.der');
  ok($k->is_private, 'is_private openssl_x25519_sk.der');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk.der');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk.pem');
  ok($k, 'new openssl_x25519_sk.pem');
  ok($k->is_private, 'is_private openssl_x25519_sk.pem');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk.pem');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk_t.pem');
  ok($k, 'new openssl_x25519_sk_t.pem');
  ok($k->is_private, 'is_private openssl_x25519_sk_t.pem');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk_t.pem');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk.pkcs8');
  ok($k, 'new openssl_x25519_sk.pkcs8');
  ok($k->is_private, 'is_private openssl_x25519_sk.pkcs8');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk.pkcs8');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk_pbes1.pkcs8', 'secret');
  ok($k, 'new openssl_x25519_sk_pbes1.pkcs8');
  ok($k->is_private, 'is_private openssl_x25519_sk_pbes1.pkcs8');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk_pbes1.pkcs8');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk_pbes2.pkcs8', 'secret');
  ok($k, 'new openssl_x25519_sk_pbes2.pkcs8');
  ok($k->is_private, 'is_private openssl_x25519_sk_pbes2.pkcs8');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk_pbes2.pkcs8');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk_pw.pem', 'secret');
  ok($k, 'new openssl_x25519_sk_pw.pem');
  ok($k->is_private, 'is_private openssl_x25519_sk_pw.pem');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk_pw.pem');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_sk_pw_t.pem', 'secret');
  ok($k, 'new openssl_x25519_sk_pw_t.pem');
  ok($k->is_private, 'is_private openssl_x25519_sk_pw_t.pem');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} openssl_x25519_sk_pw_t.pem');

  $k = Crypt::PK::X25519->new('t/data/openssl_x25519_pk.pem');
  ok($k, 'new openssl_x25519_pk.pem');
  ok(!$k->is_private, '!is_private openssl_x25519_pk.pem');
  is(uc($k->key2hash->{pub}), 'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} openssl_x25519_pk.pem');
}

{
  my $k = Crypt::PK::X25519->new;
  $k->generate_key;
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  for (qw( openssl_x25519_pk.der openssl_x25519_pk.pem )) {
    my $k = Crypt::PK::X25519->new("t/data/$_");
    is($k->export_key_der('public'), read_rawfile("t/data/$_"), 'export_key_der public') if (substr($_, -3) eq "der");
    is($k->export_key_pem('public'), read_rawfile("t/data/$_"), 'export_key_pem public') if (substr($_, -3) eq "pem");
  }

  for (qw( openssl_x25519_sk.der openssl_x25519_sk_t.pem )) {
    my $k = Crypt::PK::X25519->new("t/data/$_");
    is($k->export_key_der('private'), read_rawfile("t/data/$_"), 'export_key_der private') if (substr($_, -3) eq "der");
    is($k->export_key_pem('private'), read_rawfile("t/data/$_"), 'export_key_pem private') if (substr($_, -3) eq "pem");
  }
}

{
  my $sk1 = Crypt::PK::X25519->new;
  $sk1->import_key('t/data/openssl_x25519_sk.der');
  my $pk1 = Crypt::PK::X25519->new->import_key_raw($sk1->export_key_raw('public'), 'public');
  ok(!$pk1->is_private, '!is_private');

  my $sk2 = Crypt::PK::X25519->new;
  $sk2->generate_key;
  my $pk2 = Crypt::PK::X25519->new->import_key_raw($sk2->export_key_raw('public'), 'public');
  ok(!$pk2->is_private, '!is_private');

  my $ss1 = $sk1->shared_secret($pk2);
  my $ss2 = $sk2->shared_secret($pk1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}


# rfc7748 test vectors
{
   my $sk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), 'private');
   my $pk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"), 'public');
   is(unpack("H*", $sk->shared_secret($pk)), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
}
{
   my $sk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), 'private');
   my $pk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"), 'public');
   is(unpack("H*", $sk->shared_secret($pk)), "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}
{
   my $sk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), 'private');
   my $pk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), 'public');
   is(unpack("H*", $sk->shared_secret($pk)), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}
{
   my $sk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), 'private');
   my $pk = Crypt::PK::X25519->new->import_key_raw(pack("H*", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), 'public');
   is(unpack("H*", $sk->shared_secret($pk)), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
}
