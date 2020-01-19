use strict;
use warnings;
use Test::More tests => 46;

use Crypt::PK::X25519;

{
  my $k;

  # t/data/openssl_x25519_sk.pem
  # X25519 Private-Key:
  # priv = 002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651 == AC-T0Qulco2N2OlSdyHaujJhwLsb7957S72sYx1FRlE
  # pub  = EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41 == 6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE

  $k = Crypt::PK::X25519->new->import_key_raw(pack("H*", "002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651"), 'private');
  ok($k, 'new+import_key_raw raw-priv');
  ok($k->is_private, 'is_private raw-priv');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} raw-priv');
  is(uc($k->key2hash->{pub}),  'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} raw-priv');

  $k = Crypt::PK::X25519->new->import_key_raw(pack("H*", "EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41"), 'public');
  ok($k, 'new+import_key_raw raw-pub');
  ok(!$k->is_private, '!is_private raw-pub');
  is(uc($k->key2hash->{pub}),  'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} raw-pub');

  $k = Crypt::PK::X25519->new({ kty=>"OKP",crv=>"X25519",d=>"AC-T0Qulco2N2OlSdyHaujJhwLsb7957S72sYx1FRlE",x=>"6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE"});
  ok($k, 'new JWKHASH/priv');
  ok($k->is_private, 'is_private JWKHASH/priv');
  is(uc($k->key2hash->{priv}), '002F93D10BA5728D8DD8E9527721DABA3261C0BB1BEFDE7B4BBDAC631D454651', 'key2hash->{priv} JWKHASH/priv');

  $k = Crypt::PK::X25519->new({ kty=>"OKP",crv=>"X25519",x=>"6ngG9yGoVwUSyPbvtOjWIMSaUp5N9eqnfexkb7HofkE"});
  ok($k, 'new JWKHASH/pub');
  ok(!$k->is_private, '!is_private JWKHASH/pub');
  is(uc($k->key2hash->{pub}), 'EA7806F721A8570512C8F6EFB4E8D620C49A529E4DF5EAA77DEC646FB1E87E41', 'key2hash->{pub} JWKHASH/pub');

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
