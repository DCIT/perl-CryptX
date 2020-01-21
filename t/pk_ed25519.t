use strict;
use warnings;
use Test::More tests => 74;

use Crypt::PK::Ed25519;
use Crypt::Misc qw(read_rawfile);

{
  my $k;

  # t/data/openssl_ed25519_sk.pem
  # ED25519 Private-Key:
  # priv = 45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD == RcEJum_STotn0j77a5LZnNRX4hNxcsDXSf4rWgwULa0
  # pub  = A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D == oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0

  my $sk_data = pack("H*", "45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD");
  $k = Crypt::PK::Ed25519->new->import_key_raw($sk_data, 'private');
  ok($k, 'new+import_key_raw raw-priv');
  ok($k->is_private, 'is_private raw-priv');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} raw-priv');
  is(uc($k->key2hash->{pub}),  'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} raw-priv');
  is($k->export_key_raw('private'), $sk_data, 'export_key_raw private');

  my $pk_data = pack("H*", "A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D");
  $k = Crypt::PK::Ed25519->new->import_key_raw($pk_data, 'public');
  ok($k, 'new+import_key_raw raw-pub');
  ok(!$k->is_private, '!is_private raw-pub');
  is(uc($k->key2hash->{pub}),  'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} raw-pub');
  is($k->export_key_raw('public'), $pk_data, 'export_key_raw public');

  my $sk_jwk = { kty=>"OKP",crv=>"Ed25519",d=>"RcEJum_STotn0j77a5LZnNRX4hNxcsDXSf4rWgwULa0",x=>"oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0" };
  $k = Crypt::PK::Ed25519->new($sk_jwk);
  ok($k, 'new JWKHASH/priv');
  ok($k->is_private, 'is_private JWKHASH/priv');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} JWKHASH/priv');
  ok(eq_hash($sk_jwk, $k->export_key_jwk('private', 1)), 'JWKHASH export private');

  my $pk_jwk = { kty=>"OKP",crv=>"Ed25519",x=>"oF0a6lgwrJplzfs4RmDUl-NpfEa0Gc8s7IXei9JFRZ0" };
  $k = Crypt::PK::Ed25519->new($pk_jwk);
  ok($k, 'new JWKHASH/pub');
  ok(!$k->is_private, '!is_private JWKHASH/pub');
  is(uc($k->key2hash->{pub}), 'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} JWKHASH/pub');
  ok(eq_hash($pk_jwk, $k->export_key_jwk('public', 1)), 'JWKHASH export public');

  $k = Crypt::PK::Ed25519->new('t/data/jwk_ed25519-priv1.json');
  ok($k, 'new JWK/priv');
  ok($k->is_private, 'is_private JWK/priv');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} JWK/priv');

  $k = Crypt::PK::Ed25519->new('t/data/jwk_ed25519-pub1.json');
  ok($k, 'new JWK/pub');
  ok(!$k->is_private, '!is_private JWK/pub');
  is(uc($k->key2hash->{pub}), 'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} JWK/pub');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk.der');
  ok($k, 'new openssl_ed25519_sk.der');
  ok($k->is_private, 'is_private openssl_ed25519_sk.der');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk.der');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk.pem');
  ok($k, 'new openssl_ed25519_sk.pem');
  ok($k->is_private, 'is_private openssl_ed25519_sk.pem');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk_t.pem');
  ok($k, 'new openssl_ed25519_sk_t.pem');
  ok($k->is_private, 'is_private openssl_ed25519_sk_t.pem');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk_t.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk.pkcs8');
  ok($k, 'new openssl_ed25519_sk.pkcs8');
  ok($k->is_private, 'is_private openssl_ed25519_sk.pkcs8');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk.pkcs8');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk_pbes1.pkcs8', 'secret');
  ok($k, 'new openssl_ed25519_sk_pbes1.pkcs8');
  ok($k->is_private, 'is_private openssl_ed25519_sk_pbes1.pkcs8');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk_pbes1.pkcs8');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk_pbes2.pkcs8', 'secret');
  ok($k, 'new openssl_ed25519_sk_pbes2.pkcs8');
  ok($k->is_private, 'is_private openssl_ed25519_sk_pbes2.pkcs8');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk_pbes2.pkcs8');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk_pw.pem', 'secret');
  ok($k, 'new openssl_ed25519_sk_pw.pem');
  ok($k->is_private, 'is_private openssl_ed25519_sk_pw.pem');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk_pw.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_sk_pw_t.pem', 'secret');
  ok($k, 'new openssl_ed25519_sk_pw_t.pem');
  ok($k->is_private, 'is_private openssl_ed25519_sk_pw_t.pem');
  is(uc($k->key2hash->{priv}), '45C109BA6FD24E8B67D23EFB6B92D99CD457E2137172C0D749FE2B5A0C142DAD', 'key2hash->{priv} openssl_ed25519_sk_pw_t.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_pk.pem');
  ok($k, 'new openssl_ed25519_pk.pem');
  ok(!$k->is_private, '!is_private openssl_ed25519_pk.pem');
  is(uc($k->key2hash->{pub}), 'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} openssl_ed25519_pk.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_x509.pem');
  ok($k, 'new openssl_ed25519_x509.pem');
  ok(!$k->is_private, '!is_private openssl_ed25519_x509.pem');
  is(uc($k->key2hash->{pub}), 'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} openssl_ed25519_x509.pem');

  $k = Crypt::PK::Ed25519->new('t/data/openssl_ed25519_x509.der');
  ok($k, 'new openssl_ed25519_x509.der');
  ok(!$k->is_private, '!is_private openssl_ed25519_x509.der');
  is(uc($k->key2hash->{pub}), 'A05D1AEA5830AC9A65CDFB384660D497E3697C46B419CF2CEC85DE8BD245459D', 'key2hash->{pub} openssl_ed25519_x509.der');

  $k = Crypt::PK::Ed25519->new('t/data/ssh/ssh_ed25519.pub');
  ok($k, 'new ssh_ed25519.pub');
  ok(!$k->is_private, '!is_private ssh_ed25519.pub');
  is(uc($k->key2hash->{pub}), 'BD17B2215C443A7A1E9B286A4F0E76288130984CD942ACCCD4F1A064BB749FBE', 'key2hash->{pub} ssh_ed25519.pub');

  $k = Crypt::PK::Ed25519->new('t/data/ssh/ssh_ed25519.pub.rfc4716');
  ok($k, 'new ssh_ed25519.pub.rfc4716');
  ok(!$k->is_private, '!is_private ssh_ed25519.pub.rfc4716');
  is(uc($k->key2hash->{pub}), 'BD17B2215C443A7A1E9B286A4F0E76288130984CD942ACCCD4F1A064BB749FBE', 'key2hash->{pub} ssh_ed25519.pub.rfc4716');

  ### $k = Crypt::PK::Ed25519->new('t/data/ssh/ssh_ed25519.priv');
  ### ok($k, 'new ssh_ed25519.priv');
  ## ok($k->is_private, 'is_private ssh_ed25519.priv');

  ### $k = Crypt::PK::Ed25519->new('t/data/ssh/ssh_ed25519_pw.priv', 'secret');
  ### ok($k, 'new ssh_ed25519_pw.priv');
  ### ok($k->is_private, 'is_private ssh_ed25519_pw.priv');
}

{
  my $k = Crypt::PK::Ed25519->new;
  $k->generate_key;
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  for (qw( openssl_ed25519_pk.der openssl_ed25519_pk.pem )) {
    my $k = Crypt::PK::Ed25519->new("t/data/$_");
    is($k->export_key_der('public'), read_rawfile("t/data/$_"), 'export_key_der public') if (substr($_, -3) eq "der");
    is($k->export_key_pem('public'), read_rawfile("t/data/$_"), 'export_key_pem public') if (substr($_, -3) eq "pem");
  }

  for (qw( openssl_ed25519_sk.der openssl_ed25519_sk_t.pem )) {
    my $k = Crypt::PK::Ed25519->new("t/data/$_");
    is($k->export_key_der('private'), read_rawfile("t/data/$_"), 'export_key_der private') if (substr($_, -3) eq "der");
    is($k->export_key_pem('private'), read_rawfile("t/data/$_"), 'export_key_pem private') if (substr($_, -3) eq "pem");
  }
}

{
  my $sk = Crypt::PK::Ed25519->new;
  $sk->import_key('t/data/openssl_ed25519_sk.der');
  my $pk = Crypt::PK::Ed25519->new;
  $pk->import_key('t/data/openssl_ed25519_pk.der');

  my $sig = $sk->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pk->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $sk->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pk->verify_hash($sig, $hash, 'SHA1'), 'verify_hash');
}

