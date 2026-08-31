use strict;
use warnings;

use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
plan tests => 76;

use Crypt::PK::X448;
use Crypt::Misc qw(read_rawfile);

my $sk_hex = '10D418B111401956ABC5A92C2FBB8406D1D646BA930FDEFA2108EFE68F2000973755AA952BE018F640947C05135FBF9925EBD4DA828D86EC';
my $pk_hex = 'CF807AB0FC3EFA03108469F29E499DB2EEFEFEB12544D8D4E711F187385AAF31B4F38C8F84A3DD9E43DA309FD410C3816A50E644B5500C05';
my $sk_jwk = {
  kty => 'OKP',
  crv => 'X448',
  d   => 'ENQYsRFAGVarxaksL7uEBtHWRrqTD976IQjv5o8gAJc3VaqVK-AY9kCUfAUTX7-ZJevU2oKNhuw',
  x   => 'z4B6sPw--gMQhGnynkmdsu7-_rElRNjU5xHxhzharzG084yPhKPdnkPaMJ_UEMOBalDmRLVQDAU',
};
my $pk_jwk = {
  kty => 'OKP',
  crv => 'X448',
  x   => 'z4B6sPw--gMQhGnynkmdsu7-_rElRNjU5xHxhzharzG084yPhKPdnkPaMJ_UEMOBalDmRLVQDAU',
};

{
  my ($k, $k2);
  my $sk_data = pack('H*', $sk_hex);
  my $pk_data = pack('H*', $pk_hex);

  $k = Crypt::PK::X448->new->import_key_raw($sk_data, 'private');
  ok($k, 'new+import_key_raw raw-priv');
  ok($k->is_private, 'is_private raw-priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} raw-priv');
  is(uc($k->key2hash->{pub}),  $pk_hex, 'key2hash->{pub} raw-priv');
  is($k->export_key_raw('private'), $sk_data, 'export_key_raw private');

  $k2 = Crypt::PK::X448->new->import_key($k->key2hash);
  ok($k2->is_private, 'import_key hash private');
  is($k->export_key_der('private'), $k2->export_key_der('private'), 'private hash roundtrip');

  $k = Crypt::PK::X448->new->import_key_raw($pk_data, 'public');
  ok($k, 'new+import_key_raw raw-pub');
  ok(!$k->is_private, '!is_private raw-pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} raw-pub');
  is($k->export_key_raw('public'), $pk_data, 'export_key_raw public');

  $k2 = Crypt::PK::X448->new->import_key($k->key2hash);
  ok(!$k2->is_private, 'import_key hash public');
  is($k->export_key_der('public'), $k2->export_key_der('public'), 'public hash roundtrip');

  $k = Crypt::PK::X448->new($sk_jwk);
  ok($k, 'new JWKHASH/priv');
  ok($k->is_private, 'is_private JWKHASH/priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} JWKHASH/priv');
  is_deeply($k->export_key_jwk('private', 1), $sk_jwk, 'JWKHASH export private');

  $k = Crypt::PK::X448->new($pk_jwk);
  ok($k, 'new JWKHASH/pub');
  ok(!$k->is_private, '!is_private JWKHASH/pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} JWKHASH/pub');
  is_deeply($k->export_key_jwk('public', 1), $pk_jwk, 'JWKHASH export public');

  $k = Crypt::PK::X448->new('t/data/jwk_x448-priv1.json');
  ok($k, 'new JWK/priv');
  ok($k->is_private, 'is_private JWK/priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} JWK/priv');

  $k = Crypt::PK::X448->new('t/data/jwk_x448-pub1.json');
  ok($k, 'new JWK/pub');
  ok(!$k->is_private, '!is_private JWK/pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} JWK/pub');
}

{
  my @private_cases = (
    [ 't/data/openssl_x448_sk.der'          => undef,    'DER'           ],
    [ 't/data/openssl_x448_sk.pem'          => undef,    'PEM'           ],
    [ 't/data/openssl_x448_sk.pkcs8'        => undef,    'PKCS8'         ],
    [ 't/data/openssl_x448_sk_pbes1.pkcs8'  => 'secret', 'PKCS8 PBES1'   ],
    [ 't/data/openssl_x448_sk_pbes2.pkcs8'  => 'secret', 'PKCS8 PBES2'   ],
    [ 't/data/openssl_x448_sk_pw.pem'       => 'secret', 'encrypted PEM' ],
  );

  for my $case (@private_cases) {
    my ($file, $password, $label) = @$case;
    my $k = Crypt::PK::X448->new($file, $password);
    ok($k, "new $label");
    ok($k->is_private, "is_private $label");
    is(uc($k->key2hash->{priv}), $sk_hex, "key2hash->{priv} $label");
  }

  for my $file (qw(t/data/openssl_x448_pk.der t/data/openssl_x448_pk.pem)) {
    my $k = Crypt::PK::X448->new($file);
    ok($k, "new $file");
    ok(!$k->is_private, "!is_private $file");
    is(uc($k->key2hash->{pub}), $pk_hex, "key2hash->{pub} $file");
  }
}

{
  for my $file (qw(openssl_x448_pk.der openssl_x448_pk.pem)) {
    my $k = Crypt::PK::X448->new("t/data/$file");
    is($k->export_key_der('public'), read_rawfile("t/data/$file"), "export public $file") if $file =~ /\.der\z/;
    is($k->export_key_pem('public'), read_rawfile("t/data/$file"), "export public $file") if $file =~ /\.pem\z/;
  }

  for my $file (qw(openssl_x448_sk.der openssl_x448_sk.pem)) {
    my $k = Crypt::PK::X448->new("t/data/$file");
    is($k->export_key_der('private'), read_rawfile("t/data/$file"), "export private $file") if $file =~ /\.der\z/;
    is($k->export_key_pem('private'), read_rawfile("t/data/$file"), "export private $file") if $file =~ /\.pem\z/;
  }
}

{
  my $k = Crypt::PK::X448->new;
  $k->generate_key;
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private generated');
  is(length($k->export_key_raw('private')), 56, 'generated private raw length');
  is(length($k->export_key_raw('public')), 56, 'generated public raw length');
  ok($k->export_key_der('private'), 'export_key_der private');
  ok($k->export_key_der('public'), 'export_key_der public');
}

{
  my $sk1 = Crypt::PK::X448->new('t/data/openssl_x448_sk.der');
  my $pk1 = Crypt::PK::X448->new->import_key_raw($sk1->export_key_raw('public'), 'public');
  my $sk2 = Crypt::PK::X448->new->generate_key;
  my $pk2 = Crypt::PK::X448->new->import_key_raw($sk2->export_key_raw('public'), 'public');

  my $ss1 = $sk1->shared_secret($pk2);
  my $ss2 = $sk2->shared_secret($pk1);

  is(length($ss1), 56, 'shared_secret length');
  is(unpack('H*', $ss1), unpack('H*', $ss2), 'shared_secret symmetry');
}

### export_key_jwk_thumbprint (RFC 7638 over the RFC 8037 OKP members crv/kty/x)
{
  my $k = Crypt::PK::X448->new->generate_key;
  my $h = $k->export_key_jwk('public', 1);
  my $tp = $k->export_key_jwk_thumbprint;
  like($tp, qr/^[A-Za-z0-9_-]{43}$/, 'thumbprint is base64url SHA256');
  is($tp, Crypt::Digest::digest_data_b64u('SHA256',
       CryptX::_encode_json({crv=>$h->{crv}, kty=>$h->{kty}, x=>$h->{x}})),
     'thumbprint is over crv/kty/x in lexicographic order');
  is($tp, Crypt::PK::X448->new(\($k->export_key_jwk('public')))->export_key_jwk_thumbprint,
     'same thumbprint from a public-only key');
  isnt($tp, $k->export_key_jwk_thumbprint('SHA512'), 'hash argument is honoured');
  is($h->{crv}, 'X448', 'crv');
}

### password-protected PEM export is refused rather than writing an unreadable file
{
  my $gen = sub { Crypt::PK::X448->new->generate_key };
  my $k = $gen->();
  my $ref = $k->export_key_der('private');

  # unencrypted export is unaffected
  my $plain = $k->export_key_pem('private');
  like($plain, qr/^-----BEGIN PRIVATE KEY-----/, 'unencrypted PEM keeps the PRIVATE KEY label');
  unlike($plain, qr/Proc-Type|DEK-Info/, 'RFC 7468 permits no PEM headers');
  is(Crypt::PK::X448->new(\$plain)->export_key_der('private'), $ref, 'unencrypted PEM round-trips');
  ok($k->export_key_pem('public'), 'public PEM is unaffected');

  # a password croaks instead of producing something nothing can read
  eval { $k->export_key_pem('private', 'secret') };
  like($@, qr/password-protected PEM is not supported/, 'password croaks');
  eval { $k->export_key_pem('private', 'secret', 'AES-128-CBC') };
  like($@, qr/password-protected PEM is not supported/, 'password + cipher croaks');
  eval { $k->export_key_pem('private', '') };
  like($@, qr/password-protected PEM is not supported/, 'even an empty password croaks');

  # reading an externally produced ENCRYPTED PRIVATE KEY is a separate path and stays supported
  ok(Crypt::PK::X448->can('import_key'), 'import_key still available for reading encrypted keys');
}
