use strict;
use warnings;

use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
plan tests => 70;

use Crypt::PK::Ed448;
use Crypt::Misc qw(read_rawfile);

my $sk_hex = 'F82BD65291965DE46D87C7447863924E8EFB8DA36993618A784CD3B69A6D66E61CDC0A48A31E66BD8E81E4D77CEDC311AA0F72A322EF3E4FAD';
my $pk_hex = '1B0055AAD3B239A0FA1ED1EA8023151A5791D0BB556435299DA6CF1AAA272D858B0238822654BC15F64ADBAB97F1BB9EC848D72CD8AD856800';
my $sk_jwk = {
  kty => 'OKP',
  crv => 'Ed448',
  d   => '-CvWUpGWXeRth8dEeGOSTo77jaNpk2GKeEzTtpptZuYc3ApIox5mvY6B5Nd87cMRqg9yoyLvPk-t',
  x   => 'GwBVqtOyOaD6HtHqgCMVGleR0LtVZDUpnabPGqonLYWLAjiCJlS8FfZK26uX8bueyEjXLNithWgA',
};
my $pk_jwk = {
  kty => 'OKP',
  crv => 'Ed448',
  x   => 'GwBVqtOyOaD6HtHqgCMVGleR0LtVZDUpnabPGqonLYWLAjiCJlS8FfZK26uX8bueyEjXLNithWgA',
};

{
  my ($k, $k2);
  my $sk_data = pack('H*', $sk_hex);
  my $pk_data = pack('H*', $pk_hex);

  $k = Crypt::PK::Ed448->new->import_key_raw($sk_data, 'private');
  ok($k, 'new+import_key_raw raw-priv');
  ok($k->is_private, 'is_private raw-priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} raw-priv');
  is(uc($k->key2hash->{pub}),  $pk_hex, 'key2hash->{pub} raw-priv');
  is($k->export_key_raw('private'), $sk_data, 'export_key_raw private');

  $k2 = Crypt::PK::Ed448->new->import_key($k->key2hash);
  ok($k2->is_private, 'import_key hash private');
  is($k->export_key_der('private'), $k2->export_key_der('private'), 'private hash roundtrip');

  $k = Crypt::PK::Ed448->new->import_key_raw($pk_data, 'public');
  ok($k, 'new+import_key_raw raw-pub');
  ok(!$k->is_private, '!is_private raw-pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} raw-pub');
  is($k->export_key_raw('public'), $pk_data, 'export_key_raw public');

  $k2 = Crypt::PK::Ed448->new->import_key($k->key2hash);
  ok(!$k2->is_private, 'import_key hash public');
  is($k->export_key_der('public'), $k2->export_key_der('public'), 'public hash roundtrip');

  $k = Crypt::PK::Ed448->new($sk_jwk);
  ok($k, 'new JWKHASH/priv');
  ok($k->is_private, 'is_private JWKHASH/priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} JWKHASH/priv');
  is_deeply($k->export_key_jwk('private', 1), $sk_jwk, 'JWKHASH export private');

  $k = Crypt::PK::Ed448->new($pk_jwk);
  ok($k, 'new JWKHASH/pub');
  ok(!$k->is_private, '!is_private JWKHASH/pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} JWKHASH/pub');
  is_deeply($k->export_key_jwk('public', 1), $pk_jwk, 'JWKHASH export public');

  $k = Crypt::PK::Ed448->new('t/data/jwk_ed448-priv1.json');
  ok($k, 'new JWK/priv');
  ok($k->is_private, 'is_private JWK/priv');
  is(uc($k->key2hash->{priv}), $sk_hex, 'key2hash->{priv} JWK/priv');

  $k = Crypt::PK::Ed448->new('t/data/jwk_ed448-pub1.json');
  ok($k, 'new JWK/pub');
  ok(!$k->is_private, '!is_private JWK/pub');
  is(uc($k->key2hash->{pub}), $pk_hex, 'key2hash->{pub} JWK/pub');
}

{
  my @private_cases = (
    [ 't/data/openssl_ed448_sk.der'          => undef,    'DER'           ],
    [ 't/data/openssl_ed448_sk.pem'          => undef,    'PEM'           ],
    [ 't/data/openssl_ed448_sk.pkcs8'        => undef,    'PKCS8'         ],
    [ 't/data/openssl_ed448_sk_pbes1.pkcs8'  => 'secret', 'PKCS8 PBES1'   ],
    [ 't/data/openssl_ed448_sk_pbes2.pkcs8'  => 'secret', 'PKCS8 PBES2'   ],
    [ 't/data/openssl_ed448_sk_pw.pem'       => 'secret', 'encrypted PEM' ],
  );

  for my $case (@private_cases) {
    my ($file, $password, $label) = @$case;
    my $k = Crypt::PK::Ed448->new($file, $password);
    ok($k, "new $label");
    ok($k->is_private, "is_private $label");
    is(uc($k->key2hash->{priv}), $sk_hex, "key2hash->{priv} $label");
  }

  for my $file (qw(t/data/openssl_ed448_pk.der t/data/openssl_ed448_pk.pem t/data/openssl_ed448_x509.pem t/data/openssl_ed448_x509.der)) {
    my $k = Crypt::PK::Ed448->new($file);
    ok($k, "new $file");
    ok(!$k->is_private, "!is_private $file");
    is(uc($k->key2hash->{pub}), $pk_hex, "key2hash->{pub} $file");
  }
}

{
  for my $file (qw(openssl_ed448_pk.der openssl_ed448_pk.pem)) {
    my $k = Crypt::PK::Ed448->new("t/data/$file");
    is($k->export_key_der('public'), read_rawfile("t/data/$file"), "export public $file") if $file =~ /\.der\z/;
    is($k->export_key_pem('public'), read_rawfile("t/data/$file"), "export public $file") if $file =~ /\.pem\z/;
  }

  for my $file (qw(openssl_ed448_sk.der openssl_ed448_sk.pem)) {
    my $k = Crypt::PK::Ed448->new("t/data/$file");
    is($k->export_key_der('private'), read_rawfile("t/data/$file"), "export private $file") if $file =~ /\.der\z/;
    is($k->export_key_pem('private'), read_rawfile("t/data/$file"), "export private $file") if $file =~ /\.pem\z/;
  }
}

{
  my $k = Crypt::PK::Ed448->new;
  $k->generate_key;
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private generated');
  is(length($k->export_key_raw('private')), 57, 'generated private raw length');
  is(length($k->export_key_raw('public')), 57, 'generated public raw length');
  ok($k->export_key_der('private'), 'export_key_der private');
  ok($k->export_key_der('public'), 'export_key_der public');
}

{
  my $sk = Crypt::PK::Ed448->new('t/data/openssl_ed448_sk.der');
  my $pk = Crypt::PK::Ed448->new('t/data/openssl_ed448_pk.der');

  my $sig = $sk->sign_message('message');
  is(length($sig), 114, 'sign_message length');
  ok($pk->verify_message($sig, 'message'), 'verify_message');
  ok(!$pk->verify_message($sig, 'message!'), 'verify_message rejects tampered message');
}
