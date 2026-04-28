use strict;
use warnings;

use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
plan tests => 82;

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

# Ed448ctx test vectors from RFC 8032 Section 7.4
{
  my $sk = Crypt::PK::Ed448->new->import_key_raw(
    pack("H*", "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
              . "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"),
    'private'
  );
  my $pk = Crypt::PK::Ed448->new->import_key_raw(
    pack("H*", "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
              . "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"),
    'public'
  );

  # ctx test 1: message=0x03, context="foo"
  {
    my $msg = pack("H*", "03");
    my $ctx = "foo";
    my $expected_sig = "d4f8f6131770dd46f40867d6fd5d5055"
                     . "de43541f8c5e35abbcd001b32a89f7d2"
                     . "151f7647f11d8ca2ae279fb842d60721"
                     . "7fce6e042f6815ea000c85741de5c8da"
                     . "1144a6a1aba7f96de42505d7a7298524"
                     . "fda538fccbbb754f578c1cad10d54d0d"
                     . "5428407e85dcbc98a49155c13764e66c"
                     . "3c00";
    my $sig = $sk->sign_message_ctx($msg, $ctx);
    is(unpack("H*", $sig), $expected_sig, 'ed448ctx sign test 1');
    ok($pk->verify_message_ctx($sig, $msg, $ctx), 'ed448ctx verify test 1');
    ok(!$pk->verify_message_ctx($sig, $msg, "bar"), 'ed448ctx verify rejects wrong context');
  }
}

# Ed448ph test vector from RFC 8032 Section 7.4
{
  my $sk = Crypt::PK::Ed448->new->import_key_raw(
    pack("H*", "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
              . "ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49"),
    'private'
  );
  my $pk = Crypt::PK::Ed448->new->import_key_raw(
    pack("H*", "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743"
              . "c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880"),
    'public'
  );

  # ph test: message="abc", no context
  {
    my $msg = pack("H*", "616263"); # "abc"
    my $expected_sig = "822f6901f7480f3d5f562c592994d969"
                     . "3602875614483256505600bbc281ae38"
                     . "1f54d6bce2ea911574932f52a4e6cadd"
                     . "78769375ec3ffd1b801a0d9b3f4030cd"
                     . "433964b6457ea39476511214f97469b5"
                     . "7dd32dbc560a9a94d00bff07620464a3"
                     . "ad203df7dc7ce360c3cd3696d9d9fab9"
                     . "0f00";
    my $sig = $sk->sign_message_ph($msg);
    is(unpack("H*", $sig), $expected_sig, 'ed448ph sign (no context)');
    ok($pk->verify_message_ph($sig, $msg), 'ed448ph verify (no context)');
    ok(!$pk->verify_message_ph($sig, "wrong"), 'ed448ph verify rejects wrong message');
  }
}

# Ed448ctx/ph roundtrip with generated key
{
  my $sk = Crypt::PK::Ed448->new->generate_key;
  my $pk = Crypt::PK::Ed448->new->import_key_raw($sk->export_key_raw('public'), 'public');

  # ctx roundtrip
  my $sig_ctx = $sk->sign_message_ctx("hello", "mycontext");
  ok($pk->verify_message_ctx($sig_ctx, "hello", "mycontext"), 'ed448ctx roundtrip');
  ok(!$pk->verify_message_ctx($sig_ctx, "hello", "other"), 'ed448ctx roundtrip wrong ctx');

  # ph roundtrip without context
  my $sig_ph = $sk->sign_message_ph("hello");
  ok($pk->verify_message_ph($sig_ph, "hello"), 'ed448ph roundtrip no ctx');

  # ph roundtrip with context
  my $sig_ph_ctx = $sk->sign_message_ph("hello", "myctx");
  ok($pk->verify_message_ph($sig_ph_ctx, "hello", "myctx"), 'ed448ph roundtrip with ctx');
  ok(!$pk->verify_message_ph($sig_ph_ctx, "hello"), 'ed448ph roundtrip ctx mismatch');

  # Ed448 with empty context = plain Ed448, so cross-scheme check is different than Ed25519
  # ph signature should not verify as plain
  my $sig_ph2 = $sk->sign_message_ph("hello");
  ok(!$pk->verify_message($sig_ph2, "hello"), 'ph sig not valid as plain');
}
