use strict;
use warnings;
use Test::More tests => 9;

use Crypt::PK::ECC;

sub rejects_invalid_public {
  my ($priv, $pub_pem, $tcid, $want_hex) = @_;
  my $name = 'ecdh_secp256r1_pem_test.json tcId=' . $tcid
           . ' rejects invalid explicit-parameter public key';

  if (!$priv) {
    fail($name);
    diag('shared private key import failed earlier');
    return;
  }

  my $accepted = 0;
  my $shared;
  my $pub = eval { Crypt::PK::ECC->new(\$pub_pem) };
  if ($pub) {
    my $ok = eval {
      $shared = $priv->shared_secret($pub);
      1;
    };
    $accepted = 1 if $ok && defined $shared;
  }

  my $pass = ok(!$accepted, $name);
  if (!$pass) {
    diag('got shared secret: ' . (defined $shared ? unpack('H*', $shared) : '(undef)'));
    diag('wycheproof documented shared: ' . $want_hex) if defined $want_hex;
  }
}

{
  my $priv = Crypt::PK::ECC->new;
  my $pub  = Crypt::PK::ECC->new;
  my $sk   = pack("H*", '809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff');
  my $pk   = pack("H*", '04dbfa466f12013255f9d57a6496c158ee7dd202a1ce4a5a53005b3564d509a0bbf2578007e857bdd082751ef2f3b4b9c38a0b87bab413d55ccb26a574f2b4be9d');

  ok($priv->import_key_raw($sk, 'secp256r1'),
     'ecdh_secp256r1_ecpoint_test.json tcId=202 imports raw private key');
  ok($pub->import_key_raw($pk, 'secp256r1'),
     'ecdh_secp256r1_ecpoint_test.json tcId=202 imports raw public key');
  is(unpack("H*", $priv->shared_secret($pub)),
     'e2d57eeec983756c9124f885a4d118ed5b8de7d2895fd91264cf291496949a12',
     'ecdh_secp256r1_ecpoint_test.json tcId=202 exact shared secret');
}

{
  my $priv_pem = <<'EOF';
-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBPNBTRWJtJ9xctQ5y7
545bU1Dchd6kDNLWJ0dAxuAjnA==
-----END PRIVATE KEY-----
EOF

  my $pub_352_pem = <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAA
AAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/////
//////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR
8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84z
V2sxXs7LtkBoN79R9QIh/wAAAAD/////AAAAAAAAAABDGQVSWOhhewxGNT0DnNqv
AgEBA0IABBUQJkwYnD1SP/mRar1wae+mlo2Nx922RX14abU+pgzc+vt+1HhtoV0p
7lklb1Nto1daSIjBuwqVslb0p+n9dko=
-----END PUBLIC KEY-----
EOF

  my $pub_359_pem = <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBMDCB6QYHKoZIzj0CATCB3QIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAA
AAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD/////
//////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR
8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84z
V2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR
A0IABBUQJkwYnD1SP/mRar1wae+mlo2Nx922RX14abU+pgzc+vt+1HhtoV0p7lkl
b1Nto1daSIjBuwqVslb0p+n9dko=
-----END PUBLIC KEY-----
EOF

  my $pub_363_pem = <<'EOF';
-----BEGIN PUBLIC KEY-----
MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/QkQWaaJNjX5AOlE
nWP1crKuvEz/e05eM/GyAOi7wUUwRAQgAvbvpVl2ycsG/xa7YpwKjU1RQ7QAhLGh
zA5N/xdEPrcEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEAAAA
AAAAAAAAAAZZf6lLH9kAAAAAAAAAAAAAAAAAAAIbjH3Xf5qVYnki7O7+pz8Cjx7J
W6m4+pWjrSS9+f/0FAIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVR
AgEBA0IABAAAAAAAAAAAAAAGWX+pSx/ZAAAAAAAAAAAAAAAAAAACG4x913+alWJ5
Iuzu/qc/Ao8eyVupuPqVo60kvfn/9BQ=
-----END PUBLIC KEY-----
EOF

  my $priv = eval { Crypt::PK::ECC->new(\$priv_pem) };
  ok($priv && $priv->is_private,
     'ecdh_secp256r1_pem_test.json imports shared PKCS#8 private key');

  rejects_invalid_public($priv, $pub_352_pem, 352,
                         'd003f5cc83852584061f7a8a28bcb5671ecbda096e16e7accfa8f8d311a3db7a');
  rejects_invalid_public($priv, $pub_359_pem, 359,
                         'd003f5cc83852584061f7a8a28bcb5671ecbda096e16e7accfa8f8d311a3db7a');
  rejects_invalid_public($priv, $pub_363_pem, 363,
                         'cea0fbd8f20abc8cf8127c132e29756d25ff1530a88bf5c9e22dc1c137c36be9');
}

{
  my $priv = Crypt::PK::ECC->new;
  my $sk   = pack("H*", '55a6601d488398ee537d8e745a461cfb8e60eeb7cb09088698faa6e9');
  my $der  = pack("H*", '3052301406072a8648ce3d020106092b2403030208010106033a00040ad954137b533120d3344cc8b9913491791ebf145bab44f200a507d3027e41442fabed87e7a30783fd1618790511098b0d004c60b5086b1a');

  ok($priv->import_key_raw($sk, 'brainpoolP224r1'),
     'ecdh_brainpoolP224r1_test.json tcId=517 imports raw brainpoolP224r1 private key');

  my $accepted = 0;
  my $shared;
  my $pub = eval { Crypt::PK::ECC->new(\$der) };
  if ($pub) {
    my $ok = eval {
      $shared = $priv->shared_secret($pub);
      1;
    };
    $accepted = 1 if $ok && defined $shared;
  }

  ok(!$accepted,
     'ecdh_brainpoolP224r1_test.json tcId=517 rejects wrong-curve SPKI public key')
    or do {
      diag('got shared secret: ' . (defined $shared ? unpack('H*', $shared) : '(undef)'));
      diag('wycheproof documented shared: 38eced2a737e8101dc3bbaa23c7942d68d4afa597064dbc1607be2a9');
    };
}
