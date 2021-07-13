use strict;
use warnings;
use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
plan tests => 97;

use Crypt::PK::RSA;
use Crypt::PK::ECC;

my $rsa = Crypt::PK::RSA->new;
my $ec  = Crypt::PK::ECC->new;
ok($rsa, "RSA new");
ok($ec,  "ECC new");

### RSA

# test whether exported JWK JSON is canonical
$rsa->import_key("t/data/jwk_rsa-priv.json");
is($rsa->export_key_jwk('public'), '{"e":"AQAB","kty":"RSA","n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"}');
is($rsa->export_key_jwk('private'),'{"d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ","dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c","dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots","e":"AQAB","kty":"RSA","n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q","p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws","q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s","qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"}');

for my $f (qw/jwk_rsa-priv.json jwk_rsa-priv1.json jwk_rsa-pub1.json /) {
  $rsa->import_key("t/data/$f");
  my $kh = $rsa->key2hash;
  ok($kh->{N}, "RSA N test $f");
  ok($kh->{e}, "RSA e test $f");
}

my $RSA1 = {
  d => "5F8713B5E258FE09F81583EC5C1F2B7578B1E6FC2C83514B37913711A1BA449A151FE1CB2CA0FD33B771E68A3B1944649DC867AD1C1E5240BB853E5F24B33459B14028D2D6636BEFEC1E8DA974B352FC53D3F6127EA8A3C29DD14F3941682C56A78768164E4DDA8F06CBF9C734AAE8003224278EA9454A21B17CB06D178075868CC05B3DB6FF1DFDC3D56378B4EDADEDF0C37A4CDC26D1D49AC26F6FE3B5220A5DD29396621BBC688CF2EEE2C6E0D54DA3C782014CD0739DB252CC51CAEBA8D3F1B824BAAB24D068EC903264D7D678AB08F06EC9E7E23D960628B744BF94B3694656463C7E417399ED73D076C891FCF463A9AA9CE62DA9CD17E237DC2A8002F1",
  dP => "1B8B0F5E473A61AF72F28256F7F20B8F8C6EA69BB49738BF1FB553912F318F949D5F7728134A22998C31222D9E99302E7B450E6B97698051B2049E1CF2D436545E34D9746E80A0D33FC6A4621168E6D000EFB41EFCD9ADB9865CDC2DE6DC8DB81B61AF479B120F153200DDB3ABC2DF9FD1149ACEAB63739BF187A22A44E2063D",
  dQ => "1B8B0F5E473A61AF72F28256F7F20B8F8C6EA69BB49738BF1FB553912F318F949D5F7728134A22998C31222D9E99302E7B450E6B97698051B2049E1CF2D436545E34D9746E80A0D33FC6A4621168E6D000EFB41EFCD9ADB9865CDC2DE6DC8DB81B61AF479B120F153200DDB3ABC2DF9FD1149ACEAB63739BF187A22A44E2063D",
  e => "010001",
  N => "D2FC7B6A0A1E6C67104AEB8F88B257669B4DF679DDAD099B5C4A6CD9A88015B5A133BF0B856C7871B6DF000B554FCEB3C2ED512BB68F145C6E8434752FAB52A1CFC124408F79B58A4578C16428855789F7A249E384CB2D9FAE2D67FD96FB926C198E077399FDC815C0AF097DDE5AADEFF44DE70E827F4878432439BFEEB96068D0474FC50D6D90BF3A98DFAF1040C89C02D692AB3B3C2896609D86FD73B774CE0740647CEEEAA310BD12F985A8EB9F59FDD426CEA5B2120F4F2A34BCAB764B7E6C54D6840238BCC40587A59E66ED1F33894577635C470AF75CF92C20D1DA43E1BFC419E222A6F0D0BB358C5E38F9CB050AEAFE904814F1AC1AA49CCA9EA0CA83",
  p => "F378BEEC8BCC197A0C5C2B24BFBDD32ABF3ADFB1623BB676EF3BFCA23EA96D6510C8B3D0050C6D3D59F00F6D11FBAD1E4C3983DAE8E732DE4FA2A32B9BC45F98D855583B638CC9823233A949789C1478FB5CEB95218432A955A558487A74DDFA19565893DDCDF0173DBD8E35C72F01F51CF3386550CD7BCD12F9FB3B49D56DFB",
  q => "DDD7CE47D72E62AFB44BE9A414BCE022D80C11F173076AB78567A132E1B4A02BAA9DBDEFA1B2F2BA6AA355940ED5D22B7708139C276963305C39F5B9AF7EF40055E38967EDFCD1848A8BE89E2CE12A9A3D5554BBF13CC583190876B79C45ECEC67ED6461DFECD6A0DBC6D9031207C0213006F4B527003BA7E2F21C6FAC9E9719",
  qP => "1B233FA7A26B5F24A2CF5B6816029B595F89748DE3438CA9BBDADB316C77AD02417E6B7416863381421911514470EAB07A644DF35CE80C069AF819342963460E3247643743985856DC037B948FA9BB193F987646275D6BC7247C3B9E572D27B748F9917CAC1923AC94DB8671BD0285608B5D95D50A1B33BA21AEB34CA8405515",
  size => 256,
  type => 1,
};

my $RSA1_jwk_thumbprint_sha256 = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

my $RSA2 = {
  d => "",
  dP => "",
  dQ => "",
  e => "010001",
  N => "D2FC7B6A0A1E6C67104AEB8F88B257669B4DF679DDAD099B5C4A6CD9A88015B5A133BF0B856C7871B6DF000B554FCEB3C2ED512BB68F145C6E8434752FAB52A1CFC124408F79B58A4578C16428855789F7A249E384CB2D9FAE2D67FD96FB926C198E077399FDC815C0AF097DDE5AADEFF44DE70E827F4878432439BFEEB96068D0474FC50D6D90BF3A98DFAF1040C89C02D692AB3B3C2896609D86FD73B774CE0740647CEEEAA310BD12F985A8EB9F59FDD426CEA5B2120F4F2A34BCAB764B7E6C54D6840238BCC40587A59E66ED1F33894577635C470AF75CF92C20D1DA43E1BFC419E222A6F0D0BB358C5E38F9CB050AEAFE904814F1AC1AA49CCA9EA0CA83",
  p => "",
  q => "",
  qP => "",
  size => 256,
  type => 0,
};

{
  $rsa->import_key($RSA1);
  my $kh = $rsa->key2hash;
  is($kh->{N},  $RSA1->{N},  "RSA N test HASH1");
  is($kh->{e},  $RSA1->{e},  "RSA e test HASH1");
  is($kh->{p},  $RSA1->{p},  "RSA private p test HASH1");
  is($kh->{q},  $RSA1->{q},  "RSA private q test HASH1");
  is($kh->{d},  $RSA1->{d},  "RSA private d test HASH1");
  is($kh->{dP}, $RSA1->{dP}, "RSA private dP test HASH1");
  is($kh->{dQ}, $RSA1->{dQ}, "RSA private dQ test HASH1");
  is($kh->{qP}, $RSA1->{qP}, "RSA private qP test HASH1");
  ok($rsa->is_private, "RSA private test HASH1");
  my $jwk = $rsa->export_key_jwk('private');
  my $jwkp = $rsa->export_key_jwk('public');
  my $jwkh = $rsa->export_key_jwk('private', 1);
  my $jwkhp = $rsa->export_key_jwk('public', 1);
  is($jwkh->{kty}, "RSA",  "RSA kty test export_key_jwk as hash");
  is($jwkhp->{kty}, "RSA", "RSA(pub) kty test export_key_jwk as hash");
  ok(exists $jwkhp->{n},  "RSA(pub) n test export_key_jwk as hash");
  ok(exists $jwkhp->{e},  "RSA(pub) e test export_key_jwk as hash");
  ok(!exists $jwkhp->{p}, "RSA(pub) p test export_key_jwk as hash");
  ok(exists $jwkh->{n}, "RSA n test export_key_jwk as hash");
  ok(exists $jwkh->{e}, "RSA e test export_key_jwk as hash");
  ok(exists $jwkh->{p}, "RSA p test export_key_jwk as hash");
  my $jwk_tp = $rsa->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $RSA1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
  ### jwk re-import private key
  $rsa->import_key(\$jwk);
  $kh = $rsa->key2hash;
  ok($rsa->is_private, "RSA private test JWK1");
  is($kh->{N},  $RSA1->{N},  "RSA N test JWK1");
  is($kh->{e},  $RSA1->{e},  "RSA e test JWK1");
  is($kh->{p},  $RSA1->{p},  "RSA private p test JWK1");
  is($kh->{q},  $RSA1->{q},  "RSA private q test JWK1");
  is($kh->{d},  $RSA1->{d},  "RSA private d test JWK1");
  is($kh->{dP}, $RSA1->{dP}, "RSA private dP test JWK1");
  is($kh->{dQ}, $RSA1->{dQ}, "RSA private dQ test JWK1");
  is($kh->{qP}, $RSA1->{qP}, "RSA private qP test JWK1");
  $jwk_tp = $rsa->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $RSA1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
  ### jwk re-import public key
  $rsa->import_key(\$jwkp);
  $kh = $rsa->key2hash;
  ok(!$rsa->is_private, "RSA !private test JWK2");
  is($kh->{N},  $RSA1->{N}, "RSA N test JWK2");
  is($kh->{e},  $RSA1->{e}, "RSA e test JWK2");
  is($kh->{p},  "", "RSA private p test JWK2");
  is($kh->{q},  "", "RSA private q test JWK2");
  is($kh->{d},  "", "RSA private d test JWK2");
  is($kh->{dP}, "", "RSA private dP test JWK2");
  is($kh->{dQ}, "", "RSA private dQ test JWK2");
  is($kh->{qP}, "", "RSA private qP test JWK2");
  $jwk_tp = $rsa->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $RSA1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
}

{
  $rsa->import_key($RSA2);
  my $kh = $rsa->key2hash;
  is($kh->{N},  $RSA1->{N}, "RSA N test HASH2");
  is($kh->{e},  $RSA1->{e}, "RSA e test HASH2");
  is($kh->{p},  "", "RSA private p test HASH2");
  is($kh->{q},  "", "RSA private q test HASH2");
  is($kh->{d},  "", "RSA private d test HASH2");
  is($kh->{dP}, "", "RSA private dP test HASH2");
  is($kh->{dQ}, "", "RSA private dQ test HASH2");
  is($kh->{qP}, "", "RSA private qP test HASH2");
  ok(!$rsa->is_private, "RSA private test HASH2");
}

### ECC

# test whether exported JWK JSON is canonical
$ec->import_key("t/data/jwk_ec-priv1.json");
is($ec->export_key_jwk('public'), '{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}');
is($ec->export_key_jwk('private'),'{"crv":"P-256","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}');

for my $f (qw/jwk_ec-priv1.json jwk_ec-pub.json jwk_ec-pub1.json/) {
  $ec->import_key("t/data/$f");
  my $kh = $ec->key2hash;
  ok($kh->{pub_x}, "EC x test $f");
  ok($kh->{pub_y}, "EC y test $f");
}

my $EC1 = {
  curve_A        => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
  curve_B        => "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
  curve_bits     => 256,
  curve_bytes    => 32,
  curve_cofactor => 1,
  curve_Gx       => "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
  curve_Gy       => "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
  curve_oid      => "1.2.840.10045.3.1.7",
  curve_order    => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
  curve_prime    => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
  k              => "F3BD0C07A81FB932781ED52752F60CC89A6BE5E51934FE01938DDB55D8F77801",
  pub_x          => "30A0424CD21C2944838A2D75C92B37E76EA20D9F00893A3B4EEE8A3C0AAFEC3E",
  pub_y          => "E04B65E92456D9888B52B379BDFBD51EE869EF1F0FC65B6659695B6CCE081723",
  size           => 32,
  type           => 1,
};

my $ec1_jwk_thumbprint_sha256 = 'cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s';

my $EC2 = {
  curve_A        => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
  curve_B        => "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
  curve_bits     => 256,
  curve_bytes    => 32,
  curve_cofactor => 1,
  curve_Gx       => "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
  curve_Gy       => "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
  curve_oid      => "1.2.840.10045.3.1.7",
  curve_order    => "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
  curve_prime    => "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
  k              => "",
  pub_x          => "30A0424CD21C2944838A2D75C92B37E76EA20D9F00893A3B4EEE8A3C0AAFEC3E",
  pub_y          => "E04B65E92456D9888B52B379BDFBD51EE869EF1F0FC65B6659695B6CCE081723",
  size           => 32,
  type           => 0,
};

{
  $ec->import_key($EC1);
  my $kh = $ec->key2hash;
  is($kh->{pub_x}, $EC1->{pub_x}, "EC x test HASH1");
  is($kh->{pub_y}, $EC1->{pub_y}, "EC y test HASH1");
  is($kh->{k},     $EC1->{k},     "EC k test HASH1");
  is($kh->{curve_oid}, "1.2.840.10045.3.1.7", "EC curve test HASH1");
  ok($ec->is_private, "EC private test HASH1");
  my $jwk = $ec->export_key_jwk('private');
  my $jwkp = $ec->export_key_jwk('public');
  my $jwkh = $ec->export_key_jwk('private', 1);
  my $jwkhp = $ec->export_key_jwk('public', 1);
  is($jwkh->{kty}, "EC",  "ECC kty test export_key_jwk as hash");
  is($jwkhp->{kty}, "EC", "ECC(pub) kty test export_key_jwk as hash");
  ok(exists $jwkhp->{x},  "ECC(pub) x test export_key_jwk as hash");
  ok(exists $jwkhp->{y},  "ECC(pub) y test export_key_jwk as hash");
  ok(!exists $jwkhp->{d}, "ECC(pub) d test export_key_jwk as hash");
  ok(exists $jwkh->{x}, "ECC x test export_key_jwk as hash");
  ok(exists $jwkh->{y}, "ECC y test export_key_jwk as hash");
  ok(exists $jwkh->{d}, "ECC d test export_key_jwk as hash");
  my $jwk_tp = $ec->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $ec1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
  ### jwk re-import private key
  $ec->import_key(\$jwk);
  $kh = $ec->key2hash;
  is($kh->{pub_x}, $EC1->{pub_x}, "EC x test JWK1");
  is($kh->{pub_y}, $EC1->{pub_y}, "EC y test JWK1");
  is($kh->{k},     $EC1->{k},     "EC k test JWK1");
  is($kh->{curve_oid}, "1.2.840.10045.3.1.7", "EC curve test JWK1");
  ok($ec->is_private, "EC private test JWK1");
  $jwk_tp = $ec->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $ec1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
  ### jwk re-import public key
  $ec->import_key(\$jwkp);
  $kh = $ec->key2hash;
  is($kh->{pub_x}, $EC1->{pub_x}, "EC x test JWK2");
  is($kh->{pub_y}, $EC1->{pub_y}, "EC y test JWK2");
  is($kh->{k}, "", "EC k test JWK2");
  is($kh->{curve_oid}, "1.2.840.10045.3.1.7", "EC curve test JWK2");
  ok(!$ec->is_private, "EC !private test JWK2");
  $jwk_tp = $ec->export_key_jwk_thumbprint('SHA256');
  is($jwk_tp, $ec1_jwk_thumbprint_sha256, 'export_key_jwk_thumbprint(SHA256)');
}

{
  $ec->import_key($EC2);
  my $kh = $ec->key2hash;
  is($kh->{pub_x}, $EC1->{pub_x}, "EC x test HASH2");
  is($kh->{pub_y}, $EC1->{pub_y}, "EC y test HASH2");
  is($kh->{k}, "", "EC k test HASH2");
  is($kh->{curve_oid}, "1.2.840.10045.3.1.7", "EC curve test HASH2");
  ok(!$ec->is_private, "EC private test HASH2");
}

{
    my $jwk = {
        e => 'AQAB',
        kty => 'RSA',
        n => 'ln_cp6g_c65R6uYmwFx6AF1PyyZF7N1EaLhvUjDStK6Scmp_XCD-ynz5Q1iS0Q2t8gnh_s5dQtThiuvOGxCK1j69TA6Jpo0uUBL-gzf3J25PhqdNmTbGGRNkD0aT8qfeY9_bXTA1vmawh-46A6xrVFiT62NK7IdsyQNzrtR9QwzcSR79m9UqTVe5MdDB9tZZIotmqWQlZ5MVb26PPmgkuh6AthS-an2KeDdYRwAyQtfR1B6f-swzIPwq-AUy1pfmGVe-d6K5dCOU9RUMPPRiQ7atmodAxfcWywmnrCtSCfPk0fkTLN4RsuCWV85NXcGnpr41m4uacALT0Xs0IqBKbw',
    };
    my $before_json = {%$jwk};

    Crypt::PK::RSA->new($jwk);

    is_deeply(
        $jwk,
        $before_json,
        'new($jwk) doesn’t change $jwk',
    );
}
