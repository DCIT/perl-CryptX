use strict;
use warnings;
use Test::More tests => 62;

use Crypt::PK::DSA qw(dsa_encrypt dsa_decrypt dsa_sign_message dsa_verify_message dsa_sign_hash dsa_verify_hash);
use Crypt::Misc 'decode_b64';

{
  my $k;

  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.der');
  ok($k, 'load cryptx_priv_dsa1.der');
  ok($k->is_private, 'is_private cryptx_priv_dsa1.der');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{x}), '6C801901AC74E2DC714D75A9F6969483CF0239D142AB7E3F329ED8D49E07', 'key2hash');

  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa2.der');
  ok($k, 'load cryptx_priv_dsa2.der');
  ok($k->is_private, 'is_private cryptx_priv_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa1.der');
  ok($k, 'load cryptx_pub_dsa1.der');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa1.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa2.der');
  ok($k, 'load cryptx_pub_dsa2.der');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa1.der');
  ok($k, 'load openssl_dsa1.der');
  ok($k->is_private, 'is_private openssl_dsa1.der');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa2.der');
  ok($k, 'load openssl_dsa2.der');
  ok($k->is_private, 'is_private openssl_dsa2.der');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.pem');
  ok($k, 'load cryptx_priv_dsa1.pem');
  ok($k->is_private, 'is_private cryptx_priv_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa2.pem');
  ok($k, 'load cryptx_priv_dsa2.pem');
  ok($k->is_private, 'is_private cryptx_priv_dsa2.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa1.pem');
  ok($k, 'load cryptx_pub_dsa1.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa2.pem');
  ok($k, 'load cryptx_pub_dsa2.pem');
  ok(!$k->is_private, 'is_private cryptx_pub_dsa2.pem');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa1.pem');
  ok($k, 'load openssl_dsa1.pem');
  ok($k->is_private, 'is_private openssl_dsa1.pem');
  
  $k = Crypt::PK::DSA->new('t/data/openssl_dsa2.pem');
  ok($k, 'load openssl_dsa2.pem');
  ok($k->is_private, 'is_private openssl_dsa2.pem');
}

{
  my $pr1 = Crypt::PK::DSA->new;
  $pr1->import_key('t/data/cryptx_priv_dsa1.der');
  my $pu1 = Crypt::PK::DSA->new;
  $pu1->import_key('t/data/cryptx_pub_dsa1.der');
 
  my $ct = $pu1->encrypt("secret message");
  my $pt = $pr1->decrypt($ct);
  ok(length $ct > 200, 'encrypt ' . length($ct));
  is($pt, "secret message", 'decrypt');
  #XXX-FIXME somwhere here a crash happens on solaris - http://ppm4.activestate.com/sun4-solaris/5.14/1400/M/MI/MIK/CryptX-0.017.d/log-20130924T103600.txt
  my $sig = $pr1->sign_message("message");
  ok(length $sig > 60, 'sign_message ' . length($sig));
  ok($pu1->verify_message($sig, "message"), 'verify_message');

  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = $pr1->sign_hash($hash, 'SHA1');
  ok(length $sig > 60, 'sign_hash ' . length($sig));
  ok($pu1->verify_hash($sig, $hash, 'SHA1'), 'verify_hash'); 
 
  my $pr2 = Crypt::PK::DSA->new;
  $pr2->import_key('t/data/cryptx_priv_dsa2.der');
  my $pu2 = Crypt::PK::DSA->new;
  $pu2->import_key('t/data/cryptx_pub_dsa2.der');
 
  #my $ss1 = $pr1->shared_secret($pu2);
  #my $ss2 = $pr2->shared_secret($pu1);
  #is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::DSA->new;
  $k->generate_key(\<<"MARKER");
-----BEGIN DSA PARAMETERS-----
MIICLAKCAQEA3dZSaDnP5LgH44CDYc2wfGLtq4rbBgtOVvLkvh4j29CTiOUDRC1H
ivkTdtGrI3DdrAFeKieFYDJ1RJFbru+8/RYE7YfaR5Y3OUI4Vdf26guMViLLVjSL
W43Td50ZZziLmmYzn3cliokShe9f5/mtuLJ0uJRq7QxgHj7bgmvJvORvi4QXSCOn
nmCOgEfhoU1Vj/PePjtjeZWbLyGFXHC7vpvqePrsFtbUlBzIr2mr7JuHB3rAl7A4
1VL6lexqONRa4rQuVxiX0vp3iit9Cx02EwrZODdlifssd9Kceu2UsvifjmCBPyv8
6nmmEOtxh/xduuOBtVWXeZHSwIDUQvSJFwIhAK/ZDSl9iNuZ/TRwqQ3JRU3MjXCU
/US6/LU1qqjQATk7AoIBACoqauphNZmUZYOilArBfYCMtUwS0FNG6wfUMWDMd46z
/hv7equa9b75sT1uHyiUVuPD2hRhR3xNYkKSX9Kx8NGKj/bGDyaEW+Ud852N6BTo
9vzZ4GjKVBGe44Wa8eynVgVE5/r0z6OfHkV7uOxlGEdYgIooUbIsY7w0DmaR2FVZ
AMjGMg+L6CpulfvdETYi9LQafY4jRkgGWTc9h/2RYGhQUti1PheY1AlDYpubO8am
ZBG6vMBaANLx6Pv+lle4ltVvDVhwTK5APyfN1vVdEvVmU1/6zHZEnuiDAT8XI1rH
S1+SGX11RIn6uPVL1c0RjgW8/JZ6EeM8NvLdBiYYBuI=
-----END DSA PARAMETERS-----
MARKER
  ok($k, 'generate_key PEM');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $k = Crypt::PK::DSA->new;
  $k->generate_key(\decode_b64(<<"MARKER"));
MIICLAKCAQEA3dZSaDnP5LgH44CDYc2wfGLtq4rbBgtOVvLkvh4j29CTiOUDRC1H
ivkTdtGrI3DdrAFeKieFYDJ1RJFbru+8/RYE7YfaR5Y3OUI4Vdf26guMViLLVjSL
W43Td50ZZziLmmYzn3cliokShe9f5/mtuLJ0uJRq7QxgHj7bgmvJvORvi4QXSCOn
nmCOgEfhoU1Vj/PePjtjeZWbLyGFXHC7vpvqePrsFtbUlBzIr2mr7JuHB3rAl7A4
1VL6lexqONRa4rQuVxiX0vp3iit9Cx02EwrZODdlifssd9Kceu2UsvifjmCBPyv8
6nmmEOtxh/xduuOBtVWXeZHSwIDUQvSJFwIhAK/ZDSl9iNuZ/TRwqQ3JRU3MjXCU
/US6/LU1qqjQATk7AoIBACoqauphNZmUZYOilArBfYCMtUwS0FNG6wfUMWDMd46z
/hv7equa9b75sT1uHyiUVuPD2hRhR3xNYkKSX9Kx8NGKj/bGDyaEW+Ud852N6BTo
9vzZ4GjKVBGe44Wa8eynVgVE5/r0z6OfHkV7uOxlGEdYgIooUbIsY7w0DmaR2FVZ
AMjGMg+L6CpulfvdETYi9LQafY4jRkgGWTc9h/2RYGhQUti1PheY1AlDYpubO8am
ZBG6vMBaANLx6Pv+lle4ltVvDVhwTK5APyfN1vVdEvVmU1/6zHZEnuiDAT8XI1rH
S1+SGX11RIn6uPVL1c0RjgW8/JZ6EeM8NvLdBiYYBuI=
MARKER
  ok($k, 'generate_key DER');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $k = Crypt::PK::DSA->new;
  $k->generate_key({
        p => "0xA717676E57280B32123B22E3F5BABC9460FEEBD53CE9ECBA2060AAD0A7128A2EA25D049D0784B08E7B3C63A53F2764".
                "2EA5B62B44F80BDF74828F9227FACDEAC50D8698AE12722F58F52087564466FA92A38ED6158B5437A4382D7E460D".
                "41F3FA9B7BD0808E2DDD93529F6CAD397B9287313CFE2A0F913079E86EA0FE55D2620750A57419158EDAC4BB7C97".
                "2B7C20756C503FBBBC84EE39D0C72298CA3F9B28CD14C640D459F160ADD615F4A24300F5832DE2A874776B94D158".
                "F77BBD13D417F5A56BE043CD358D9B983B003DF4AE20EB43A358F391CBD75668AAE9A7633815FEE4DBFF0303D097".
                "AA2BBA9BD7ADD5B75B40ED3F756516AAB46B66872187544B8D",
        q => "0x81EA35142EDAC0B7A9CCBB4A0D29D16803792A1FC4FD4310682CD6C0FEFD3DC7",
        g => "0x62160328C0B7F11AD92684E27A28BF5F79D936F968C6301E339D2F18FF86106736030F4287E588AD7A79F37E7340D1
                E3CA1D89D320F2C2BA5FDC263990456C77FBE683D620A0BB0D49DB793E48C68710750163EF822129D32CC9254218DD
                74F2E07ACE3B51115837A6336E1CC567862651E911D5FF36D775FE600436BC21FC92076544D813C2437502FD5AC728
                C1BCBFEA216DFC4B544D39F6D3BC301D7409EDA84A4CFDC7E3D1BB4C37A9E9D27A25ED55630119DBBC4D79E052F1A2
                CBF5F121531DE33C1FAF2D97930E45A08DE816477711685B4D673041A4D75C8D613091274B2E8766037E4EA973A65F
                912D74319649E698A019ADEEC66567E9D05A135E8A",
  });
  ok($k, 'generate_key HASH');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $k = Crypt::PK::DSA->new;
  $k->generate_key(20, 128);
  ok($k, 'generate_key size');
  ok($k->is_private, 'is_private');
  ok($k->export_key_pem('private'), 'export_key_pem pri');
  ok($k->export_key_pem('public'), 'export_key_pem pub');
  ok($k->export_key_der('private'), 'export_key_der pri');
  ok($k->export_key_der('public'), 'export_key_der pub');
}

{
  my $ct = dsa_encrypt('t/data/cryptx_pub_dsa1.der', 'test string');
  ok($ct, 'dsa_encrypt');
  my $pt = dsa_decrypt('t/data/cryptx_priv_dsa1.der', $ct);
  ok($pt, 'dsa_decrypt');
  my $sig = dsa_sign_message('t/data/cryptx_priv_dsa1.der', 'test string');
  ok($sig, 'dsa_sign_message');
  ok(dsa_verify_message('t/data/cryptx_pub_dsa1.der', $sig, 'test string'), 'dsa_verify_message');
  my $hash = pack("H*","04624fae618e9ad0c5e479f62e1420c71fff34dd");
  $sig = dsa_sign_hash('t/data/cryptx_priv_dsa1.der', $hash, 'SHA1');
  ok($sig, 'dsa_sign_hash');
  ok(dsa_verify_hash('t/data/cryptx_pub_dsa1.der', $sig, $hash, 'SHA1'), 'dsa_verify_hash');
}
