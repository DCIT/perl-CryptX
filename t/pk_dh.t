use strict;
use warnings;
use Test::More tests => 60;

use Crypt::Misc 'decode_b64';
use Crypt::PK::DH qw(dh_shared_secret);

{
  my $k;

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh1.bin');
  ok($k, 'load cryptx_priv_dh1.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh1.bin');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{x}), '73CA6A11B1595C06AB08E8E0875B9689E265C29E3F52FBC7830F071AEA4AF5A26D23CFBC96101267', 'key2hash');

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh2.bin');
  ok($k, 'load cryptx_priv_dh2.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh2.bin');

  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh1.bin');
  ok($k, 'load cryptx_pub_dh1.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh1.bin');

  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh2.bin');
  ok($k, 'load cryptx_pub_dh2.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh2.bin');
}

{
  my $k;

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh_pg1.bin');
  ok($k, 'load cryptx_priv_dh_pg1.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh_pg1.bin');
  is($k->size, 256, 'size');
  is(uc($k->key2hash->{x}), '3E2F764CDAD2EDFEC737E2198C9C4FAFBA4274C8A73A9E2FDCBC11954D8B48C375399E4BDE930EC9', 'key2hash');

  $k = Crypt::PK::DH->new('t/data/cryptx_priv_dh_pg2.bin');
  ok($k, 'load cryptx_priv_dh_pg2.bin');
  ok($k->is_private, 'is_private cryptx_priv_dh_pg2.bin');

  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh_pg1.bin');
  ok($k, 'load cryptx_pub_dh_pg1.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh_pg1.bin');

  $k = Crypt::PK::DH->new('t/data/cryptx_pub_dh_pg2.bin');
  ok($k, 'load cryptx_pub_dh_pg2.bin');
  ok(!$k->is_private, 'is_private cryptx_pub_dh_pg2.bin');
}

{
  my $pr1 = Crypt::PK::DH->new;
  $pr1->import_key('t/data/cryptx_priv_dh1.bin');
  my $pu1 = Crypt::PK::DH->new;
  $pu1->import_key('t/data/cryptx_pub_dh1.bin');

  my $pr2 = Crypt::PK::DH->new;
  $pr2->import_key('t/data/cryptx_priv_dh2.bin');
  my $pu2 = Crypt::PK::DH->new;
  $pu2->import_key('t/data/cryptx_pub_dh2.bin');

  my $ss1 = $pr1->shared_secret($pu2);
  my $ss2 = $pr2->shared_secret($pu1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $pr1 = Crypt::PK::DH->new;
  $pr1->import_key('t/data/cryptx_priv_dh_pg1.bin');
  my $pu1 = Crypt::PK::DH->new;
  $pu1->import_key('t/data/cryptx_pub_dh_pg1.bin');

  my $pr2 = Crypt::PK::DH->new;
  $pr2->import_key('t/data/cryptx_priv_dh_pg2.bin');
  my $pu2 = Crypt::PK::DH->new;
  $pu2->import_key('t/data/cryptx_pub_dh_pg2.bin');

  my $ss1 = $pr1->shared_secret($pu2);
  my $ss2 = $pr2->shared_secret($pu1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $pr1 = Crypt::PK::DH->new;
  $pr1->import_key_raw(pack('H*','5F7EF8D4F7D80C2D88ADADDFE57F4F4DC578259E3B5F42D82838D5905FF6D2BECDC489452D3F5807EF4E2361821089DDC9B27198D79E9C22EE249318688FE250CCC69E49C5F985777405A76264C5EF0D83AEA1C368B1E1A48DC0E04D6E0C884F0C95A3949B29A05437A6179E7AADCC4D095A55C03046296C02AA9991EFD17745615726D52B8B8A12DAC7218265DBB4B760176C27E644AD2EC15B238980326BE1B27D5AC28EA2B2DC5F24FD6A315CA2193A23370B130B541D54C470AD91BE20ECD697B01C2DAEE00E0027A9EBD2D87404E20ADE1DE3B92798928B837AC5EFB305C168823D362A1162C7A709A70E6619F01AF113E316376B3561F88AC2B6F647B2'),'private','ike2048');
  my $pu1 = Crypt::PK::DH->new;
  $pu1->import_key_raw(pack('H*','4B9ECB56202EDBC6578072A4519EBE625DE8972877462240F62393C59A6C04AA159E56505156E7DF645FF6EC588E0778A96B78B26A0793D90A4B5C5EC4C61EA69D21C630843ACC2BFD3864CD9DA9600BA8F1B7D8542B01F7251AA3AC257C7AC65A1D2BCF51A8E3E67D9544599B0956710E2B052CDA9B565CDD121CC123364B480E9E7E2237D3D6B5B1E200C7BF858C54CCD3175736DB28336210A16F8F0ACEC08847EF7905FAB7E97E626CFD13CBDF167441FEEB72CB6E7407DFC59F03249F79312A94DA89B1D61196B41E90C08D2C801FD7BEA02A47A1CDA1581F57BA700C1BCDDE6338718E19079055194CAF176D85464957D405B04CC3DD9756C211E11BF2'),'public','ike2048');
  ok($pr1, 'import_key_raw private1');
  ok($pu1, 'import_key_raw public1');
  ok($pr1->is_private, 'is_private private1');
  ok(!$pu1->is_private, 'is_private public1');
  is(uc(unpack('H*',$pr1->export_key_raw('private'))),'5F7EF8D4F7D80C2D88ADADDFE57F4F4DC578259E3B5F42D82838D5905FF6D2BECDC489452D3F5807EF4E2361821089DDC9B27198D79E9C22EE249318688FE250CCC69E49C5F985777405A76264C5EF0D83AEA1C368B1E1A48DC0E04D6E0C884F0C95A3949B29A05437A6179E7AADCC4D095A55C03046296C02AA9991EFD17745615726D52B8B8A12DAC7218265DBB4B760176C27E644AD2EC15B238980326BE1B27D5AC28EA2B2DC5F24FD6A315CA2193A23370B130B541D54C470AD91BE20ECD697B01C2DAEE00E0027A9EBD2D87404E20ADE1DE3B92798928B837AC5EFB305C168823D362A1162C7A709A70E6619F01AF113E316376B3561F88AC2B6F647B2');
  is(uc(unpack('H*',$pr1->export_key_raw('public'))),'4B9ECB56202EDBC6578072A4519EBE625DE8972877462240F62393C59A6C04AA159E56505156E7DF645FF6EC588E0778A96B78B26A0793D90A4B5C5EC4C61EA69D21C630843ACC2BFD3864CD9DA9600BA8F1B7D8542B01F7251AA3AC257C7AC65A1D2BCF51A8E3E67D9544599B0956710E2B052CDA9B565CDD121CC123364B480E9E7E2237D3D6B5B1E200C7BF858C54CCD3175736DB28336210A16F8F0ACEC08847EF7905FAB7E97E626CFD13CBDF167441FEEB72CB6E7407DFC59F03249F79312A94DA89B1D61196B41E90C08D2C801FD7BEA02A47A1CDA1581F57BA700C1BCDDE6338718E19079055194CAF176D85464957D405B04CC3DD9756C211E11BF2');
  is(uc(unpack('H*',$pu1->export_key_raw('public'))),'4B9ECB56202EDBC6578072A4519EBE625DE8972877462240F62393C59A6C04AA159E56505156E7DF645FF6EC588E0778A96B78B26A0793D90A4B5C5EC4C61EA69D21C630843ACC2BFD3864CD9DA9600BA8F1B7D8542B01F7251AA3AC257C7AC65A1D2BCF51A8E3E67D9544599B0956710E2B052CDA9B565CDD121CC123364B480E9E7E2237D3D6B5B1E200C7BF858C54CCD3175736DB28336210A16F8F0ACEC08847EF7905FAB7E97E626CFD13CBDF167441FEEB72CB6E7407DFC59F03249F79312A94DA89B1D61196B41E90C08D2C801FD7BEA02A47A1CDA1581F57BA700C1BCDDE6338718E19079055194CAF176D85464957D405B04CC3DD9756C211E11BF2');

  my $pr2 = Crypt::PK::DH->new;
  $pr2->import_key_raw(pack('H*','473156C909EBB0A6F61F707CDDD7E6401BFDE22BC57B8D3CCC30C4CD3FF7678CCD9B022167AA774786F367FE5B5924A3C1E09AA71264F94E7ABA87FFA888913BB9592613F8AD87FBE82E99064B00CE3294CFD410BCFB4C88A46F5F8532633458C317DF40F395C2F08A822D84BF4291A1A63DE1F6D0F460DB81C685ADD0F26262307823227C17B4671BCF74A6337738BB4596337644656A060F1BB109640878D23F56E493719D6EF60FEA7AC85123CFB6E476392789AC1FE4F4CA371DB2863192ADE424F3EFDEE52D4CB445B99B10566A4B6F6DC813C265DC0052D710AEAA0969392BD478A46AB9C7A0E2FA27964A759938904FCEFAC4CE061C9927764AAB57DC'),'private','ike2048');
  my $pu2 = Crypt::PK::DH->new;
  $pu2->import_key_raw(pack('H*','774A01FF19C1603040DFBB5C8A44F11CE8719F757C2AF6B2921EDDDEF27F77D5F2DAF9539BCBCB30F80D76E054C489C9E6533051767E6220539C871F23D3B6F80D84037A6FBAB3AE6AF8F214A60A816D6F0F6C3F31801DCD6EA771F41A2A5618BC333D650F46F22FEA81A94F4E00CD05B83F8FE257A2607E62519D9BF8B8C96D0587FB2BCEC8D18DDCF66EBBB8A56623953531EE27C68C8C37E6413FD2C98339F491A0472E5D4DFADC7BF30E89A2CE2081EE3CF9F9B0FFCD902A3021CAC14A4AD7E00F6202C8A9AB93BF96E33838FB9178DC8A8F995ABD81F28F5A137A78E813ABD185498A3A50CB3021CF58BE9D0200C19928AA097D306ABAD9874E0F217482'),'public','ike2048');

  my $ss1 = $pr1->shared_secret($pu2);
  my $ss2 = $pr2->shared_secret($pu1);
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $k = Crypt::PK::DH->new;
  my $p = <<"MARKER";
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA7DIdWuBlIVFTnN9t9SP5tjajNgmQtBuhRlBQJIaHxblApAP9XZgS
iuAdkZugjvYb83bFzrjdo+TyKCUKZwVp8pv8LHEG90K54BsZwlbyjHHVlWFcQPIh
XYMg7YKEVcOPg0ZRty55g2u6IMMlMl16WWubHvtAeI0qVU7VUA6vuy7qAOauaZWo
0klH0zGkc8s1NGectcNbk8GmlUop+7JLUh3K0ikHVPYx2OJHjBhTz2vPgTdlcbHb
+dQIMdLFBOySNKv141QsDBo1ugu0Cxx02We6FFp1k5k4le+yGhFtLotE4OlZtcZW
xyjO1D0DrX8p6PeI4OmMAeGgGmDNBGreywIBAg==
-----END DH PARAMETERS-----
MARKER
  $k->generate_key(\$p);
  ok($k, 'generate_key PEM');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
}

{
  my $k = Crypt::PK::DH->new;
  my $p = decode_b64(<<"MARKER");
MIIBCAKCAQEA7DIdWuBlIVFTnN9t9SP5tjajNgmQtBuhRlBQJIaHxblApAP9XZgS
iuAdkZugjvYb83bFzrjdo+TyKCUKZwVp8pv8LHEG90K54BsZwlbyjHHVlWFcQPIh
XYMg7YKEVcOPg0ZRty55g2u6IMMlMl16WWubHvtAeI0qVU7VUA6vuy7qAOauaZWo
0klH0zGkc8s1NGectcNbk8GmlUop+7JLUh3K0ikHVPYx2OJHjBhTz2vPgTdlcbHb
+dQIMdLFBOySNKv141QsDBo1ugu0Cxx02We6FFp1k5k4le+yGhFtLotE4OlZtcZW
xyjO1D0DrX8p6PeI4OmMAeGgGmDNBGreywIBAg==
MARKER
  $k->generate_key(\$p);
  ok($k, 'generate_key DER');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key({
        g=>"0x2",
        p=>"0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1".
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DD".
             "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245".
             "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED".
             "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D".
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F".
             "83655D23DCA3AD961C62F356208552BB9ED529077096966D".
             "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B".
             "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9".
             "DE2BCBF6955817183995497CEA956AE515D2261898FA0510".
             "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64".
             "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7".
             "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B".
             "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C".
             "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31".
             "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
  });
  ok($k, 'generate_key HASH');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key('ike2048');
  ok($k, 'generate_key groupname');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key(256);
  ok($k, 'generate_key groupsize');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri');
  ok($k->export_key('public'), 'export_key_pem pub');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key({g => 2, p => 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF'});
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri gp');
  ok($k->export_key('public'), 'export_key_pem pub gp');
}

{
  my $k = Crypt::PK::DH->new;
  $k->generate_key('ike2048');
  ok($k, 'generate_key');
  ok($k->is_private, 'is_private');
  ok($k->export_key('private'), 'export_key_pem pri ike2048');
  ok($k->export_key('public'), 'export_key_pem pub ike2048');
}

{
  my $ss1 = dh_shared_secret('t/data/cryptx_priv_dh1.bin', 't/data/cryptx_pub_dh2.bin');
  my $ss2 = dh_shared_secret('t/data/cryptx_priv_dh2.bin', 't/data/cryptx_pub_dh1.bin');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}

{
  my $ss1 = dh_shared_secret('t/data/cryptx_priv_dh_pg1.bin', 't/data/cryptx_pub_dh_pg2.bin');
  my $ss2 = dh_shared_secret('t/data/cryptx_priv_dh_pg2.bin', 't/data/cryptx_pub_dh_pg1.bin');
  is(unpack("H*",$ss1), unpack("H*",$ss2), 'shared_secret');
}
