use strict;
use warnings;
use Test::More tests => 12;
use Crypt::Mode::OFB;

my @tests = (
  { key=>'2b7e151628aed2a6abf7158809cf4f3c', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
    ct=>'3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e' },
  { key=>'8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c',
    ct=>'cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9ac' },
  { key=>'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b',
    ct=>'dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8b' },
);

my $m = Crypt::Mode::OFB->new('AES');

for (@tests) {
  my ($pt, $ct);
  $ct = $m->encrypt(pack("H*",$_->{pt}), pack("H*",$_->{key}), pack("H*",$_->{iv}));
  $pt = $m->decrypt(pack("H*",$_->{ct}), pack("H*",$_->{key}), pack("H*",$_->{iv}));
  ok($ct, "cipher text");
  ok($pt, "plain text");
  is(unpack("H*",$ct), $_->{ct}, 'cipher text match');
  is(unpack("H*",$pt), $_->{pt}, 'plain text match');
}
