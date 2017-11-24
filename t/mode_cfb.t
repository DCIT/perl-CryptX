use strict;
use warnings;
use Test::More tests => 12;
use Crypt::Mode::CFB;

my @tests = (
  { key=>'2b7e151628aed2a6abf7158809cf4f3c', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
    ct=>'3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6' },
  { key=>'8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c',
    ct=>'cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b' },
  { key=>'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', iv=>'000102030405060708090a0b0c0d0e0f',
    pt=>'6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b',
    ct=>'dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d' },
);

my $m = Crypt::Mode::CFB->new('AES');
for (@tests) {
  my ($pt, $ct);
  $ct = $m->encrypt(pack("H*",$_->{pt}), pack("H*",$_->{key}), pack("H*",$_->{iv}));
  $pt = $m->decrypt(pack("H*",$_->{ct}), pack("H*",$_->{key}), pack("H*",$_->{iv}));
  ok($ct, "cipher text");
  ok($pt, "plain text");
  is(unpack("H*",$ct), $_->{ct}, 'cipher text match');
  is(unpack("H*",$pt), $_->{pt}, 'plain text match');
}
