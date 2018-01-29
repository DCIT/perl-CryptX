use strict;
use warnings;
use Test::More tests => 24;

use Crypt::Mode::CTR;

my $pt_hex = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
my $ct_hex = "3b3fd92eb72dad20333449f8e83cfb4a96ef86442deb1b77ed386671a3c3ecfab3006f3856f9a6699a37efae3e3d5c62b501d9aec0ea791c33b2c869c427fec1";
my $key = pack("H*", '2b7e151628aed2a6abf7158809cf4f3c');
my $iv  = pack("H*", '000102030405060708090a0b0c0d0e0f');
my $crt_mode = 0;

sub do_test {
  my %a = @_;
  my $pt  = pack("H*", $a{pt});
  my $key = pack("H*", $a{key});
  my $iv  = pack("H*", $a{iv});
  # test: encrypt/decrypt in a single step
  my $ct_out = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->encrypt($pt, $key, $iv);
  is(unpack("H*", $ct_out), $a{ct}, "cipher text1 [m=$a{mode}, w=$a{width}]");
  my $pt_out = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->decrypt($ct_out, $key, $iv);
  is(unpack("H*", $pt_out), $a{pt}, "plain text1 [m=$a{mode}, w=$a{width}]");
  # test: add(@in)
  my $mode;
  my @in = map { pack("H*", $_) } ($a{pt} =~ /(..)/g);
  $mode = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->start_encrypt($key, $iv);
  $ct_out = $mode->add(@in) . $mode->finish;
  is(unpack("H*", $ct_out), $a{ct}, "cipher text2 [m=$a{mode}, w=$a{width}]");
  $mode = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->start_encrypt($key, $iv);
  $ct_out = join ('', map { $mode->add($_) } @in) . $mode->finish;
  is(unpack("H*", $ct_out), $a{ct}, "cipher text3 [m=$a{mode}, w=$a{width}]");
  # test: add(?)->add(?)->add(?)->add(?)
  @in = split //, $ct_out;
  $mode = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->start_decrypt($key, $iv);
  $pt_out = $mode->add(@in) . $mode->finish;
  is(unpack("H*", $pt_out), $a{pt}, "plain text2 [m=$a{mode}, w=$a{width}]");
  $mode = Crypt::Mode::CTR->new('AES', $a{mode}, $a{width})->start_decrypt($key, $iv);
  $pt_out = join ('', map { $mode->add($_) } @in) . $mode->finish;
  is(unpack("H*", $pt_out), $a{pt}, "plain text3 [m=$a{mode}, w=$a{width}]");
}

do_test(%$_) for (
 {
   pt   => '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
   ct   => '3b3fd92eb72dad20333449f8e83cfb4a96ef86442deb1b77ed386671a3c3ecfab3006f3856f9a6699a37efae3e3d5c62b501d9aec0ea791c33b2c869c427fec1',
   key  => '2b7e151628aed2a6abf7158809cf4f3c', iv => '000102030405060708090a0b0c0d0e0f',
   mode => 0, width => 0,
 },
 {
   pt   => '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
   ct   => '3b3fd92eb72dad20333449f8e83cfb4a010c041999e03f36448624483e582d0ea62293cfa6df74535c354181168774df2d55a54706273c50d7b4f8a8cddc6ed7',
   key  => '2b7e151628aed2a6abf7158809cf4f3c', iv => '000102030405060708090a0b0c0d0e0f',
   mode => 1, width => 0,
 },
 {
   pt   => '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
   ct   => '5303b2f11da8287d9ab277cc95ff75812de5f929eba6eee4e17b411b619880dc7356e1adbcf9061a7b62480b38419b3e0146ff417abed13f054b9de33a7d3837',
   key  => '2b7e151628aed2a6abf7158809cf4f3c', iv => '000102030405060708090a0b0c0d0e0f',
   mode => 2, width => 0,
 },
 {
   pt   => '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
   ct   => 'c4e030aca9a30c3c330c35f50864b47538c705de1b803cde2779ef344922a861eb029d447a3443569f6478ca31ba0b28ee4c049b87186d1a43e8bf76a1320b79',
   key  => '2b7e151628aed2a6abf7158809cf4f3c', iv => '000102030405060708090a0b0c0d0e0f',
   mode => 3, width => 0,
 },
);
