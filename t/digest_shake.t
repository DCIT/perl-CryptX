use strict;
use warnings;

use Test::More tests => 7;

use Crypt::Digest::SHAKE;


my $sh128 = Crypt::Digest::SHAKE->new(128);
ok($sh128, "Crypt::Digest::SHAKE->new(128)");

my $sh256 = Crypt::Digest::SHAKE->new(256);
ok($sh256, "Crypt::Digest::SHAKE->new(256)");

is(unpack("H*", $sh128->add("")->done(32)), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
is(unpack("H*", $sh256->add("")->done(64)), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

is(unpack("H*", Crypt::Digest::SHAKE->new(128)->add("The quick brown fox jumps over the lazy dog")->done(32)),
   "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e");
is(unpack("H*", Crypt::Digest::SHAKE->new(128)->add("The quick brown fox jumps over the lazy dof")->done(32)),
   "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c");

{
  my $sh128 = Crypt::Digest::SHAKE->new(128);
  $sh128->add("The qui");
  $sh128->add("ck bro");
  $sh128->add("wn fox j");
  $sh128->add("umps o");
  $sh128->add("ver the l");
  $sh128->add("azy dof");
  my $res = $sh128->done(5);
  $res .= $sh128->done(7);
  $res .= $sh128->done(8);
  $res .= $sh128->done(12);
  is(unpack("H*", $res), "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c");
}
