use strict;
use warnings;

use Test::More tests => 3;
use Crypt::Cipher::Twofish;

my $line = 1;
while (my $l = <DATA>) {
  chomp($l);
  $l =~ s/[\s\t]+/ /g;
  my $d = {};
  for my $pair (split / /, $l) {
    my ($k, $v) = split /:/, $pair;
    $d->{$k} = $v;
  }

  my $c = Crypt::Cipher::Twofish->new(pack('H*',$d->{key}));
  my $result = pack('H*', $d->{pt});
  $result = $c->encrypt($result) for(1..$d->{iter});
  is(unpack('H*', $result), lc($d->{ct}), "line=$line");
  $line++;
}

__DATA__
iter:1 key:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f pt:000102030405060708090A0B0C0D0E0F ct:8ef0272c42db838bcf7b07af0ec30f38
iter:1 key:000102030405060708090a0b0c0d0e0f1011121314151617 pt:000102030405060708090A0B0C0D0E0F ct:95accc625366547617f8be4373d10cd7
iter:1 key:000102030405060708090a0b0c0d0e0f pt:000102030405060708090A0B0C0D0E0F ct:9fb63337151be9c71306d159ea7afaa4
