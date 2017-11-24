use strict;
use warnings;

use Test::More tests => 4;
use Crypt::Cipher::XTEA;

my $line = 1;
while (my $l = <DATA>) {
  chomp($l);
  $l =~ s/[\s\t]+/ /g;
  my $d = {};
  for my $pair (split / /, $l) {
    my ($k, $v) = split /:/, $pair;
    $d->{$k} = $v;
  }

  my $c = Crypt::Cipher::XTEA->new(pack('H*',$d->{key}));
  my $result = pack('H*', $d->{pt});
  $result = $c->encrypt($result) for(1..$d->{iter});
  is(unpack('H*', $result), lc($d->{ct}), "line=$line");
  $line++;
}

__DATA__
iter:1 key:00000000000000000000000000000000 pt:0000000000000000 ct:dee9d4d8f7131ed9
iter:1 key:00000000000000000000000000000000 pt:0102030405060708 ct:065c1b8975c6a816
iter:1 key:0123456712345678234567893456789A pt:0000000000000000 ct:1ff9a0261ac64264
iter:1 key:0123456712345678234567893456789A pt:0102030405060708 ct:8c67155b2ef91ead
