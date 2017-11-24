use strict;
use warnings;

use Test::More tests => 5;
use Crypt::Cipher::SEED;

my $line = 1;
while (my $l = <DATA>) {
  chomp($l);
  $l =~ s/[\s\t]+/ /g;
  my $d = {};
  for my $pair (split / /, $l) {
    my ($k, $v) = split /:/, $pair;
    $d->{$k} = $v;
  }

  my $c = Crypt::Cipher::SEED->new(pack('H*',$d->{key}));
  my $result = pack('H*', $d->{pt});
  $result = $c->encrypt($result) for(1..$d->{iter});
  is(unpack('H*', $result), lc($d->{ct}), "line=$line");
  $line++;
}

__DATA__
iter:1 key:00000000000000000000000000000000 pt:000102030405060708090a0b0c0d0e0f ct:5EBAC6E0054E166819AFF1CC6D346CDB
iter:1 key:000102030405060708090a0b0c0d0e0f pt:00000000000000000000000000000000 ct:c11f22f20140505084483597e4370f43
iter:1 key:4706480851E61BE85D74BFB3FD956185 pt:83A2F8A288641FB9A4E9A5CC2F131C7D ct:EE54D13EBCAE706D226BC3142CD40D4A
iter:1 key:28DBC3BC49FFD87DCFA509B11D422BE7 pt:B41E6BE2EBA84A148E2EED84593C5EC7 ct:9B9B7BFCD1813CB95D0B3618F40F5122
iter:1 key:0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E pt:0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E ct:8296F2F1B007AB9D533FDEE35A9AD850
