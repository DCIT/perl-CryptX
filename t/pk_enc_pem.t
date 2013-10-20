use strict;
use warnings;
use Test::More;

use Crypt::PK::RSA;
use Crypt::PK::DSA;

for my $f (qw/rsa-aes128.pem rsa-aes192.pem rsa-aes256.pem rsa-des.pem rsa-des3.pem rsa-seed.pem rsa-camellia128.pem rsa-camellia192.pem rsa-camellia256.pem/) {
  my $pk = Crypt::PK::RSA->new("t/data/$f", 'secret');
  is($pk->is_private, 1, $f);
}

for my $f (qw/dsa-aes128.pem dsa-aes192.pem dsa-aes256.pem dsa-des.pem dsa-des3.pem dsa-seed.pem dsa-camellia128.pem dsa-camellia192.pem dsa-camellia256.pem/) {
  my $pk = Crypt::PK::DSA->new("t/data/$f", 'secret');
  is($pk->is_private, 1, $f);
}

done_testing;