#!perl

use strict;
use warnings;

use Test::More;

BEGIN {
  plan skip_all => "requires Math::BigInt" unless eval { require Math::BigInt };
  plan tests => 2;
}

use Math::BigInt lib => 'LTM';

my $V = $Math::BigInt::VERSION;

# https://github.com/DCIT/perl-CryptX/issues/56
{
  my ($x, $y);
  $x = Math::BigInt->new("2");
  $y = Math::BigInt->new("-1");
  is($x ** $y, $V < 1.999817 ? 'NaN' : 0);
  $x = Math::BigInt->new("-2");
  $y = Math::BigInt->new("-2");
  is($x ** $y, $V < 1.999817 ? 'NaN' : 0);
}
