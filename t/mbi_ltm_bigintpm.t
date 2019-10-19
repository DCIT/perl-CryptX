#!perl

use strict;
use warnings;

use Test::More;

BEGIN {
  plan skip_all => "requires Math::BigInt 1.999817+" unless eval { require Math::BigInt && eval($Math::BigInt::VERSION) >= 1.999817 };
  plan tests => 3712            # tests in require'd file
                 + 6;           # tests in this file
}

use Math::BigInt lib => 'LTM';

our ($CLASS, $CALC);
$CLASS = "Math::BigInt";
$CALC  = "Math::BigInt::LTM";

my $x;

#############################################################################
# from_hex(), from_bin() and from_oct() tests

$x = Math::BigInt->from_hex('0xcafe');
is($x, "51966",
   qq|Math::BigInt->from_hex("0xcafe")|);

$x = Math::BigInt->from_hex('0xcafebabedead');
is($x, "223195403574957",
   qq|Math::BigInt->from_hex("0xcafebabedead")|);

$x = Math::BigInt->from_bin('0b1001');
is($x, "9",
   qq|Math::BigInt->from_bin("0b1001")|);

$x = Math::BigInt->from_bin('0b1001100110011001100110011001');
is($x, "161061273",
   qq|Math::BigInt->from_bin("0b1001100110011001100110011001");|);

$x = Math::BigInt->from_oct('0775');
is($x, "509",
   qq|Math::BigInt->from_oct("0775");|);

$x = Math::BigInt->from_oct('07777777777777711111111222222222');
is($x, "9903520314281112085086151826",
   qq|Math::BigInt->from_oct("07777777777777711111111222222222");|);

#############################################################################
# all the other tests

require './t/mbi_ltm/bigintpm.inc';       # all tests here for sharing
