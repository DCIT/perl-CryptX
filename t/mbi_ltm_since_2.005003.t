use strict;
use warnings;
use Test::More;

BEGIN {
  plan skip_all => "requires Math::BigInt 2.005003+" unless eval { require Math::BigInt && eval($Math::BigInt::VERSION) >= 2.005003 };
  plan tests => 5;
}

use Math::BigFloat only => 'LTM';
use Math::BigInt only => 'LTM';

######## https://github.com/DCIT/perl-CryptX/issues/118

#   Failed test '$x = Math::BigFloat->new("+0"); $y = Math::BigFloat->new("+0"); Math::BigFloat::blcm($x, $y);'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '0'
#     expected: 'NaN'

#   Failed test '$x = Math::BigFloat->new("2.1"); $y = Math::BigFloat->new("-1"); $Math::BigFloat::round_mode = "even"; join(",", $x->bdiv($y));'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '-3,-0.9'
#     expected: '-2.1,0'

#   Failed test '$x = Math::BigFloat->new("2.1"); $y = Math::BigFloat->new("1"); $Math::BigFloat::round_mode = "even"; join(",", $x->bdiv($y));'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '2,0.1'
#     expected: '2.1,0'

#   Failed test '$x = Math::BigFloat->new("-2.1"); $y = Math::BigFloat->new("-1"); $Math::BigFloat::round_mode = "even"; join(",", $x->bdiv($y));'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '2,-0.1'
#     expected: '2.1,0'

#   Failed test '$x = Math::BigFloat->new("-2.1"); $y = Math::BigFloat->new("1"); $Math::BigFloat::round_mode = "even"; join(",", $x->bdiv($y));'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '-3,0.9'
#     expected: '-2.1,0'

########

my ($x, $y);

$x = Math::BigFloat->new("+0");
$y = Math::BigFloat->new("+0");
is(Math::BigFloat::blcm($x, $y), 0);

$x = Math::BigFloat->new("2.1");
$y = Math::BigFloat->new("-1");
$Math::BigFloat::round_mode = "even";
is(join(",", $x->bdiv($y)), '-3,-0.9');

$x = Math::BigFloat->new("2.1");
$y = Math::BigFloat->new("1");
$Math::BigFloat::round_mode = "even";
is(join(",", $x->bdiv($y)), '2,0.1');

$x = Math::BigFloat->new("-2.1");
$y = Math::BigFloat->new("-1");
$Math::BigFloat::round_mode = "even";
is(join(",", $x->bdiv($y)), '2,-0.1');

$x = Math::BigFloat->new("-2.1");
$y = Math::BigFloat->new("1");
$Math::BigFloat::round_mode = "even";
is(join(",", $x->bdiv($y)), '-3,0.9');
