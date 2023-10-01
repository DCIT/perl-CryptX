use strict;
use warnings;
use Test::More;

BEGIN {
  plan skip_all => "requires Math::BigInt 1.999842+" unless eval { require Math::BigInt && eval($Math::BigInt::VERSION) >= 1.999842 };
  plan tests => 7;
}

use Math::BigFloat only => 'LTM';
use Math::BigInt only => 'LTM';

######## https://github.com/Perl/perl5/issues/21518

#   Failed test '$x = Math::BigFloat->new("1"); $y = Math::BigFloat->new("1"); $x >> $y;'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '0'
#     expected: '0.5'

#   Failed test '$x = Math::BigFloat->new("123"); $y = Math::BigFloat->new("1"); $x >> $y;'
#   at ./t/mbi_ltm/bigfltpm.inc line 168.
#          got: '61'
#     expected: '61.5'

#   Failed test '$x = Math::BigFloat->new("2"); $y = Math::BigFloat->new("18.2"); $x <<= $y; $x->copy()->bfround(-9);'
#   at ./t/mbi_ltm/bigfltpm.inc line 502.
#          got: '524288.000000000'
#     expected: '602248.763144685'

#   Failed test '$x = Math::BigInt->new("+8"); $y = Math::BigInt->new("-2"); $x << $y;'
#   at ./t/mbi_ltm/bigintpm.inc line 202.
#          got: '2'
#     expected: 'NaN'

#   Failed test '$x = Math::BigInt->new("+1234"); $y = Math::BigInt->new("-3"); $x->blsft($y, 10);'
#   at ./t/mbi_ltm/bigintpm.inc line 202.
#          got: '1'
#     expected: 'NaN'

#   Failed test '$x = Math::BigInt->new("+2"); $y = Math::BigInt->new("-2"); $x >> $y;'
#   at ./t/mbi_ltm/bigintpm.inc line 202.
#          got: '8'
#     expected: 'NaN'

#   Failed test '$x = Math::BigInt->new("+1234"); $y = Math::BigInt->new("-3"); $x->brsft($y, 10);'
#   at ./t/mbi_ltm/bigintpm.inc line 202.
#          got: '1234000'
#     expected: 'NaN'

########

my ($x, $y);

$x = Math::BigFloat->new("1");
$y = Math::BigFloat->new("1");
is($x >> $y, 0);

$x = Math::BigFloat->new("123");
$y = Math::BigFloat->new("1");
is($x >> $y, 61);

$x = Math::BigFloat->new("2");
$y = Math::BigFloat->new("18.2");
$x = $x <<= $y;
$x->copy()->bfround(-9);
is($x, 524288);

$x = Math::BigInt->new("+8");
$y = Math::BigInt->new("-2");
is($x << $y, 2);

$x = Math::BigInt->new("+1234");
$y = Math::BigInt->new("-3");
$x->blsft($y, 10);
is($x, 1);

$x = Math::BigInt->new("+2");
$y = Math::BigInt->new("-2");
is($x >> $y, 8);

$x = Math::BigInt->new("+1234");
$y = Math::BigInt->new("-3");
$x->brsft($y, 10);
is($x, 1234000);
