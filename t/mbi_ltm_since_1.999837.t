use strict;
use warnings;
use Test::More;

BEGIN {
  plan skip_all => "requires Math::BigInt 1.999837+" unless eval { require Math::BigInt && eval($Math::BigInt::VERSION) >= 1.999837 };
  plan tests => 3;
}

use Math::BigFloat only => 'LTM';
use Math::BigInt only => 'LTM';

my ($x, $y);

### https://github.com/DCIT/perl-CryptX/issues/82

$x = Math::BigFloat->new("0");
$y = Math::BigFloat->new("20");
$x->bcos($y);
is($x, "1.0000000000000000000");
$x = Math::BigFloat->new("0");
$y = Math::BigFloat->new("20");
$x->bcos($y);
is($x, "1.0000000000000000000");
$x = Math::BigFloat->blog(Math::BigInt->new(100),10);
is($x, "2");

### unsolved part of https://github.com/DCIT/perl-CryptX/issues/82
## t/mbi_ltm_bigfltpm.t ................ 123/2408 Argument "" isn't numeric in subtraction (-) at /home/jkeenan/testing/v5.36.0/lib/perl5/site_perl/5.36.0/Math/BigFloat.pm line 4651, <DATA> line 330.
## Argument "" isn't numeric in subtraction (-) at /home/jkeenan/testing/v5.36.0/lib/perl5/site_perl/5.36.0/Math/BigFloat.pm line 4651, <DATA> line 331.
## Argument "" isn't numeric in subtraction (-) at /home/jkeenan/testing/v5.36.0/lib/perl5/site_perl/5.36.0/Math/BigFloat.pm line 4651, <DATA> line 332.
## Argument "abc" isn't numeric in subtraction (-) at /home/jkeenan/testing/v5.36.0/lib/perl5/site_perl/5.36.0/Math/BigFloat.pm line 4651, <DATA> line 333.
#
#&bone
#...
#-0::1
#--2::1
#-abc::1
#-2:abc:1
