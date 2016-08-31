use strict;
use warnings;
use Test::More;

BEGIN {
  plan skip_all => "requires Storable 2.0+" unless eval { require Storable && eval($Storable::VERSION) >= 2.0 };
  plan tests => 1;
}

use Math::BigInt::LTM;

use Storable qw(freeze thaw);

my $num = Math::BigInt::LTM->_new(42);

my $serialised = freeze $num;
my $cloned = thaw $serialised;

ok(!Math::BigInt::LTM->_acmp($cloned, $num));
