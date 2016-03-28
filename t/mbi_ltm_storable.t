use strict;
use warnings;
use Test::More tests => 1;

use Math::BigInt::LTM;

use Storable qw(freeze thaw);

my $num = Math::BigInt::LTM->_new(42);

my $serialised = freeze $num;
my $cloned = thaw $serialised;

ok(!Math::BigInt::LTM->_acmp($cloned, $num));
