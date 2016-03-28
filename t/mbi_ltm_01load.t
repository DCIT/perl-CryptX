#!perl

use strict;             # restrict unsafe constructs
use warnings;           # enable optional warnings

use Test::More tests => 2;

BEGIN {
    use_ok('Math::BigInt::LTM');
    use_ok('Math::BigInt');         # Math::BigInt is required for the tests
};
