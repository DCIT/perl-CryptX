#!perl

use strict;
use warnings;

use Test::More;

BEGIN {
    plan skip_all => "requires Math::BigFloat 1.999827+" unless eval { require Math::BigFloat && eval($Math::BigFloat::VERSION) >= 1.999827 };
    plan tests => 2380            # tests in require'd file
                  + 5;            # tests in this file
}

use Math::BigInt lib => 'LTM';
use Math::BigFloat;

our $CLASS = "Math::BigFloat";
our $CALC  = "Math::BigInt::LTM";      # backend

is($CLASS->config()->{class}, $CLASS, "$CLASS->config()->{class}");
is($CLASS->config()->{with},  $CALC,  "$CLASS->config()->{with}");

# bug #17447: Can't call method Math::BigFloat->bsub, not a valid method
my $c = Math::BigFloat->new('123.3');
is($c->bsub(123), '0.3',
   qq|\$c = Math::BigFloat -> new("123.3"); \$y = \$c -> bsub("123")|);

# Bug until Math::BigInt v1.86, the scale wasn't treated as a scalar:
$c = Math::BigFloat->new('0.008');
my $d = Math::BigFloat->new(3);
my $e = $c->bdiv(Math::BigFloat->new(3), $d);

is($e, '0.00267', '0.008 / 3 = 0.0027');

SKIP: {
    skip("skipping test which is not for this backend", 1)
      unless $CALC eq 'Math::BigInt::Calc';
    is(ref($e->{_e}->[0]), '', '$e->{_e}->[0] is a scalar');
}

require './t/mbi_ltm/bigfltpm.inc'; # all tests here for sharing
