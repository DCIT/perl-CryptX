#!/usr/bin/env perl

# See https://rt.cpan.org/Ticket/Display.html?id=103517

use strict;
use warnings;

use Test::More;
use Config;

my $use64;

BEGIN {
  plan skip_all => "requires Math::BigInt 1.999712+" unless eval { require Math::BigInt && eval($Math::BigInt::VERSION) >= 1.999712 };
  # Don't run these tests unless we have proper 64-bit support.
  plan skip_all => "missing 64bit int support" if $Config{ivsize} < 8;
  $use64    = ~0 > 4294967295;
  my $broken64 = (18446744073709550592 == ~0);
  if ($broken64) {
      plan(skip_all =>
           "Your 64-bit system is broken.  Upgrade from 5.6 for this test.");
  }
  plan tests => 4*2 + 2*1 + 1 + $use64;
}

diag "use64=".($use64?1:0)." ivsize=".$Config{ivsize}." ivtype=".$Config{ivtype}." use64bitint=".$Config{use64bitint}."\n";

use Math::BigInt lib => "LTM";

my $maxs = ~0 >> 1;
for my $n ($maxs - 2, $maxs - 1, $maxs, $maxs + 1) {
    is( Math::BigInt->new($n), $n, "new $n" );
    is( Math::BigInt->new(-$n), -$n, "new -$n" );
}

for my $n (~0 - 1, ~0) {
    is( Math::BigInt->new($n), $n, "new $n" );
}

# bacmp makes a new variable.  This will test if it is screwing up the sign.
is( Math::BigInt->new(10)->bacmp(~0), -1, "10 should be less than maxint" );

if ($use64) {
  SKIP: {
        skip "The following test may hang or cause an exception if incorrect."
          . " Set AUTHOR_TESTING to a true value to run this test.", 1
            unless $ENV{AUTHOR_TESTING};

        is( Math::BigInt->new("14")->bmodpow(9506577562092332135,
                                             "29544731879021791655795710"),
            "19946192910281559497582964", "big modpow" );
    }
}
