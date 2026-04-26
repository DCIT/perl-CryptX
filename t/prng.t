use strict;
use warnings;
use Test::More tests => 79;

use Crypt::PRNG qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u random_string random_string_from rand irand);

{
  package Local::PRNGName;
  use overload '""' => sub { 'ChaCha20' }, fallback => 1;
}

my $r = Crypt::PRNG->new();
ok($r, 'new');

{
 my $sum = 0;
 $sum += $r->double for (1..1000);
 my $avg = $sum/1000;
 ok($avg>0.4 && $avg<0.6, "rand $avg");
}

{
 my $sum = 0;
 $sum += $r->double(-180) for (1..1000);
 my $avg = $sum/1000;
 ok($avg>-100 && $avg<-80, "rand $avg");
}

{
 my $sum = 0;
 $sum += $r->int32 for (1..1000);
 my $avg = $sum/1000;
 ok($avg>2**30 && $avg<2**32, "rand $avg");
}

{
 my $sum = 0;
 $sum += rand(80) for (1..1000);
 my $avg = $sum/1000;
 ok($avg>30 && $avg<50, "rand $avg");
}

{
 my $sum = 0;
 $sum += rand(-180) for (1..1000);
 my $avg = $sum/1000;
 ok($avg>-100 && $avg<-80, "rand $avg");
}

{
 my $sum = 0;
 $sum += irand for (1..1000);
 my $avg = $sum/1000;
 ok($avg>2**30 && $avg<2**32, "rand $avg");
}

{
  like($r->string(45), qr/^[A-Z-a-z0-9]+$/, 'string');
  like($r->string_from("ABC,.-", 45), qr/^[ABC,\,\.\-]+$/, 'string');
  is(length $r->bytes(55), 55, "bytes");
  like($r->bytes_hex(55),  qr/^[0-9A-Fa-f]{110}$/,    "bytes_hex");
  like($r->bytes_b64(60),  qr/^[A-Za-z0-9+\/=]{80}$/, "bytes_b64");
  like($r->bytes_b64u(60), qr/^[A-Za-z0-9_-]{80}$/,   "bytes_b64u");

  like(random_string(45), qr/^[A-Z-a-z0-9]+$/, 'string');
  like(random_string_from("ABC,.-", 45), qr/^[ABC,\,\.\-]+$/, 'string');
  is(length random_bytes(55), 55, "bytes");
  like(random_bytes_hex(55),  qr/^[0-9A-Fa-f]{110}$/,    "bytes_hex");
 like(random_bytes_b64(60),  qr/^[A-Za-z0-9+\/=]{80}$/, "bytes_b64");
 like(random_bytes_b64u(60), qr/^[A-Za-z0-9_-]{80}$/,   "bytes_b64u");
}

{
  for my $len (1..6) {
    is(length($r->bytes_b64($len)), 4 * int(($len + 2) / 3), "bytes_b64 length $len");
    is(length($r->bytes_b64u($len)), 4 * int(($len + 2) / 3) - (($len % 3) ? (3 - $len % 3) : 0), "bytes_b64u length $len");
  }
}

{
  is(length($r->bytes(0)), 0, 'method bytes zero');
  is(length($r->bytes_hex(0)), 0, 'method bytes_hex zero');
  is(length($r->bytes_b64(0)), 0, 'method bytes_b64 zero');
  is(length($r->bytes_b64u(0)), 0, 'method bytes_b64u zero');
  is(length(random_bytes(0)), 0, 'func random_bytes zero');
  is(length(random_bytes_hex(0)), 0, 'func random_bytes_hex zero');
  is(length(random_bytes_b64(0)), 0, 'func random_bytes_b64 zero');
  is(length(random_bytes_b64u(0)), 0, 'func random_bytes_b64u zero');
}

{
  my @invalid_len = (
    [-1, '-1'],
    ['18446744073709551616', 'too large'],
  );
  for my $spec (@invalid_len) {
    my ($len, $label) = @$spec;
    for my $call (
      [sub { $r->bytes($len) }, "method bytes $label"],
      [sub { $r->bytes_hex($len) }, "method bytes_hex $label"],
      [sub { $r->bytes_b64($len) }, "method bytes_b64 $label"],
      [sub { $r->bytes_b64u($len) }, "method bytes_b64u $label"],
      [sub { random_bytes($len) }, "func random_bytes $label"],
      [sub { random_bytes_hex($len) }, "func random_bytes_hex $label"],
      [sub { random_bytes_b64($len) }, "func random_bytes_b64 $label"],
      [sub { random_bytes_b64u($len) }, "func random_bytes_b64u $label"],
    ) {
      my ($code, $name) = @$call;
      eval { $code->(); 1 };
      like($@, qr/^FATAL: output_len too large\b/, "$name croaks cleanly");
    }
  }
}

{
  my $obj = bless {}, 'Local::PRNGName';
  isa_ok(Crypt::PRNG->new($obj), 'Crypt::PRNG', 'stringifiable algorithm name');

  for my $spec (
    [undef, 'undef'],
    [[], 'arrayref'],
    [1, 'numeric'],
  ) {
    my ($alg, $label) = @$spec;
    eval { Crypt::PRNG->new($alg); 1 };
    like($@, qr/^FATAL: (?:invalid PRNG name|find_prng failed for '1')/, "new($label) error");
  }
}

{
  my $p = Crypt::PRNG->new;
  eval { $p->add_entropy("some extra entropy data") };
  is($@, '', "add_entropy with explicit data");
  eval { $p->add_entropy() };
  is($@, '', "add_entropy auto-seed");
  is(length($p->bytes(16)), 16, "bytes work after add_entropy");
}

{
  is($r->string_from("A" x 65536, 8), "A" x 8, 'string_from accepts 65536-char alphabet');
  ok(!defined $r->string_from("A" x 65537, 8), 'string_from rejects alphabet > 65536 chars');
  is(length($r->string_from("ABCD", 1024)), 1024, 'string_from large output');
}

{
  for my $alg (qw(ChaCha20 Fortuna Sober128 Yarrow)) {
    my $prng = eval { Crypt::PRNG->new($alg, 'A') };
    ok($prng, "$alg accepts 1-byte seed");
  }

  for my $alg (qw(ChaCha20 Fortuna RC4 Sober128 Yarrow)) {
    eval { Crypt::PRNG->new($alg, ''); 1 };
    like($@, qr/^FATAL: PRNG_add_entropy failed:/, "$alg rejects empty seed");
  }

  for my $len (1..4) {
    eval { Crypt::PRNG->new('RC4', 'A' x $len); 1 };
    like($@, qr/^FATAL: PRNG_ready failed:/, "RC4 rejects $len-byte seed");
  }

  my $rc4 = eval { Crypt::PRNG->new('RC4', 'A' x 5) };
  ok($rc4, 'RC4 accepts 5-byte seed');
}
