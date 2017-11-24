use strict;
use warnings;
use Test::More tests => 19;

use Crypt::PRNG::ChaCha20 qw(random_bytes random_bytes_hex random_bytes_b64 random_bytes_b64u random_string random_string_from rand irand);

my $r = Crypt::PRNG::ChaCha20->new();
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
