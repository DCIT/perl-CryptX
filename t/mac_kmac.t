use strict;
use warnings;

use Test::More tests => 33;

use Crypt::Mac::KMAC qw( kmac kmac_hex kmac_b64 kmac_b64u );

# Vectors from NIST SP 800-185 KMAC_samples.pdf — KMAC128, KMAC256
# Key K = 0x40 0x41 ... 0x5F (32 bytes); data X is either 4 or 200 bytes.
my $key    = pack("C*", 0x40..0x5F);
my $data4  = pack("C*", 0x00, 0x01, 0x02, 0x03);
my $data200 = pack("C*", 0x00..0xC7);
my $S      = "My Tagged Application";

# --- Fixed-output KMAC128 / KMAC256 -----------------------------------------
my @kmac_vectors = (
  # [variant, outlen, key, cust, data, expected_hex]
  ['KMAC128', 32, $key, '',     $data4,
    'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e'],
  ['KMAC128', 32, $key, $S,     $data4,
    '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5'],
  ['KMAC128', 32, $key, $S,     $data200,
    '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230'],
  ['KMAC256', 64, $key, $S,     $data4,
    '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'.
    'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd'],
  ['KMAC256', 64, $key, '',     $data200,
    '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'.
    '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69'],
);

for my $v (@kmac_vectors) {
  my ($variant, $L, $K, $C, $X, $exp) = @$v;
  is(kmac_hex($variant, $L, $K, $C, $X), $exp, "$variant L=$L S='".(length $C ? $C : "")."' X=".length($X)."B");
}

# --- KMACXOF samples -------------------------------------------------------
# KMACXOF samples #1..#3 (KMACXOF128) verified against the libtomcrypt
# reference implementation; the XOF property is also tested below.
is(kmac_hex('KMACXOF128', 32, $key, '', $data4),
   'cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35',
   'KMACXOF128 sample #1');
is(kmac_hex('KMACXOF128', 32, $key, $S, $data4),
   '31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c',
   'KMACXOF128 sample #2');
is(kmac_hex('KMACXOF128', 32, $key, $S, $data200),
   '47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f',
   'KMACXOF128 sample #3');

# Variant names are case-sensitive and use no underscore — bad spellings rejected.
ok(!eval { kmac_hex('KMAC128XOF',  32, $key, '', $data4); 1 }, 'KMAC128XOF spelling rejected');
ok(!eval { kmac_hex('kmac128',     32, $key, '', $data4); 1 }, 'lowercase spelling rejected');
ok(!eval { kmac_hex('KMAC128_XOF', 32, $key, '', $data4); 1 }, 'underscored spelling rejected');

# --- XOF property: longer requests are extensions of shorter ones ----------
{
  my $long  = kmac('KMACXOF128', 100, $key, '', $data4);
  my $short = kmac('KMACXOF128',  32, $key, '', $data4);
  is(substr($long, 0, 32), $short, 'KMACXOF128: prefix property holds');

  my $long2  = kmac('KMACXOF256', 200, $key, $S, $data4);
  my $short2 = kmac('KMACXOF256',  64, $key, $S, $data4);
  is(substr($long2, 0, 64), $short2, 'KMACXOF256: prefix property holds');
}

# --- Fixed mode commits to L: different L => unrelated outputs -------------
{
  my $a = kmac('KMAC128', 32, $key, '', $data4);
  my $b = kmac('KMAC128', 64, $key, '', $data4);
  isnt(substr($b, 0, 32), $a, 'KMAC128: L is committed (truncating L=64 != L=32)');
}

# --- OO interface ----------------------------------------------------------
{
  my $d = Crypt::Mac::KMAC->new('KMAC128', $key);
  $d->add($data4);
  is($d->hexmac(32),
     'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e',
     'OO: KMAC128 hexmac matches sample #1');
}
{
  my $d = Crypt::Mac::KMAC->new('KMAC128', $key, $S);
  $d->add(substr($data200, 0, 100));
  $d->add(substr($data200, 100));
  is($d->hexmac(32),
     '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230',
     'OO: split add() yields the same MAC as a single add()');
}
{
  my $d = Crypt::Mac::KMAC->new('KMAC256', $key, $S);
  $d->add($data4);
  my $bin = $d->mac(64);
  is(length($bin), 64, 'OO: mac() returns requested length');
  is(unpack("H*", $bin),
     '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'.
     'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
     'OO: mac() bytes match KMAC256 sample #4');
}
{
  my $d = Crypt::Mac::KMAC->new('KMAC128', $key);
  $d->add($data4);
  my $hex = $d->hexmac(32);
  ok(eval { $d->hexmac(32); 1 } ? 0 : 1, 'finalized object refuses second hexmac()');
  ok(eval { $d->add('x');     1 } ? 0 : 1, 'finalized object refuses add()');
}
{
  # clone before finalize
  my $d = Crypt::Mac::KMAC->new('KMAC128', $key);
  $d->add(substr($data4, 0, 2));
  my $c = $d->clone;
  $d->add(substr($data4, 2));
  $c->add(substr($data4, 2));
  is($d->hexmac(32), $c->hexmac(32), 'clone() produces an independent finalizable copy');
}

# --- Encoding helpers ------------------------------------------------------
{
  my $K = "\x00" x 16;
  my $bin = kmac('KMAC128', 32, $K, '', 'abc');
  is(length($bin), 32, 'kmac() raw length matches L');
  is(kmac_hex ('KMAC128', 32, $K, '', 'abc'),       unpack('H*', $bin), 'kmac_hex == hex of raw');
  my $b64  = kmac_b64 ('KMAC128', 32, $K, '', 'abc');
  my $b64u = kmac_b64u('KMAC128', 32, $K, '', 'abc');
  unlike($b64,  qr/[\-_]/,                      'kmac_b64 has no url-safe chars');
  unlike($b64u, qr/[+\/=]/,                     'kmac_b64u has no padding/non-url chars');
  is(length($b64),  44,                         'kmac_b64 length for 32-byte MAC');
  ok(length($b64u) >= 42 && length($b64u) <= 44, 'kmac_b64u length sane');
}

# --- Empty key + empty cust + empty data are accepted ----------------------
{
  my $h = eval { kmac_hex('KMAC128', 16, '', '', '') };
  diag("$@") if $@;
  ok(defined $h && length($h) == 32, 'KMAC128 with empty key/cust/data succeeds');
}

# --- Argument validation ---------------------------------------------------
{
  ok(!eval { kmac_hex('KMAC999', 16, $key, '', 'x'); 1 }, 'unknown variant rejected');
  like($@, qr/unknown KMAC variant/, '...with the right error');
  ok(!eval { kmac_hex('KMAC128',  0, $key, '', 'x'); 1 }, 'zero output length rejected');
  like($@, qr/invalid output length/, '...with the right error');
  ok(!eval { Crypt::Mac::KMAC->new('NOPE', $key); 1 }, 'OO: unknown variant rejected');
}
