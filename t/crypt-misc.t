use strict;
use warnings;
use Test::More tests => 761;

use Crypt::Misc qw( encode_b64   decode_b64
                    encode_b64u  decode_b64u
                    encode_b58b  decode_b58b
                    encode_b58f  decode_b58f
                    encode_b58r  decode_b58r
                    encode_b58t  decode_b58t
                    encode_b58s  decode_b58s
                    encode_b32r  decode_b32r
                    encode_b32b  decode_b32b
                    encode_b32z  decode_b32z
                    encode_b32c  decode_b32c
                    pem_to_der   der_to_pem
                    read_rawfile write_rawfile
                    slow_eq is_v4uuid random_v4uuid
                    is_uuid random_v7uuid
                    increment_octets_be increment_octets_le
                  );

{
  package CryptMiscTest::Stringy;
  use overload '""' => sub { 'abc' }, fallback => 1;
}

is(encode_b64(pack("H*","702fad4215a04a657f011d3ea5711879c696788c91d2")), "cC+tQhWgSmV/AR0+pXEYecaWeIyR0g==", "encode_b64");
is(unpack("H*", decode_b64("cC+tQhWgSmV/AR0+pXEYecaWeIyR0g==")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64");
is(unpack("H*", decode_b64("cC+tQhWgSmV/AR0+pXEYecaWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64/relaxed1");
is(unpack("H*", decode_b64("cC+tQh\nWgSmV/A\nR0+pXEYec\naWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64/relaxed2");
is(unpack("H*", decode_b64("cC+tQh\r\nWgSmV/A\r\nR0+pXEYec\r\naWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64/relaxed3");
is(unpack("H*", decode_b64("cC+tQh WgSmV/A R0+pXEYec aWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64/relaxed4");
is(unpack("H*", decode_b64("cC+tQh\tWgSmV/A\tR0+pXEYec\taWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64/relaxed5");

is(encode_b64u(pack("H*","702fad4215a04a657f011d3ea5711879c696788c91d2")), "cC-tQhWgSmV_AR0-pXEYecaWeIyR0g", "encode_b64u");
is(unpack("H*", decode_b64u("cC-tQhWgSmV_AR0-pXEYecaWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u");
is(unpack("H*", decode_b64u("cC-tQhWgSmV_AR0-pXEYecaWeIyR0g==")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u/padded");
is(unpack("H*", decode_b64u("cC-tQh\nWgSmV_A\nR0-pXEYec\naWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u/relaxed1");
is(unpack("H*", decode_b64u("cC-tQh\r\nWgSmV_A\r\nR0-pXEYec\r\naWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u/relaxed2");
is(unpack("H*", decode_b64u("cC-tQh WgSmV_A R0-pXEYec aWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u/relaxed3");
is(unpack("H*", decode_b64u("cC-tQh\tWgSmV_A\tR0-pXEYec\taWeIyR0g")), "702fad4215a04a657f011d3ea5711879c696788c91d2", "decode_b64u/relaxed4");

is(decode_b64("Zg=="    ), "f",      "ltc 1a");
is(decode_b64("Zg="     ), "f",      "ltc 1b");
is(decode_b64("Zg"      ), "f",      "ltc 1c");
is(decode_b64("Zm8="    ), "fo",     "ltc 2a");
is(decode_b64("Zm8"     ), "fo",     "ltc 2b");
is(decode_b64("Zm9v"    ), "foo",    "ltc 3");
is(decode_b64("Zm9vYg=="), "foob",   "ltc 4a");
is(decode_b64("Zm9vYg=" ), "foob",   "ltc 4b");
is(decode_b64("Zm9vYg"  ), "foob",   "ltc 4c");
is(decode_b64("Zm9vYmE="), "fooba",  "ltc 5a");
is(decode_b64("Zm9vYmE" ), "fooba",  "ltc 5b");
is(decode_b64("Zm9vYmFy"), "foobar", "ltc 6");

is(decode_b64u("Zg=="    ), "f",      "ltcu 1a");
is(decode_b64u("Zg="     ), "f",      "ltcu 1b");
is(decode_b64u("Zg"      ), "f",      "ltcu 1c");
is(decode_b64u("Zm8="    ), "fo",     "ltcu 2a");
is(decode_b64u("Zm8"     ), "fo",     "ltcu 2b");
is(decode_b64u("Zm9v"    ), "foo",    "ltcu 3");
is(decode_b64u("Zm9vYg=="), "foob",   "ltcu 4a");
is(decode_b64u("Zm9vYg=" ), "foob",   "ltcu 4b");
is(decode_b64u("Zm9vYg"  ), "foob",   "ltcu 4c");
is(decode_b64u("Zm9vYmE="), "fooba",  "ltcu 5a");
is(decode_b64u("Zm9vYmE" ), "fooba",  "ltcu 5b");
is(decode_b64u("Zm9vYmFy"), "foobar", "ltcu 6");

is(decode_b64("="),   undef, "decode_b64 rejects padding-only input 1");
is(decode_b64("=="),  undef, "decode_b64 rejects padding-only input 2");
is(decode_b64u("="),  undef, "decode_b64u rejects padding-only input");
is(decode_b64(" \n\t"),  undef, "decode_b64 rejects whitespace-only input");
is(decode_b64u(" \n\t"), undef, "decode_b64u rejects whitespace-only input");
is(decode_b32r("="),  undef, "decode_b32r rejects padding-only input");
is(decode_b32b("=="), undef, "decode_b32b rejects padding-only input");
is(decode_b32c("==="), undef, "decode_b32c rejects padding-only input");
is(decode_b32r(" \n\t"), undef, "decode_b32r rejects whitespace-only input");

is(encode_b64(undef),   undef, "encode_b64 undef stays undef");
is(decode_b64(undef),   undef, "decode_b64 undef stays undef");
is(encode_b32r(undef),  undef, "encode_b32r undef stays undef");
is(decode_b32r(undef),  undef, "decode_b32r undef stays undef");
is(encode_b58b(undef),  undef, "encode_b58b undef stays undef");
is(decode_b58b(undef),  undef, "decode_b58b undef stays undef");
is(encode_b58b(""),     "",    "encode_b58b empty string stays empty");
is(decode_b58b(""),     "",    "decode_b58b empty string stays empty");
is(decode_b58b(" \n\t"), undef, "decode_b58b rejects whitespace-only input");

write_rawfile("tmp.$$.file", "a\nb\r\nc\rd\te");
ok(slow_eq(read_rawfile("tmp.$$.file"), "a\nb\r\nc\rd\te"), "slow_eq + read_rawfile + write_rawfile");
unlink "tmp.$$.file";
ok(slow_eq("abc", "abc"), "slow_eq equal strings");
ok(!slow_eq("abc", "abd"), "slow_eq rejects same-length mismatch");
ok(!slow_eq("abc", "ab"), "slow_eq rejects shorter mismatch");
ok(!slow_eq("ab", "abc"), "slow_eq rejects longer mismatch");
ok(slow_eq("", ""), "slow_eq accepts two empty strings");
ok(!defined(slow_eq(undef, "")), "slow_eq returns undef on undef input");
ok( slow_eq("a\x00b", "a\x00b"), "slow_eq: binary with embedded NUL");
ok(!slow_eq("a\x00b", "a\x00c"), "slow_eq: binary NUL differ");

{
  my $obj = bless {}, 'CryptMiscTest::Stringy';
  is(encode_b64($obj),           encode_b64("abc"),         "encode_b64 accepts overloaded string");
  is(decode_b64($obj),           decode_b64("abc"),         "decode_b64 accepts overloaded string");
  is(encode_b32r($obj),          encode_b32r("abc"),        "encode_b32r accepts overloaded string");
  is(increment_octets_be($obj),  increment_octets_be("abc"), "increment_octets_be accepts overloaded string");
}

{ # increment_octets_be
  is(unpack("H*", increment_octets_be("\x00")),         "01",       "inc_be: 0x00 -> 0x01");
  is(unpack("H*", increment_octets_be("\x00\xfe")),     "00ff",     "inc_be: no carry");
  is(unpack("H*", increment_octets_be("\x00\xff")),     "0100",     "inc_be: carry");
  is(unpack("H*", increment_octets_be("\x00\xff\xff")), "010000",   "inc_be: multi-byte carry");
  eval { increment_octets_be("\xff") };
  like($@, qr/overflow/, "inc_be: single-byte overflow");
  eval { increment_octets_be("\xff\xff\xff") };
  like($@, qr/overflow/, "inc_be: multi-byte overflow");
}

{ # increment_octets_le
  is(unpack("H*", increment_octets_le("\x00")),         "01",       "inc_le: 0x00 -> 0x01");
  is(unpack("H*", increment_octets_le("\xfe\x00")),     "ff00",     "inc_le: no carry");
  is(unpack("H*", increment_octets_le("\xff\x00")),     "0001",     "inc_le: carry");
  is(unpack("H*", increment_octets_le("\xff\xff\x00")), "000001",   "inc_le: multi-byte carry");
  eval { increment_octets_le("\xff") };
  like($@, qr/overflow/, "inc_le: single-byte overflow");
  eval { increment_octets_le("\xff\xff\xff") };
  like($@, qr/overflow/, "inc_le: multi-byte overflow");
}

{
  my $pem_zero = der_to_pem("abc", "TEST KEY", "0");
  like($pem_zero, qr/^Proc-Type: 4,ENCRYPTED$/m, "der_to_pem encrypts with password '0'");
  is(pem_to_der($pem_zero, "0"), "abc", "pem_to_der round-trips password '0'");

  my $pem_empty = der_to_pem("abc", "TEST KEY", "");
  like($pem_empty, qr/^Proc-Type: 4,ENCRYPTED$/m, "der_to_pem encrypts with empty password");
  is(pem_to_der($pem_empty, ""), "abc", "pem_to_der round-trips empty password");

  my $enc_pem = read_rawfile("t/data/rsa-aes256.pem");
  my $bad_end = $enc_pem;
  $bad_end =~ s/END RSA PRIVATE KEY/END PUBLIC KEY/;
  is(pem_to_der($bad_end, "secret"), undef, "pem_to_der rejects mismatched END label");

  my $bad_begin = $enc_pem;
  $bad_begin =~ s/BEGIN RSA PRIVATE KEY/BEGIN PUBLIC KEY/;
  is(pem_to_der($bad_begin, "secret"), undef, "pem_to_der rejects mismatched BEGIN label");

  my $wrong = eval { pem_to_der($enc_pem, "wrong") };
  ok(!defined($wrong), "pem_to_der returns no value for wrong password");
  like($@, qr/padding_depad failed|Invalid input packet/, "pem_to_der wrong password croaks");

  eval { der_to_pem("data", "BAD\nHEADER") };
  like($@, qr/invalid header name/, "der_to_pem rejects header with newline");
  eval { der_to_pem("data", "BAD--HEADER") };
  like($@, qr/invalid header name/, "der_to_pem rejects header with dashes");
  eval { der_to_pem("data", undef) };
  like($@, qr/invalid header name/, "der_to_pem rejects undef header");
  eval { der_to_pem("data", "") };
  like($@, qr/invalid header name/, "der_to_pem rejects empty header");

  eval { Crypt::Misc::_name2mode("INVALID-CIPHER") };
  like($@, qr/unsupported cipher/, "_name2mode rejects invalid cipher");

  for my $c (qw(DES-EDE3-CBC DES-CBC AES-128-CBC AES-256-OFB AES-256-CFB CAMELLIA-256-CBC SEED-CBC)) {
    my $pem = der_to_pem("test", "TEST KEY", "pw", $c);
    is(pem_to_der($pem, "pw"), "test", "PEM roundtrip with $c");
  }
}

my $uuid = random_v4uuid;
ok($uuid,            'random_v4uuid');
ok(is_v4uuid($uuid), 'is_v4uuid: accepts v4');
ok(is_uuid($uuid),   'is_uuid: accepts v4');

{ ### random_v7uuid / is_uuid
  my $v7 = random_v7uuid();
  ok($v7,                                        'random_v7uuid: defined');
  is(substr($v7, 14, 1), '7',                    'random_v7uuid: version digit is 7');
  ok(substr($v7, 19, 1) =~ /^[89ab]$/i,         'random_v7uuid: variant digit is 8/9/a/b');
  ok(is_uuid($v7),                               'is_uuid: accepts v7');
  ok(!is_v4uuid($v7),                            'is_v4uuid: rejects v7');

  # two successive UUIDs must have non-decreasing 12-char timestamp prefix
  my ($u1, $u2) = (random_v7uuid(), random_v7uuid());
  my $ts = sub { substr($_[0],0,8).substr($_[0],9,4) };
  ok($ts->($u2) ge $ts->($u1),                   'random_v7uuid: time-ordered');

  # is_uuid accepts any version/variant
  ok( is_uuid('f47ac10b-58cc-4372-a567-0e02b2c3d479'), 'is_uuid: v4 lowercase');
  ok( is_uuid('F47AC10B-58CC-4372-A567-0E02B2C3D479'), 'is_uuid: uppercase');
  ok( is_uuid('017f22e2-79b0-7cc3-98c4-dc0c0c07398f'), 'is_uuid: v7 example');
  ok( is_uuid('f47ac10b-58cc-4372-0567-0e02b2c3d479'), 'is_uuid: relaxed variant 0');
  ok(!is_uuid(''),                                     'is_uuid: rejects empty');
  ok(!is_uuid('not-a-uuid'),                           'is_uuid: rejects garbage');
  ok(!is_uuid('f47ac10b-58cc-4372-a567-0e02b2c3d47'),  'is_uuid: rejects short');
  ok(!is_uuid('f47ac10b-58cc-4372-7567-0e02b2c3d479'), 'is_uuid: rejects invalid variant 7');
  ok(!is_uuid('f47ac10b-58cc-4372-c567-0e02b2c3d479'), 'is_uuid: rejects invalid variant c');

  ok( is_v4uuid('f47ac10b-58cc-4372-0567-0e02b2c3d479'), 'is_v4uuid: relaxed variant 0');
  ok(!is_v4uuid('f47ac10b-58cc-4372-7567-0e02b2c3d479'), 'is_v4uuid: rejects invalid variant 7');
  ok(!is_v4uuid('f47ac10b-58cc-4372-c567-0e02b2c3d479'), 'is_v4uuid: rejects invalid variant c');
}

my @hex = (qw/fb
              9534
              93e5de
              ac143db0
              bd82426d56
              d0cd21a99345
              95df02e1c24160
              390b1835d5845413
              e9a141e7ae08ab7684
              12e8c059cb511d10fabc
              5bfe0e44cd99e982da61dd
              990417ce7f929341e01e88c4
              99cbc040b3e8629c8854615134
              be294ddb946fdfbce7e70abe7c7c
              92031ecbb3aa0a7e34479b1bf7b57c
              a50e6f53a4fd2cf52d443fe815f17b90
              39d41e163cf2f2be61d0b18d13508a158f
              792a745c10c0abb3de5f73bdb32a901456ce
              4897c2083c3952a778c08fe234859cbc06fa6a
              b3a79f01ecc9a11c703de44dbfb7b9bb7f230de9
              eba9fa4f4908f74bd0dda6adea37413dcd29a9b623
              619eb868071f31e2c604de3752a8cc7706d156d7deb3
              055489debeb244419a587e7f59c42ffa49dbfe537b5c10
              16c945707cb0421c8adc7d300564b98192a0d15a796f293a
              c89c8664e43f792bd6348a1ad079ad45dfc02e617597186084
              2496818ec6f81fcf225c8c73dce933f5322faf41a40c6b4df1c6
              4d63b1afb4077a1939d46d2b3e5a82637fbef9e87ff72fb1d8d2e7
              5cba279be0d5cf4bedf92d700fdc6acbe601d454a39e10c666b7017e
              c2f2c48f4c4ae9bfa7203d2667c54d1af2d6031d2c8c3639afd172d06b
              303e72e0f19ce9195594ec1c849183a74caf6381c73a41a809f0e1a8c90e
              36589f8310f0f366327b4565180698e20f41aeee8338e14d98bde4671316c7
              b3291646007104bb06d9f12f806abde0b4ce137fc5a9f895d4a847161f563b0f
              01a4afec2458d3403de9631e7c70b418465c6fdaf48bec167ae39045ed518fdf1f
              9a8205871065078385dec5beeeebff48ff2f85a191438979dc1bf06dfdc09ef4c3d0
              16bccfed44ddd4b8fae8b84d411744d35becb9ff6e893805cab9e93464c301bdb63128
              f80358a25a8ba8d071c4734ef0fd8349bde4f0ebb0e7a3f8bfef8ced5027f041dc77cbee
              6cbdffd01cf7901cca8426406397fac12f5738ac121161a2ae31958ba69706065fb21e9fd2
              00
              0000
              000000
              00000000
              0000000000
              ff
              ffff
              ffffff
              ffffffff
              ffffffffff
              00fa
              00003d
              000079ec
              0000a21acb
              0000538487a3
              00003e7f8143b5
              0000161c1c88c3a9
              0000317cf0558dd0df
              00007292d21fc70db6e1
              000057bfcd39753080702a
              0000e0e553536a659155bf1b
              /);

for my $h (@hex) {
  my $b = pack("H*", $h);
  is(unpack("H*", decode_b64 (encode_b64 ($b))), $h);
  is(unpack("H*", decode_b64u(encode_b64u($b))), $h);
  is(unpack("H*", decode_b58b(encode_b58b($b))), $h);
  is(unpack("H*", decode_b58f(encode_b58f($b))), $h);
  is(unpack("H*", decode_b58r(encode_b58r($b))), $h);
  is(unpack("H*", decode_b58t(encode_b58t($b))), $h);
  is(unpack("H*", decode_b58s(encode_b58s($b))), $h);
  is(unpack("H*", decode_b32r(encode_b32r($b))), $h);
  is(unpack("H*", decode_b32b(encode_b32b($b))), $h);
  is(unpack("H*", decode_b32z(encode_b32z($b))), $h);
  is(unpack("H*", decode_b32c(encode_b32c($b))), $h);
}

is(decode_b58b("111OIl0"), undef, "bug: decode_b58b + invalid input");
