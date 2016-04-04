use strict;
use warnings;
use Test::More tests => 15;

use Crypt::Misc qw(encode_b64 decode_b64 encode_b64u decode_b64u pem_to_der der_to_pem read_rawfile write_rawfile slow_eq);

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

write_rawfile("tmp.$$.file", "a\nb\r\nc\rd\te");
ok(slow_eq(read_rawfile("tmp.$$.file"), "a\nb\r\nc\rd\te"), "slow_eq + read_rawfile + write_rawfile");
unlink "tmp.$$.file";
