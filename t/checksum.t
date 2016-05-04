use strict;
use warnings;

use Test::More tests => 24;

use Crypt::Checksum ':all';
use Crypt::Checksum::Adler32;
use Crypt::Checksum::CRC32;

my $a32 = Crypt::Checksum::Adler32->new;
is($a32->hexdigest, "00000001");
is($a32->hexdigest, "00000001");
$a32->add("a");
is($a32->hexdigest, "00620062");
$a32->reset;
is($a32->hexdigest, "00000001");
$a32->add("abc");
is($a32->hexdigest, "024d0127");
$a32->reset;
$a32->add("abc");
$a32->add("abc");
is($a32->hexdigest, "080c024d");
$a32->reset;
$a32->add("abcabc");
is($a32->hexdigest, "080c024d");
$a32->reset;
$a32->add("\xFF" x 32);
is($a32->hexdigest, "0e2e1fe1");
is(adler32_data_hex("a"), "00620062");
is(adler32_data("a"), pack("H*","00620062"));

is(crc32_data_hex("a"), "e8b7be43");
is(crc32_data_hex("libtomcrypt"), "b37376ef");
is(crc32_data_hex("This is the test string"), "6d680973");
is(crc32_data_int("This is the test string"), 1835534707);
is(crc32_data_hex("This is another test string"), "806e15e9");
is(crc32_data_int("This is another test string"), 2154698217);

is(crc32_file_hex("t/data/binary-test.file"), "24111fed");
is(crc32_file_hex("t/data/text-CR.file"), "1ca430c6");
is(crc32_file_hex("t/data/text-CRLF.file"), "4d434dfb");
is(crc32_file_hex("t/data/text-LF.file"), "9f9b8258");

is(adler32_file_hex("t/data/binary-test.file"), "f35fb68a");
is(adler32_file_hex("t/data/text-CR.file"), "948e2644");
is(adler32_file_hex("t/data/text-CRLF.file"), "3f0e2702");
is(adler32_file_hex("t/data/text-LF.file"), "86ba260b");
