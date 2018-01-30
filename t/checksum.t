use strict;
use warnings;

use Test::More tests => 56;

use Crypt::Checksum::Adler32 ':all';
use Crypt::Checksum::CRC32 ':all';

{
  my $a32 = Crypt::Checksum::Adler32->new;
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
  $a32->add("abc", "abc");
  is($a32->hexdigest, "080c024d");
  $a32->reset;
  $a32->add("abcabc");
  is($a32->hexdigest, "080c024d");
  $a32->reset;
  $a32->add("\xFF" x 32);
  is($a32->hexdigest, "0e2e1fe1");
  is($a32->intdigest, 237903841);
  is($a32->digest, pack("H*", "0e2e1fe1"));

  is(adler32_data_hex("aaa"), "02490124");
  is(adler32_data_int("aaa"), 38338852);
  is(adler32_data("aaa"), pack("H*","02490124"));
  is(adler32_data_hex("a","a","a"), "02490124");
  is(adler32_data_int("a","a","a"), 38338852);
  is(adler32_data("a","a","a"), pack("H*","02490124"));

  is(adler32_data_hex("libtomcrypt"), "1be804ba");
  is(adler32_data_hex("This is the test string"), "6363088d");
  is(adler32_data_int("This is the test string"), 1667434637);
  is(adler32_data_hex("This is another test string"), "8b900a3d");
  is(adler32_data_int("This is another test string"), 2341472829);

  is(adler32_file("t/data/binary-test.file"), pack("H*", "f35fb68a"));
  is(adler32_file_int("t/data/binary-test.file"), 4083136138);
  is(adler32_file_hex("t/data/binary-test.file"), "f35fb68a");
  is(Crypt::Checksum::Adler32->new->addfile("t/data/binary-test.file")->hexdigest, "f35fb68a");

  is(adler32_file_hex("t/data/text-CR.file"), "948e2644");
  is(adler32_file_hex("t/data/text-CRLF.file"), "3f0e2702");
  is(adler32_file_hex("t/data/text-LF.file"), "86ba260b");
}

{
  my $a32 = Crypt::Checksum::CRC32->new;
  is($a32->hexdigest, "00000000");
  $a32->add("a");
  is($a32->hexdigest, "e8b7be43");
  $a32->reset;
  is($a32->hexdigest, "00000000");
  $a32->add("abc");
  is($a32->hexdigest, "352441c2");
  $a32->reset;
  $a32->add("abc");
  $a32->add("abc");
  is($a32->hexdigest, "726e994c");
  $a32->reset;
  $a32->add("abc", "abc");
  is($a32->hexdigest, "726e994c");
  $a32->reset;
  $a32->add("abcabc");
  is($a32->hexdigest, "726e994c");
  $a32->reset;
  $a32->add("\xFF" x 32);
  is($a32->hexdigest, "ff6cab0b");
  is($a32->intdigest, 4285311755);
  is($a32->digest, pack("H*", "ff6cab0b"));

  is(crc32_data_hex("aaa"), "f007732d");
  is(crc32_data_int("aaa"), 4027020077);
  is(crc32_data("aaa"), pack("H*","f007732d"));
  is(crc32_data_hex("a","a","a"), "f007732d");
  is(crc32_data_int("a","a","a"), 4027020077);
  is(crc32_data("a","a","a"), pack("H*","f007732d"));

  is(crc32_data_hex("libtomcrypt"), "b37376ef");
  is(crc32_data_hex("This is the test string"), "6d680973");
  is(crc32_data_int("This is the test string"), 1835534707);
  is(crc32_data_hex("This is another test string"), "806e15e9");
  is(crc32_data_int("This is another test string"), 2154698217);

  is(crc32_file("t/data/binary-test.file"), pack("H*", "24111fed"));
  is(crc32_file_int("t/data/binary-test.file"), 605102061);
  is(crc32_file_hex("t/data/binary-test.file"), "24111fed");
  is(Crypt::Checksum::CRC32->new->addfile("t/data/binary-test.file")->hexdigest, "24111fed");

  is(crc32_file_hex("t/data/text-CR.file"), "1ca430c6");
  is(crc32_file_hex("t/data/text-CRLF.file"), "4d434dfb");
  is(crc32_file_hex("t/data/text-LF.file"), "9f9b8258");
}
