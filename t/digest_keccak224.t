### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::Keccak224 qw( keccak224 keccak224_hex keccak224_b64 keccak224_b64u keccak224_file keccak224_file_hex keccak224_file_b64 keccak224_file_b64u );

is( Crypt::Digest::hashsize('Keccak224'), 28, 'hashsize/1');
is( Crypt::Digest->hashsize('Keccak224'), 28, 'hashsize/2');
is( Crypt::Digest::Keccak224::hashsize, 28, 'hashsize/3');
is( Crypt::Digest::Keccak224->hashsize, 28, 'hashsize/4');
is( Crypt::Digest->new('Keccak224')->hashsize, 28, 'hashsize/5');
is( Crypt::Digest::Keccak224->new->hashsize, 28, 'hashsize/6');

is( keccak224("A","A","A"), pack("H*","92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252"), 'keccak224 (raw/tripple_A)');
is( keccak224_hex("A","A","A"), "92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252", 'keccak224 (hex/tripple_A)');
is( keccak224_b64("A","A","A"), "krnSolIi0qA2xTvU3SRrQHPRAOCuIKxyQPWyUg==", 'keccak224 (base64/tripple_A)');
is( keccak224_b64u("A","A","A"), "krnSolIi0qA2xTvU3SRrQHPRAOCuIKxyQPWyUg", 'keccak224 (base64url/tripple_A)');
is( digest_data('Keccak224', "A","A","A"), pack("H*","92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252"), 'keccak224 (digest_data_raw/tripple_A)');
is( digest_data_hex('Keccak224', "A","A","A"), "92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252", 'keccak224 (digest_data_hex/tripple_A)');
is( digest_data_b64('Keccak224', "A","A","A"), "krnSolIi0qA2xTvU3SRrQHPRAOCuIKxyQPWyUg==", 'keccak224 (digest_data_b64/tripple_A)');
is( digest_data_b64u('Keccak224', "A","A","A"), "krnSolIi0qA2xTvU3SRrQHPRAOCuIKxyQPWyUg", 'keccak224 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::Keccak224->new->add("A","A","A")->hexdigest, "92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252", 'keccak224 (OO/tripple_A)');
is( Crypt::Digest::Keccak224->new->add("A")->add("A")->add("A")->hexdigest, "92b9d2a25222d2a036c53bd4dd246b4073d100e0ae20ac7240f5b252", 'keccak224 (OO3/tripple_A)');


is( keccak224(""), pack("H*","f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"), 'keccak224 (raw/1)');
is( keccak224_hex(""), "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", 'keccak224 (hex/1)');
is( keccak224_b64(""), "9xg3UCuo4Qg3vdjTZa24VZGJVgL8VStItzkKvQ==", 'keccak224 (base64/1)');
is( digest_data('Keccak224', ""), pack("H*","f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"), 'keccak224 (digest_data_raw/1)');
is( digest_data_hex('Keccak224', ""), "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", 'keccak224 (digest_data_hex/1)');
is( digest_data_b64('Keccak224', ""), "9xg3UCuo4Qg3vdjTZa24VZGJVgL8VStItzkKvQ==", 'keccak224 (digest_data_b64/1)');
is( digest_data_b64u('Keccak224', ""), "9xg3UCuo4Qg3vdjTZa24VZGJVgL8VStItzkKvQ", 'keccak224 (digest_data_b64u/1)');
is( Crypt::Digest::Keccak224->new->add("")->hexdigest, "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd", 'keccak224 (OO/1)');

is( keccak224("123"), pack("H*","5c52615361ce4c5469f9d8c90113c7a543a4bf43490782d291cb32d8"), 'keccak224 (raw/2)');
is( keccak224_hex("123"), "5c52615361ce4c5469f9d8c90113c7a543a4bf43490782d291cb32d8", 'keccak224 (hex/2)');
is( keccak224_b64("123"), "XFJhU2HOTFRp+djJARPHpUOkv0NJB4LSkcsy2A==", 'keccak224 (base64/2)');
is( digest_data('Keccak224', "123"), pack("H*","5c52615361ce4c5469f9d8c90113c7a543a4bf43490782d291cb32d8"), 'keccak224 (digest_data_raw/2)');
is( digest_data_hex('Keccak224', "123"), "5c52615361ce4c5469f9d8c90113c7a543a4bf43490782d291cb32d8", 'keccak224 (digest_data_hex/2)');
is( digest_data_b64('Keccak224', "123"), "XFJhU2HOTFRp+djJARPHpUOkv0NJB4LSkcsy2A==", 'keccak224 (digest_data_b64/2)');
is( digest_data_b64u('Keccak224', "123"), "XFJhU2HOTFRp-djJARPHpUOkv0NJB4LSkcsy2A", 'keccak224 (digest_data_b64u/2)');
is( Crypt::Digest::Keccak224->new->add("123")->hexdigest, "5c52615361ce4c5469f9d8c90113c7a543a4bf43490782d291cb32d8", 'keccak224 (OO/2)');

is( keccak224("test\0test\0test\n"), pack("H*","7cbb8e9a6026e7c8324ab2f1cba55a1aff03b7b0424b8915b0439179"), 'keccak224 (raw/3)');
is( keccak224_hex("test\0test\0test\n"), "7cbb8e9a6026e7c8324ab2f1cba55a1aff03b7b0424b8915b0439179", 'keccak224 (hex/3)');
is( keccak224_b64("test\0test\0test\n"), "fLuOmmAm58gySrLxy6VaGv8Dt7BCS4kVsEOReQ==", 'keccak224 (base64/3)');
is( digest_data('Keccak224', "test\0test\0test\n"), pack("H*","7cbb8e9a6026e7c8324ab2f1cba55a1aff03b7b0424b8915b0439179"), 'keccak224 (digest_data_raw/3)');
is( digest_data_hex('Keccak224', "test\0test\0test\n"), "7cbb8e9a6026e7c8324ab2f1cba55a1aff03b7b0424b8915b0439179", 'keccak224 (digest_data_hex/3)');
is( digest_data_b64('Keccak224', "test\0test\0test\n"), "fLuOmmAm58gySrLxy6VaGv8Dt7BCS4kVsEOReQ==", 'keccak224 (digest_data_b64/3)');
is( digest_data_b64u('Keccak224', "test\0test\0test\n"), "fLuOmmAm58gySrLxy6VaGv8Dt7BCS4kVsEOReQ", 'keccak224 (digest_data_b64u/3)');
is( Crypt::Digest::Keccak224->new->add("test\0test\0test\n")->hexdigest, "7cbb8e9a6026e7c8324ab2f1cba55a1aff03b7b0424b8915b0439179", 'keccak224 (OO/3)');


is( keccak224_file('t/data/binary-test.file'), pack("H*","8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e"), 'keccak224 (raw/file/1)');
is( keccak224_file_hex('t/data/binary-test.file'), "8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e", 'keccak224 (hex/file/1)');
is( keccak224_file_b64('t/data/binary-test.file'), "jxZR/6uQNhkxShs9fImu+8H49UEomxiJMgsajg==", 'keccak224 (base64/file/1)');
is( digest_file('Keccak224', 't/data/binary-test.file'), pack("H*","8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e"), 'keccak224 (digest_file_raw/file/1)');
is( digest_file_hex('Keccak224', 't/data/binary-test.file'), "8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e", 'keccak224 (digest_file_hex/file/1)');
is( digest_file_b64('Keccak224', 't/data/binary-test.file'), "jxZR/6uQNhkxShs9fImu+8H49UEomxiJMgsajg==", 'keccak224 (digest_file_b64/file/1)');
is( digest_file_b64u('Keccak224', 't/data/binary-test.file'), "jxZR_6uQNhkxShs9fImu-8H49UEomxiJMgsajg", 'keccak224 (digest_file_b64u/file/1)');
is( Crypt::Digest::Keccak224->new->addfile('t/data/binary-test.file')->hexdigest, "8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e", 'keccak224 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Keccak224->new->addfile($fh)->hexdigest, "8f1651ffab903619314a1b3d7c89aefbc1f8f541289b1889320b1a8e", 'keccak224 (OO/filehandle/1)');
  close($fh);
}

is( keccak224_file('t/data/text-CR.file'), pack("H*","28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8"), 'keccak224 (raw/file/2)');
is( keccak224_file_hex('t/data/text-CR.file'), "28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8", 'keccak224 (hex/file/2)');
is( keccak224_file_b64('t/data/text-CR.file'), "KP+KFzguH6EcN81uJUO/JX+RSq43YO93BzmHyA==", 'keccak224 (base64/file/2)');
is( digest_file('Keccak224', 't/data/text-CR.file'), pack("H*","28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8"), 'keccak224 (digest_file_raw/file/2)');
is( digest_file_hex('Keccak224', 't/data/text-CR.file'), "28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8", 'keccak224 (digest_file_hex/file/2)');
is( digest_file_b64('Keccak224', 't/data/text-CR.file'), "KP+KFzguH6EcN81uJUO/JX+RSq43YO93BzmHyA==", 'keccak224 (digest_file_b64/file/2)');
is( digest_file_b64u('Keccak224', 't/data/text-CR.file'), "KP-KFzguH6EcN81uJUO_JX-RSq43YO93BzmHyA", 'keccak224 (digest_file_b64u/file/2)');
is( Crypt::Digest::Keccak224->new->addfile('t/data/text-CR.file')->hexdigest, "28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8", 'keccak224 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Keccak224->new->addfile($fh)->hexdigest, "28ff8a17382e1fa11c37cd6e2543bf257f914aae3760ef77073987c8", 'keccak224 (OO/filehandle/2)');
  close($fh);
}

is( keccak224_file('t/data/text-CRLF.file'), pack("H*","26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa"), 'keccak224 (raw/file/3)');
is( keccak224_file_hex('t/data/text-CRLF.file'), "26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa", 'keccak224 (hex/file/3)');
is( keccak224_file_b64('t/data/text-CRLF.file'), "JmWQCHWUI83kTEmEdIr2th19TqXH6Bvlj7cvqg==", 'keccak224 (base64/file/3)');
is( digest_file('Keccak224', 't/data/text-CRLF.file'), pack("H*","26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa"), 'keccak224 (digest_file_raw/file/3)');
is( digest_file_hex('Keccak224', 't/data/text-CRLF.file'), "26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa", 'keccak224 (digest_file_hex/file/3)');
is( digest_file_b64('Keccak224', 't/data/text-CRLF.file'), "JmWQCHWUI83kTEmEdIr2th19TqXH6Bvlj7cvqg==", 'keccak224 (digest_file_b64/file/3)');
is( digest_file_b64u('Keccak224', 't/data/text-CRLF.file'), "JmWQCHWUI83kTEmEdIr2th19TqXH6Bvlj7cvqg", 'keccak224 (digest_file_b64u/file/3)');
is( Crypt::Digest::Keccak224->new->addfile('t/data/text-CRLF.file')->hexdigest, "26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa", 'keccak224 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak224->new->addfile($fh)->hexdigest, "26659008759423cde44c4984748af6b61d7d4ea5c7e81be58fb72faa", 'keccak224 (OO/filehandle/3)');
  close($fh);
}

is( keccak224_file('t/data/text-LF.file'), pack("H*","2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b"), 'keccak224 (raw/file/4)');
is( keccak224_file_hex('t/data/text-LF.file'), "2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b", 'keccak224 (hex/file/4)');
is( keccak224_file_b64('t/data/text-LF.file'), "ICFxfRb5n0k5YNCDmjyysBvoB4wotCXX8chmKw==", 'keccak224 (base64/file/4)');
is( digest_file('Keccak224', 't/data/text-LF.file'), pack("H*","2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b"), 'keccak224 (digest_file_raw/file/4)');
is( digest_file_hex('Keccak224', 't/data/text-LF.file'), "2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b", 'keccak224 (digest_file_hex/file/4)');
is( digest_file_b64('Keccak224', 't/data/text-LF.file'), "ICFxfRb5n0k5YNCDmjyysBvoB4wotCXX8chmKw==", 'keccak224 (digest_file_b64/file/4)');
is( digest_file_b64u('Keccak224', 't/data/text-LF.file'), "ICFxfRb5n0k5YNCDmjyysBvoB4wotCXX8chmKw", 'keccak224 (digest_file_b64u/file/4)');
is( Crypt::Digest::Keccak224->new->addfile('t/data/text-LF.file')->hexdigest, "2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b", 'keccak224 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak224->new->addfile($fh)->hexdigest, "2021717d16f99f493960d0839a3cb2b01be8078c28b425d7f1c8662b", 'keccak224 (OO/filehandle/4)');
  close($fh);
}
