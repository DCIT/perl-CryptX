### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2s_128 qw( blake2s_128 blake2s_128_hex blake2s_128_b64 blake2s_128_b64u blake2s_128_file blake2s_128_file_hex blake2s_128_file_b64 blake2s_128_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2s_128'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2s_128'), 16, 'hashsize/2');
is( Crypt::Digest::BLAKE2s_128::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::BLAKE2s_128->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2s_128')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::BLAKE2s_128->new->hashsize, 16, 'hashsize/6');

is( blake2s_128("A","A","A"), pack("H*","a2a5699c7579ee354f4d20fa75f09cb6"), 'blake2s_128 (raw/tripple_A)');
is( blake2s_128_hex("A","A","A"), "a2a5699c7579ee354f4d20fa75f09cb6", 'blake2s_128 (hex/tripple_A)');
is( blake2s_128_b64("A","A","A"), "oqVpnHV57jVPTSD6dfCctg==", 'blake2s_128 (base64/tripple_A)');
is( blake2s_128_b64u("A","A","A"), "oqVpnHV57jVPTSD6dfCctg", 'blake2s_128 (base64url/tripple_A)');
is( digest_data('BLAKE2s_128', "A","A","A"), pack("H*","a2a5699c7579ee354f4d20fa75f09cb6"), 'blake2s_128 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2s_128', "A","A","A"), "a2a5699c7579ee354f4d20fa75f09cb6", 'blake2s_128 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2s_128', "A","A","A"), "oqVpnHV57jVPTSD6dfCctg==", 'blake2s_128 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2s_128', "A","A","A"), "oqVpnHV57jVPTSD6dfCctg", 'blake2s_128 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2s_128->new->add("A","A","A")->hexdigest, "a2a5699c7579ee354f4d20fa75f09cb6", 'blake2s_128 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2s_128->new->add("A")->add("A")->add("A")->hexdigest, "a2a5699c7579ee354f4d20fa75f09cb6", 'blake2s_128 (OO3/tripple_A)');


is( blake2s_128(""), pack("H*","64550d6ffe2c0a01a14aba1eade0200c"), 'blake2s_128 (raw/1)');
is( blake2s_128_hex(""), "64550d6ffe2c0a01a14aba1eade0200c", 'blake2s_128 (hex/1)');
is( blake2s_128_b64(""), "ZFUNb/4sCgGhSroereAgDA==", 'blake2s_128 (base64/1)');
is( digest_data('BLAKE2s_128', ""), pack("H*","64550d6ffe2c0a01a14aba1eade0200c"), 'blake2s_128 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2s_128', ""), "64550d6ffe2c0a01a14aba1eade0200c", 'blake2s_128 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2s_128', ""), "ZFUNb/4sCgGhSroereAgDA==", 'blake2s_128 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2s_128', ""), "ZFUNb_4sCgGhSroereAgDA", 'blake2s_128 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2s_128->new->add("")->hexdigest, "64550d6ffe2c0a01a14aba1eade0200c", 'blake2s_128 (OO/1)');

is( blake2s_128("123"), pack("H*","0a0c4b61b07a608b3904949a4998f8b1"), 'blake2s_128 (raw/2)');
is( blake2s_128_hex("123"), "0a0c4b61b07a608b3904949a4998f8b1", 'blake2s_128 (hex/2)');
is( blake2s_128_b64("123"), "CgxLYbB6YIs5BJSaSZj4sQ==", 'blake2s_128 (base64/2)');
is( digest_data('BLAKE2s_128', "123"), pack("H*","0a0c4b61b07a608b3904949a4998f8b1"), 'blake2s_128 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2s_128', "123"), "0a0c4b61b07a608b3904949a4998f8b1", 'blake2s_128 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2s_128', "123"), "CgxLYbB6YIs5BJSaSZj4sQ==", 'blake2s_128 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2s_128', "123"), "CgxLYbB6YIs5BJSaSZj4sQ", 'blake2s_128 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2s_128->new->add("123")->hexdigest, "0a0c4b61b07a608b3904949a4998f8b1", 'blake2s_128 (OO/2)');

is( blake2s_128("test\0test\0test\n"), pack("H*","32aa3dfdb8adb174cab17a2ac7c205a8"), 'blake2s_128 (raw/3)');
is( blake2s_128_hex("test\0test\0test\n"), "32aa3dfdb8adb174cab17a2ac7c205a8", 'blake2s_128 (hex/3)');
is( blake2s_128_b64("test\0test\0test\n"), "Mqo9/bitsXTKsXoqx8IFqA==", 'blake2s_128 (base64/3)');
is( digest_data('BLAKE2s_128', "test\0test\0test\n"), pack("H*","32aa3dfdb8adb174cab17a2ac7c205a8"), 'blake2s_128 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2s_128', "test\0test\0test\n"), "32aa3dfdb8adb174cab17a2ac7c205a8", 'blake2s_128 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2s_128', "test\0test\0test\n"), "Mqo9/bitsXTKsXoqx8IFqA==", 'blake2s_128 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2s_128', "test\0test\0test\n"), "Mqo9_bitsXTKsXoqx8IFqA", 'blake2s_128 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2s_128->new->add("test\0test\0test\n")->hexdigest, "32aa3dfdb8adb174cab17a2ac7c205a8", 'blake2s_128 (OO/3)');


is( blake2s_128_file('t/data/binary-test.file'), pack("H*","b5a4e21a67fdd4f2d75ab779feb83bfc"), 'blake2s_128 (raw/file/1)');
is( blake2s_128_file_hex('t/data/binary-test.file'), "b5a4e21a67fdd4f2d75ab779feb83bfc", 'blake2s_128 (hex/file/1)');
is( blake2s_128_file_b64('t/data/binary-test.file'), "taTiGmf91PLXWrd5/rg7/A==", 'blake2s_128 (base64/file/1)');
is( digest_file('BLAKE2s_128', 't/data/binary-test.file'), pack("H*","b5a4e21a67fdd4f2d75ab779feb83bfc"), 'blake2s_128 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2s_128', 't/data/binary-test.file'), "b5a4e21a67fdd4f2d75ab779feb83bfc", 'blake2s_128 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2s_128', 't/data/binary-test.file'), "taTiGmf91PLXWrd5/rg7/A==", 'blake2s_128 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2s_128', 't/data/binary-test.file'), "taTiGmf91PLXWrd5_rg7_A", 'blake2s_128 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2s_128->new->addfile('t/data/binary-test.file')->hexdigest, "b5a4e21a67fdd4f2d75ab779feb83bfc", 'blake2s_128 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_128->new->addfile($fh)->hexdigest, "b5a4e21a67fdd4f2d75ab779feb83bfc", 'blake2s_128 (OO/filehandle/1)');
  close($fh);
}

is( blake2s_128_file('t/data/text-CR.file'), pack("H*","b17af4ae04bd7412393fc958bd60fdb6"), 'blake2s_128 (raw/file/2)');
is( blake2s_128_file_hex('t/data/text-CR.file'), "b17af4ae04bd7412393fc958bd60fdb6", 'blake2s_128 (hex/file/2)');
is( blake2s_128_file_b64('t/data/text-CR.file'), "sXr0rgS9dBI5P8lYvWD9tg==", 'blake2s_128 (base64/file/2)');
is( digest_file('BLAKE2s_128', 't/data/text-CR.file'), pack("H*","b17af4ae04bd7412393fc958bd60fdb6"), 'blake2s_128 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2s_128', 't/data/text-CR.file'), "b17af4ae04bd7412393fc958bd60fdb6", 'blake2s_128 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2s_128', 't/data/text-CR.file'), "sXr0rgS9dBI5P8lYvWD9tg==", 'blake2s_128 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2s_128', 't/data/text-CR.file'), "sXr0rgS9dBI5P8lYvWD9tg", 'blake2s_128 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2s_128->new->addfile('t/data/text-CR.file')->hexdigest, "b17af4ae04bd7412393fc958bd60fdb6", 'blake2s_128 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_128->new->addfile($fh)->hexdigest, "b17af4ae04bd7412393fc958bd60fdb6", 'blake2s_128 (OO/filehandle/2)');
  close($fh);
}

is( blake2s_128_file('t/data/text-CRLF.file'), pack("H*","5e7c030d5e05b0c8c34105634417770c"), 'blake2s_128 (raw/file/3)');
is( blake2s_128_file_hex('t/data/text-CRLF.file'), "5e7c030d5e05b0c8c34105634417770c", 'blake2s_128 (hex/file/3)');
is( blake2s_128_file_b64('t/data/text-CRLF.file'), "XnwDDV4FsMjDQQVjRBd3DA==", 'blake2s_128 (base64/file/3)');
is( digest_file('BLAKE2s_128', 't/data/text-CRLF.file'), pack("H*","5e7c030d5e05b0c8c34105634417770c"), 'blake2s_128 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2s_128', 't/data/text-CRLF.file'), "5e7c030d5e05b0c8c34105634417770c", 'blake2s_128 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2s_128', 't/data/text-CRLF.file'), "XnwDDV4FsMjDQQVjRBd3DA==", 'blake2s_128 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2s_128', 't/data/text-CRLF.file'), "XnwDDV4FsMjDQQVjRBd3DA", 'blake2s_128 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2s_128->new->addfile('t/data/text-CRLF.file')->hexdigest, "5e7c030d5e05b0c8c34105634417770c", 'blake2s_128 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_128->new->addfile($fh)->hexdigest, "5e7c030d5e05b0c8c34105634417770c", 'blake2s_128 (OO/filehandle/3)');
  close($fh);
}

is( blake2s_128_file('t/data/text-LF.file'), pack("H*","72a2b42b4c947d3d3c479b3b0e596aae"), 'blake2s_128 (raw/file/4)');
is( blake2s_128_file_hex('t/data/text-LF.file'), "72a2b42b4c947d3d3c479b3b0e596aae", 'blake2s_128 (hex/file/4)');
is( blake2s_128_file_b64('t/data/text-LF.file'), "cqK0K0yUfT08R5s7Dllqrg==", 'blake2s_128 (base64/file/4)');
is( digest_file('BLAKE2s_128', 't/data/text-LF.file'), pack("H*","72a2b42b4c947d3d3c479b3b0e596aae"), 'blake2s_128 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2s_128', 't/data/text-LF.file'), "72a2b42b4c947d3d3c479b3b0e596aae", 'blake2s_128 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2s_128', 't/data/text-LF.file'), "cqK0K0yUfT08R5s7Dllqrg==", 'blake2s_128 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2s_128', 't/data/text-LF.file'), "cqK0K0yUfT08R5s7Dllqrg", 'blake2s_128 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2s_128->new->addfile('t/data/text-LF.file')->hexdigest, "72a2b42b4c947d3d3c479b3b0e596aae", 'blake2s_128 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_128->new->addfile($fh)->hexdigest, "72a2b42b4c947d3d3c479b3b0e596aae", 'blake2s_128 (OO/filehandle/4)');
  close($fh);
}
