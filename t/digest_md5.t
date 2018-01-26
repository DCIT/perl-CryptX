### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::MD5 qw( md5 md5_hex md5_b64 md5_b64u md5_file md5_file_hex md5_file_b64 md5_file_b64u );

is( Crypt::Digest::hashsize('MD5'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('MD5'), 16, 'hashsize/2');
is( Crypt::Digest::MD5::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::MD5->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('MD5')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::MD5->new->hashsize, 16, 'hashsize/6');

is( md5("A","A","A"), pack("H*","e1faffb3e614e6c2fba74296962386b7"), 'md5 (raw/tripple_A)');
is( md5_hex("A","A","A"), "e1faffb3e614e6c2fba74296962386b7", 'md5 (hex/tripple_A)');
is( md5_b64("A","A","A"), "4fr/s+YU5sL7p0KWliOGtw==", 'md5 (base64/tripple_A)');
is( md5_b64u("A","A","A"), "4fr_s-YU5sL7p0KWliOGtw", 'md5 (base64url/tripple_A)');
is( digest_data('MD5', "A","A","A"), pack("H*","e1faffb3e614e6c2fba74296962386b7"), 'md5 (digest_data_raw/tripple_A)');
is( digest_data_hex('MD5', "A","A","A"), "e1faffb3e614e6c2fba74296962386b7", 'md5 (digest_data_hex/tripple_A)');
is( digest_data_b64('MD5', "A","A","A"), "4fr/s+YU5sL7p0KWliOGtw==", 'md5 (digest_data_b64/tripple_A)');
is( digest_data_b64u('MD5', "A","A","A"), "4fr_s-YU5sL7p0KWliOGtw", 'md5 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::MD5->new->add("A","A","A")->hexdigest, "e1faffb3e614e6c2fba74296962386b7", 'md5 (OO/tripple_A)');
is( Crypt::Digest::MD5->new->add("A")->add("A")->add("A")->hexdigest, "e1faffb3e614e6c2fba74296962386b7", 'md5 (OO3/tripple_A)');


is( md5(""), pack("H*","d41d8cd98f00b204e9800998ecf8427e"), 'md5 (raw/1)');
is( md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e", 'md5 (hex/1)');
is( md5_b64(""), "1B2M2Y8AsgTpgAmY7PhCfg==", 'md5 (base64/1)');
is( digest_data('MD5', ""), pack("H*","d41d8cd98f00b204e9800998ecf8427e"), 'md5 (digest_data_raw/1)');
is( digest_data_hex('MD5', ""), "d41d8cd98f00b204e9800998ecf8427e", 'md5 (digest_data_hex/1)');
is( digest_data_b64('MD5', ""), "1B2M2Y8AsgTpgAmY7PhCfg==", 'md5 (digest_data_b64/1)');
is( digest_data_b64u('MD5', ""), "1B2M2Y8AsgTpgAmY7PhCfg", 'md5 (digest_data_b64u/1)');
is( Crypt::Digest::MD5->new->add("")->hexdigest, "d41d8cd98f00b204e9800998ecf8427e", 'md5 (OO/1)');

is( md5("123"), pack("H*","202cb962ac59075b964b07152d234b70"), 'md5 (raw/2)');
is( md5_hex("123"), "202cb962ac59075b964b07152d234b70", 'md5 (hex/2)');
is( md5_b64("123"), "ICy5YqxZB1uWSwcVLSNLcA==", 'md5 (base64/2)');
is( digest_data('MD5', "123"), pack("H*","202cb962ac59075b964b07152d234b70"), 'md5 (digest_data_raw/2)');
is( digest_data_hex('MD5', "123"), "202cb962ac59075b964b07152d234b70", 'md5 (digest_data_hex/2)');
is( digest_data_b64('MD5', "123"), "ICy5YqxZB1uWSwcVLSNLcA==", 'md5 (digest_data_b64/2)');
is( digest_data_b64u('MD5', "123"), "ICy5YqxZB1uWSwcVLSNLcA", 'md5 (digest_data_b64u/2)');
is( Crypt::Digest::MD5->new->add("123")->hexdigest, "202cb962ac59075b964b07152d234b70", 'md5 (OO/2)');

is( md5("test\0test\0test\n"), pack("H*","38b00a95b30ee620eacd9aa05259a436"), 'md5 (raw/3)');
is( md5_hex("test\0test\0test\n"), "38b00a95b30ee620eacd9aa05259a436", 'md5 (hex/3)');
is( md5_b64("test\0test\0test\n"), "OLAKlbMO5iDqzZqgUlmkNg==", 'md5 (base64/3)');
is( digest_data('MD5', "test\0test\0test\n"), pack("H*","38b00a95b30ee620eacd9aa05259a436"), 'md5 (digest_data_raw/3)');
is( digest_data_hex('MD5', "test\0test\0test\n"), "38b00a95b30ee620eacd9aa05259a436", 'md5 (digest_data_hex/3)');
is( digest_data_b64('MD5', "test\0test\0test\n"), "OLAKlbMO5iDqzZqgUlmkNg==", 'md5 (digest_data_b64/3)');
is( digest_data_b64u('MD5', "test\0test\0test\n"), "OLAKlbMO5iDqzZqgUlmkNg", 'md5 (digest_data_b64u/3)');
is( Crypt::Digest::MD5->new->add("test\0test\0test\n")->hexdigest, "38b00a95b30ee620eacd9aa05259a436", 'md5 (OO/3)');


is( md5_file('t/data/binary-test.file'), pack("H*","ca56fa983a4b49e81c68167fe4a2e835"), 'md5 (raw/file/1)');
is( md5_file_hex('t/data/binary-test.file'), "ca56fa983a4b49e81c68167fe4a2e835", 'md5 (hex/file/1)');
is( md5_file_b64('t/data/binary-test.file'), "ylb6mDpLSegcaBZ/5KLoNQ==", 'md5 (base64/file/1)');
is( digest_file('MD5', 't/data/binary-test.file'), pack("H*","ca56fa983a4b49e81c68167fe4a2e835"), 'md5 (digest_file_raw/file/1)');
is( digest_file_hex('MD5', 't/data/binary-test.file'), "ca56fa983a4b49e81c68167fe4a2e835", 'md5 (digest_file_hex/file/1)');
is( digest_file_b64('MD5', 't/data/binary-test.file'), "ylb6mDpLSegcaBZ/5KLoNQ==", 'md5 (digest_file_b64/file/1)');
is( digest_file_b64u('MD5', 't/data/binary-test.file'), "ylb6mDpLSegcaBZ_5KLoNQ", 'md5 (digest_file_b64u/file/1)');
is( Crypt::Digest::MD5->new->addfile('t/data/binary-test.file')->hexdigest, "ca56fa983a4b49e81c68167fe4a2e835", 'md5 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::MD5->new->addfile($fh)->hexdigest, "ca56fa983a4b49e81c68167fe4a2e835", 'md5 (OO/filehandle/1)');
  close($fh);
}

is( md5_file('t/data/text-CR.file'), pack("H*","9e2beba516f19ee3d2b3cfcbfbf05fc2"), 'md5 (raw/file/2)');
is( md5_file_hex('t/data/text-CR.file'), "9e2beba516f19ee3d2b3cfcbfbf05fc2", 'md5 (hex/file/2)');
is( md5_file_b64('t/data/text-CR.file'), "nivrpRbxnuPSs8/L+/Bfwg==", 'md5 (base64/file/2)');
is( digest_file('MD5', 't/data/text-CR.file'), pack("H*","9e2beba516f19ee3d2b3cfcbfbf05fc2"), 'md5 (digest_file_raw/file/2)');
is( digest_file_hex('MD5', 't/data/text-CR.file'), "9e2beba516f19ee3d2b3cfcbfbf05fc2", 'md5 (digest_file_hex/file/2)');
is( digest_file_b64('MD5', 't/data/text-CR.file'), "nivrpRbxnuPSs8/L+/Bfwg==", 'md5 (digest_file_b64/file/2)');
is( digest_file_b64u('MD5', 't/data/text-CR.file'), "nivrpRbxnuPSs8_L-_Bfwg", 'md5 (digest_file_b64u/file/2)');
is( Crypt::Digest::MD5->new->addfile('t/data/text-CR.file')->hexdigest, "9e2beba516f19ee3d2b3cfcbfbf05fc2", 'md5 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::MD5->new->addfile($fh)->hexdigest, "9e2beba516f19ee3d2b3cfcbfbf05fc2", 'md5 (OO/filehandle/2)');
  close($fh);
}

is( md5_file('t/data/text-CRLF.file'), pack("H*","d939ac2b17f6091bb062bb6f9190fc76"), 'md5 (raw/file/3)');
is( md5_file_hex('t/data/text-CRLF.file'), "d939ac2b17f6091bb062bb6f9190fc76", 'md5 (hex/file/3)');
is( md5_file_b64('t/data/text-CRLF.file'), "2TmsKxf2CRuwYrtvkZD8dg==", 'md5 (base64/file/3)');
is( digest_file('MD5', 't/data/text-CRLF.file'), pack("H*","d939ac2b17f6091bb062bb6f9190fc76"), 'md5 (digest_file_raw/file/3)');
is( digest_file_hex('MD5', 't/data/text-CRLF.file'), "d939ac2b17f6091bb062bb6f9190fc76", 'md5 (digest_file_hex/file/3)');
is( digest_file_b64('MD5', 't/data/text-CRLF.file'), "2TmsKxf2CRuwYrtvkZD8dg==", 'md5 (digest_file_b64/file/3)');
is( digest_file_b64u('MD5', 't/data/text-CRLF.file'), "2TmsKxf2CRuwYrtvkZD8dg", 'md5 (digest_file_b64u/file/3)');
is( Crypt::Digest::MD5->new->addfile('t/data/text-CRLF.file')->hexdigest, "d939ac2b17f6091bb062bb6f9190fc76", 'md5 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::MD5->new->addfile($fh)->hexdigest, "d939ac2b17f6091bb062bb6f9190fc76", 'md5 (OO/filehandle/3)');
  close($fh);
}

is( md5_file('t/data/text-LF.file'), pack("H*","2c5b1996d510a6cc97fad5fbaa0b313f"), 'md5 (raw/file/4)');
is( md5_file_hex('t/data/text-LF.file'), "2c5b1996d510a6cc97fad5fbaa0b313f", 'md5 (hex/file/4)');
is( md5_file_b64('t/data/text-LF.file'), "LFsZltUQpsyX+tX7qgsxPw==", 'md5 (base64/file/4)');
is( digest_file('MD5', 't/data/text-LF.file'), pack("H*","2c5b1996d510a6cc97fad5fbaa0b313f"), 'md5 (digest_file_raw/file/4)');
is( digest_file_hex('MD5', 't/data/text-LF.file'), "2c5b1996d510a6cc97fad5fbaa0b313f", 'md5 (digest_file_hex/file/4)');
is( digest_file_b64('MD5', 't/data/text-LF.file'), "LFsZltUQpsyX+tX7qgsxPw==", 'md5 (digest_file_b64/file/4)');
is( digest_file_b64u('MD5', 't/data/text-LF.file'), "LFsZltUQpsyX-tX7qgsxPw", 'md5 (digest_file_b64u/file/4)');
is( Crypt::Digest::MD5->new->addfile('t/data/text-LF.file')->hexdigest, "2c5b1996d510a6cc97fad5fbaa0b313f", 'md5 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::MD5->new->addfile($fh)->hexdigest, "2c5b1996d510a6cc97fad5fbaa0b313f", 'md5 (OO/filehandle/4)');
  close($fh);
}
