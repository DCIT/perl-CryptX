### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA3_384 qw( sha3_384 sha3_384_hex sha3_384_b64 sha3_384_b64u sha3_384_file sha3_384_file_hex sha3_384_file_b64 sha3_384_file_b64u );

is( Crypt::Digest::hashsize('SHA3_384'), 48, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA3_384'), 48, 'hashsize/2');
is( Crypt::Digest::SHA3_384::hashsize, 48, 'hashsize/3');
is( Crypt::Digest::SHA3_384->hashsize, 48, 'hashsize/4');
is( Crypt::Digest->new('SHA3_384')->hashsize, 48, 'hashsize/5');
is( Crypt::Digest::SHA3_384->new->hashsize, 48, 'hashsize/6');

is( sha3_384("A","A","A"), pack("H*","3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4"), 'sha3_384 (raw/tripple_A)');
is( sha3_384_hex("A","A","A"), "3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4", 'sha3_384 (hex/tripple_A)');
is( sha3_384_b64("A","A","A"), "NVXtimNLI1+wemkeGTSz6BIoyFm8HBes3rtLq4LNY/BuF8rtWFUztGFbxuP7LgvE", 'sha3_384 (base64/tripple_A)');
is( sha3_384_b64u("A","A","A"), "NVXtimNLI1-wemkeGTSz6BIoyFm8HBes3rtLq4LNY_BuF8rtWFUztGFbxuP7LgvE", 'sha3_384 (base64url/tripple_A)');
is( digest_data('SHA3_384', "A","A","A"), pack("H*","3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4"), 'sha3_384 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA3_384', "A","A","A"), "3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4", 'sha3_384 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA3_384', "A","A","A"), "NVXtimNLI1+wemkeGTSz6BIoyFm8HBes3rtLq4LNY/BuF8rtWFUztGFbxuP7LgvE", 'sha3_384 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA3_384', "A","A","A"), "NVXtimNLI1-wemkeGTSz6BIoyFm8HBes3rtLq4LNY_BuF8rtWFUztGFbxuP7LgvE", 'sha3_384 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA3_384->new->add("A","A","A")->hexdigest, "3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4", 'sha3_384 (OO/tripple_A)');
is( Crypt::Digest::SHA3_384->new->add("A")->add("A")->add("A")->hexdigest, "3555ed8a634b235fb07a691e1934b3e81228c859bc1c17acdebb4bab82cd63f06e17caed585533b4615bc6e3fb2e0bc4", 'sha3_384 (OO3/tripple_A)');


is( sha3_384(""), pack("H*","0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"), 'sha3_384 (raw/1)');
is( sha3_384_hex(""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", 'sha3_384 (hex/1)');
is( sha3_384_b64(""), "DGOnW4ReT30BEH2FLkwkhcUaUKqqlPxhmV5xu+6YOirDcTgxJkrbR/tr0eBY1fAE", 'sha3_384 (base64/1)');
is( digest_data('SHA3_384', ""), pack("H*","0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"), 'sha3_384 (digest_data_raw/1)');
is( digest_data_hex('SHA3_384', ""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", 'sha3_384 (digest_data_hex/1)');
is( digest_data_b64('SHA3_384', ""), "DGOnW4ReT30BEH2FLkwkhcUaUKqqlPxhmV5xu+6YOirDcTgxJkrbR/tr0eBY1fAE", 'sha3_384 (digest_data_b64/1)');
is( digest_data_b64u('SHA3_384', ""), "DGOnW4ReT30BEH2FLkwkhcUaUKqqlPxhmV5xu-6YOirDcTgxJkrbR_tr0eBY1fAE", 'sha3_384 (digest_data_b64u/1)');
is( Crypt::Digest::SHA3_384->new->add("")->hexdigest, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", 'sha3_384 (OO/1)');

is( sha3_384("123"), pack("H*","9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"), 'sha3_384 (raw/2)');
is( sha3_384_hex("123"), "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007", 'sha3_384 (hex/2)');
is( sha3_384_b64("123"), "m9lC0WeKJdApsRQwb14drkn+ir7qzQPPqw8VaqLjY8mIscEoA9Soybo4/chz5fAH", 'sha3_384 (base64/2)');
is( digest_data('SHA3_384', "123"), pack("H*","9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"), 'sha3_384 (digest_data_raw/2)');
is( digest_data_hex('SHA3_384', "123"), "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007", 'sha3_384 (digest_data_hex/2)');
is( digest_data_b64('SHA3_384', "123"), "m9lC0WeKJdApsRQwb14drkn+ir7qzQPPqw8VaqLjY8mIscEoA9Soybo4/chz5fAH", 'sha3_384 (digest_data_b64/2)');
is( digest_data_b64u('SHA3_384', "123"), "m9lC0WeKJdApsRQwb14drkn-ir7qzQPPqw8VaqLjY8mIscEoA9Soybo4_chz5fAH", 'sha3_384 (digest_data_b64u/2)');
is( Crypt::Digest::SHA3_384->new->add("123")->hexdigest, "9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007", 'sha3_384 (OO/2)');

is( sha3_384("test\0test\0test\n"), pack("H*","69cf4f5bfec6ec9fc866208f6442dd3f140ad87d9b6092ab32624a462a6d3ab219e339b392b18596aec0520f770cd543"), 'sha3_384 (raw/3)');
is( sha3_384_hex("test\0test\0test\n"), "69cf4f5bfec6ec9fc866208f6442dd3f140ad87d9b6092ab32624a462a6d3ab219e339b392b18596aec0520f770cd543", 'sha3_384 (hex/3)');
is( sha3_384_b64("test\0test\0test\n"), "ac9PW/7G7J/IZiCPZELdPxQK2H2bYJKrMmJKRiptOrIZ4zmzkrGFlq7AUg93DNVD", 'sha3_384 (base64/3)');
is( digest_data('SHA3_384', "test\0test\0test\n"), pack("H*","69cf4f5bfec6ec9fc866208f6442dd3f140ad87d9b6092ab32624a462a6d3ab219e339b392b18596aec0520f770cd543"), 'sha3_384 (digest_data_raw/3)');
is( digest_data_hex('SHA3_384', "test\0test\0test\n"), "69cf4f5bfec6ec9fc866208f6442dd3f140ad87d9b6092ab32624a462a6d3ab219e339b392b18596aec0520f770cd543", 'sha3_384 (digest_data_hex/3)');
is( digest_data_b64('SHA3_384', "test\0test\0test\n"), "ac9PW/7G7J/IZiCPZELdPxQK2H2bYJKrMmJKRiptOrIZ4zmzkrGFlq7AUg93DNVD", 'sha3_384 (digest_data_b64/3)');
is( digest_data_b64u('SHA3_384', "test\0test\0test\n"), "ac9PW_7G7J_IZiCPZELdPxQK2H2bYJKrMmJKRiptOrIZ4zmzkrGFlq7AUg93DNVD", 'sha3_384 (digest_data_b64u/3)');
is( Crypt::Digest::SHA3_384->new->add("test\0test\0test\n")->hexdigest, "69cf4f5bfec6ec9fc866208f6442dd3f140ad87d9b6092ab32624a462a6d3ab219e339b392b18596aec0520f770cd543", 'sha3_384 (OO/3)');


is( sha3_384_file('t/data/binary-test.file'), pack("H*","d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd"), 'sha3_384 (raw/file/1)');
is( sha3_384_file_hex('t/data/binary-test.file'), "d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd", 'sha3_384 (hex/file/1)');
is( sha3_384_file_b64('t/data/binary-test.file'), "01B2nB0YR6LORTlCnQbjtxW1ko1INT9/Hu+6b3auYpn7G/NsLCBn3blkUFGlUnm9", 'sha3_384 (base64/file/1)');
is( digest_file('SHA3_384', 't/data/binary-test.file'), pack("H*","d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd"), 'sha3_384 (digest_file_raw/file/1)');
is( digest_file_hex('SHA3_384', 't/data/binary-test.file'), "d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd", 'sha3_384 (digest_file_hex/file/1)');
is( digest_file_b64('SHA3_384', 't/data/binary-test.file'), "01B2nB0YR6LORTlCnQbjtxW1ko1INT9/Hu+6b3auYpn7G/NsLCBn3blkUFGlUnm9", 'sha3_384 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA3_384', 't/data/binary-test.file'), "01B2nB0YR6LORTlCnQbjtxW1ko1INT9_Hu-6b3auYpn7G_NsLCBn3blkUFGlUnm9", 'sha3_384 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA3_384->new->addfile('t/data/binary-test.file')->hexdigest, "d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd", 'sha3_384 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_384->new->addfile($fh)->hexdigest, "d350769c1d1847a2ce4539429d06e3b715b5928d48353f7f1eefba6f76ae6299fb1bf36c2c2067ddb9645051a55279bd", 'sha3_384 (OO/filehandle/1)');
  close($fh);
}

is( sha3_384_file('t/data/text-CR.file'), pack("H*","71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656"), 'sha3_384 (raw/file/2)');
is( sha3_384_file_hex('t/data/text-CR.file'), "71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656", 'sha3_384 (hex/file/2)');
is( sha3_384_file_b64('t/data/text-CR.file'), "cSRXYOBnxfAm16mOEs01U+gGeBw/X3Uew0KvbPjBInnxoss/fDRJweb198nU2LZW", 'sha3_384 (base64/file/2)');
is( digest_file('SHA3_384', 't/data/text-CR.file'), pack("H*","71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656"), 'sha3_384 (digest_file_raw/file/2)');
is( digest_file_hex('SHA3_384', 't/data/text-CR.file'), "71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656", 'sha3_384 (digest_file_hex/file/2)');
is( digest_file_b64('SHA3_384', 't/data/text-CR.file'), "cSRXYOBnxfAm16mOEs01U+gGeBw/X3Uew0KvbPjBInnxoss/fDRJweb198nU2LZW", 'sha3_384 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA3_384', 't/data/text-CR.file'), "cSRXYOBnxfAm16mOEs01U-gGeBw_X3Uew0KvbPjBInnxoss_fDRJweb198nU2LZW", 'sha3_384 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA3_384->new->addfile('t/data/text-CR.file')->hexdigest, "71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656", 'sha3_384 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_384->new->addfile($fh)->hexdigest, "71245760e067c5f026d7a98e12cd3553e806781c3f5f751ec342af6cf8c12279f1a2cb3f7c3449c1e6f5f7c9d4d8b656", 'sha3_384 (OO/filehandle/2)');
  close($fh);
}

is( sha3_384_file('t/data/text-CRLF.file'), pack("H*","f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5"), 'sha3_384 (raw/file/3)');
is( sha3_384_file_hex('t/data/text-CRLF.file'), "f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5", 'sha3_384 (hex/file/3)');
is( sha3_384_file_b64('t/data/text-CRLF.file'), "8yd/De9aUsYjfCkR0g7PqKQ0rczpAMcM4G41HWwP4IgGrhrwz5lHJeCPzACjPTil", 'sha3_384 (base64/file/3)');
is( digest_file('SHA3_384', 't/data/text-CRLF.file'), pack("H*","f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5"), 'sha3_384 (digest_file_raw/file/3)');
is( digest_file_hex('SHA3_384', 't/data/text-CRLF.file'), "f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5", 'sha3_384 (digest_file_hex/file/3)');
is( digest_file_b64('SHA3_384', 't/data/text-CRLF.file'), "8yd/De9aUsYjfCkR0g7PqKQ0rczpAMcM4G41HWwP4IgGrhrwz5lHJeCPzACjPTil", 'sha3_384 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA3_384', 't/data/text-CRLF.file'), "8yd_De9aUsYjfCkR0g7PqKQ0rczpAMcM4G41HWwP4IgGrhrwz5lHJeCPzACjPTil", 'sha3_384 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA3_384->new->addfile('t/data/text-CRLF.file')->hexdigest, "f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5", 'sha3_384 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_384->new->addfile($fh)->hexdigest, "f3277f0def5a52c6237c2911d20ecfa8a434adcce900c70ce06e351d6c0fe08806ae1af0cf994725e08fcc00a33d38a5", 'sha3_384 (OO/filehandle/3)');
  close($fh);
}

is( sha3_384_file('t/data/text-LF.file'), pack("H*","06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9"), 'sha3_384 (raw/file/4)');
is( sha3_384_file_hex('t/data/text-LF.file'), "06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9", 'sha3_384 (hex/file/4)');
is( sha3_384_file_b64('t/data/text-LF.file'), "Bqu1NRkfa7hjy4APuofd1nPx21vUL6p4UcaJJG/W0D0YSQbnlN+d29J97OaMXdbJ", 'sha3_384 (base64/file/4)');
is( digest_file('SHA3_384', 't/data/text-LF.file'), pack("H*","06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9"), 'sha3_384 (digest_file_raw/file/4)');
is( digest_file_hex('SHA3_384', 't/data/text-LF.file'), "06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9", 'sha3_384 (digest_file_hex/file/4)');
is( digest_file_b64('SHA3_384', 't/data/text-LF.file'), "Bqu1NRkfa7hjy4APuofd1nPx21vUL6p4UcaJJG/W0D0YSQbnlN+d29J97OaMXdbJ", 'sha3_384 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA3_384', 't/data/text-LF.file'), "Bqu1NRkfa7hjy4APuofd1nPx21vUL6p4UcaJJG_W0D0YSQbnlN-d29J97OaMXdbJ", 'sha3_384 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA3_384->new->addfile('t/data/text-LF.file')->hexdigest, "06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9", 'sha3_384 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_384->new->addfile($fh)->hexdigest, "06abb535191f6bb863cb800fba87ddd673f1db5bd42faa7851c689246fd6d03d184906e794df9ddbd27dece68c5dd6c9", 'sha3_384 (OO/filehandle/4)');
  close($fh);
}
