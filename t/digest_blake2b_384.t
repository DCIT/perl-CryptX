### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2b_384 qw( blake2b_384 blake2b_384_hex blake2b_384_b64 blake2b_384_b64u blake2b_384_file blake2b_384_file_hex blake2b_384_file_b64 blake2b_384_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2b_384'), 48, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2b_384'), 48, 'hashsize/2');
is( Crypt::Digest::BLAKE2b_384::hashsize, 48, 'hashsize/3');
is( Crypt::Digest::BLAKE2b_384->hashsize, 48, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2b_384')->hashsize, 48, 'hashsize/5');
is( Crypt::Digest::BLAKE2b_384->new->hashsize, 48, 'hashsize/6');

is( blake2b_384("A","A","A"), pack("H*","9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685"), 'blake2b_384 (raw/tripple_A)');
is( blake2b_384_hex("A","A","A"), "9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685", 'blake2b_384 (hex/tripple_A)');
is( blake2b_384_b64("A","A","A"), "mqB9nK8Xv/SXR/yUiOtrq83NV1YW+FqRdY7lDm5JpIhL9vtGtCTgrmaQcczYyxaF", 'blake2b_384 (base64/tripple_A)');
is( blake2b_384_b64u("A","A","A"), "mqB9nK8Xv_SXR_yUiOtrq83NV1YW-FqRdY7lDm5JpIhL9vtGtCTgrmaQcczYyxaF", 'blake2b_384 (base64url/tripple_A)');
is( digest_data('BLAKE2b_384', "A","A","A"), pack("H*","9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685"), 'blake2b_384 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2b_384', "A","A","A"), "9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685", 'blake2b_384 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2b_384', "A","A","A"), "mqB9nK8Xv/SXR/yUiOtrq83NV1YW+FqRdY7lDm5JpIhL9vtGtCTgrmaQcczYyxaF", 'blake2b_384 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2b_384', "A","A","A"), "mqB9nK8Xv_SXR_yUiOtrq83NV1YW-FqRdY7lDm5JpIhL9vtGtCTgrmaQcczYyxaF", 'blake2b_384 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2b_384->new->add("A","A","A")->hexdigest, "9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685", 'blake2b_384 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2b_384->new->add("A")->add("A")->add("A")->hexdigest, "9aa07d9caf17bff49747fc9488eb6babcdcd575616f85a91758ee50e6e49a4884bf6fb46b424e0ae669071ccd8cb1685", 'blake2b_384 (OO3/tripple_A)');


is( blake2b_384(""), pack("H*","b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"), 'blake2b_384 (raw/1)');
is( blake2b_384_hex(""), "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100", 'blake2b_384 (hex/1)');
is( blake2b_384_b64(""), "sygRQjN39S14Yihu4acu5UBSQ4D9oXJKbyXXl4xv0yRKbK8EmIEmc8XgXvWDglEA", 'blake2b_384 (base64/1)');
is( digest_data('BLAKE2b_384', ""), pack("H*","b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"), 'blake2b_384 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2b_384', ""), "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100", 'blake2b_384 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2b_384', ""), "sygRQjN39S14Yihu4acu5UBSQ4D9oXJKbyXXl4xv0yRKbK8EmIEmc8XgXvWDglEA", 'blake2b_384 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2b_384', ""), "sygRQjN39S14Yihu4acu5UBSQ4D9oXJKbyXXl4xv0yRKbK8EmIEmc8XgXvWDglEA", 'blake2b_384 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2b_384->new->add("")->hexdigest, "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100", 'blake2b_384 (OO/1)');

is( blake2b_384("123"), pack("H*","50af7f5deca52771b287704c66e79479adc0ec91a380279ab05627eb4c050f13494beb28dfc739a2a1a7194f9d1c30b0"), 'blake2b_384 (raw/2)');
is( blake2b_384_hex("123"), "50af7f5deca52771b287704c66e79479adc0ec91a380279ab05627eb4c050f13494beb28dfc739a2a1a7194f9d1c30b0", 'blake2b_384 (hex/2)');
is( blake2b_384_b64("123"), "UK9/XeylJ3Gyh3BMZueUea3A7JGjgCeasFYn60wFDxNJS+so38c5oqGnGU+dHDCw", 'blake2b_384 (base64/2)');
is( digest_data('BLAKE2b_384', "123"), pack("H*","50af7f5deca52771b287704c66e79479adc0ec91a380279ab05627eb4c050f13494beb28dfc739a2a1a7194f9d1c30b0"), 'blake2b_384 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2b_384', "123"), "50af7f5deca52771b287704c66e79479adc0ec91a380279ab05627eb4c050f13494beb28dfc739a2a1a7194f9d1c30b0", 'blake2b_384 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2b_384', "123"), "UK9/XeylJ3Gyh3BMZueUea3A7JGjgCeasFYn60wFDxNJS+so38c5oqGnGU+dHDCw", 'blake2b_384 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2b_384', "123"), "UK9_XeylJ3Gyh3BMZueUea3A7JGjgCeasFYn60wFDxNJS-so38c5oqGnGU-dHDCw", 'blake2b_384 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2b_384->new->add("123")->hexdigest, "50af7f5deca52771b287704c66e79479adc0ec91a380279ab05627eb4c050f13494beb28dfc739a2a1a7194f9d1c30b0", 'blake2b_384 (OO/2)');

is( blake2b_384("test\0test\0test\n"), pack("H*","42788332987449000fd8deeec86645ed2c2986fc2338f3defdb4dd48681ad5eb6a92823516a74093288673922f19c669"), 'blake2b_384 (raw/3)');
is( blake2b_384_hex("test\0test\0test\n"), "42788332987449000fd8deeec86645ed2c2986fc2338f3defdb4dd48681ad5eb6a92823516a74093288673922f19c669", 'blake2b_384 (hex/3)');
is( blake2b_384_b64("test\0test\0test\n"), "QniDMph0SQAP2N7uyGZF7SwphvwjOPPe/bTdSGga1etqkoI1FqdAkyiGc5IvGcZp", 'blake2b_384 (base64/3)');
is( digest_data('BLAKE2b_384', "test\0test\0test\n"), pack("H*","42788332987449000fd8deeec86645ed2c2986fc2338f3defdb4dd48681ad5eb6a92823516a74093288673922f19c669"), 'blake2b_384 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2b_384', "test\0test\0test\n"), "42788332987449000fd8deeec86645ed2c2986fc2338f3defdb4dd48681ad5eb6a92823516a74093288673922f19c669", 'blake2b_384 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2b_384', "test\0test\0test\n"), "QniDMph0SQAP2N7uyGZF7SwphvwjOPPe/bTdSGga1etqkoI1FqdAkyiGc5IvGcZp", 'blake2b_384 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2b_384', "test\0test\0test\n"), "QniDMph0SQAP2N7uyGZF7SwphvwjOPPe_bTdSGga1etqkoI1FqdAkyiGc5IvGcZp", 'blake2b_384 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2b_384->new->add("test\0test\0test\n")->hexdigest, "42788332987449000fd8deeec86645ed2c2986fc2338f3defdb4dd48681ad5eb6a92823516a74093288673922f19c669", 'blake2b_384 (OO/3)');


is( blake2b_384_file('t/data/binary-test.file'), pack("H*","8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239"), 'blake2b_384 (raw/file/1)');
is( blake2b_384_file_hex('t/data/binary-test.file'), "8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239", 'blake2b_384 (hex/file/1)');
is( blake2b_384_file_b64('t/data/binary-test.file'), "hRRVahYvvBl9CUy4Tr86f2UTe8yI5IBGMawyEoZh9wRXQHMAUAzVJ+E7MN+aFnI5", 'blake2b_384 (base64/file/1)');
is( digest_file('BLAKE2b_384', 't/data/binary-test.file'), pack("H*","8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239"), 'blake2b_384 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2b_384', 't/data/binary-test.file'), "8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239", 'blake2b_384 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2b_384', 't/data/binary-test.file'), "hRRVahYvvBl9CUy4Tr86f2UTe8yI5IBGMawyEoZh9wRXQHMAUAzVJ+E7MN+aFnI5", 'blake2b_384 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2b_384', 't/data/binary-test.file'), "hRRVahYvvBl9CUy4Tr86f2UTe8yI5IBGMawyEoZh9wRXQHMAUAzVJ-E7MN-aFnI5", 'blake2b_384 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2b_384->new->addfile('t/data/binary-test.file')->hexdigest, "8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239", 'blake2b_384 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_384->new->addfile($fh)->hexdigest, "8514556a162fbc197d094cb84ebf3a7f65137bcc88e4804631ac32128661f70457407300500cd527e13b30df9a167239", 'blake2b_384 (OO/filehandle/1)');
  close($fh);
}

is( blake2b_384_file('t/data/text-CR.file'), pack("H*","dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386"), 'blake2b_384 (raw/file/2)');
is( blake2b_384_file_hex('t/data/text-CR.file'), "dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386", 'blake2b_384 (hex/file/2)');
is( blake2b_384_file_b64('t/data/text-CR.file'), "2tZoTPZccrHUSvwuEhVCoBlUYxsDnn/fZjt5drlTmzeaxYADzaiM76z8h7kkJBOG", 'blake2b_384 (base64/file/2)');
is( digest_file('BLAKE2b_384', 't/data/text-CR.file'), pack("H*","dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386"), 'blake2b_384 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2b_384', 't/data/text-CR.file'), "dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386", 'blake2b_384 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2b_384', 't/data/text-CR.file'), "2tZoTPZccrHUSvwuEhVCoBlUYxsDnn/fZjt5drlTmzeaxYADzaiM76z8h7kkJBOG", 'blake2b_384 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2b_384', 't/data/text-CR.file'), "2tZoTPZccrHUSvwuEhVCoBlUYxsDnn_fZjt5drlTmzeaxYADzaiM76z8h7kkJBOG", 'blake2b_384 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2b_384->new->addfile('t/data/text-CR.file')->hexdigest, "dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386", 'blake2b_384 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_384->new->addfile($fh)->hexdigest, "dad6684cf65c72b1d44afc2e121542a01954631b039e7fdf663b7976b9539b379ac58003cda88cefacfc87b924241386", 'blake2b_384 (OO/filehandle/2)');
  close($fh);
}

is( blake2b_384_file('t/data/text-CRLF.file'), pack("H*","c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17"), 'blake2b_384 (raw/file/3)');
is( blake2b_384_file_hex('t/data/text-CRLF.file'), "c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17", 'blake2b_384 (hex/file/3)');
is( blake2b_384_file_b64('t/data/text-CRLF.file'), "wno+ZcxT0v9RQdfRWRhpPLog2N6LkdB1qcWgZqyBsATgM9BctLbIJX2093APMhoX", 'blake2b_384 (base64/file/3)');
is( digest_file('BLAKE2b_384', 't/data/text-CRLF.file'), pack("H*","c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17"), 'blake2b_384 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2b_384', 't/data/text-CRLF.file'), "c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17", 'blake2b_384 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2b_384', 't/data/text-CRLF.file'), "wno+ZcxT0v9RQdfRWRhpPLog2N6LkdB1qcWgZqyBsATgM9BctLbIJX2093APMhoX", 'blake2b_384 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2b_384', 't/data/text-CRLF.file'), "wno-ZcxT0v9RQdfRWRhpPLog2N6LkdB1qcWgZqyBsATgM9BctLbIJX2093APMhoX", 'blake2b_384 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2b_384->new->addfile('t/data/text-CRLF.file')->hexdigest, "c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17", 'blake2b_384 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_384->new->addfile($fh)->hexdigest, "c27a3e65cc53d2ff5141d7d15918693cba20d8de8b91d075a9c5a066ac81b004e033d05cb4b6c8257db4f7700f321a17", 'blake2b_384 (OO/filehandle/3)');
  close($fh);
}

is( blake2b_384_file('t/data/text-LF.file'), pack("H*","6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe"), 'blake2b_384 (raw/file/4)');
is( blake2b_384_file_hex('t/data/text-LF.file'), "6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe", 'blake2b_384 (hex/file/4)');
is( blake2b_384_file_b64('t/data/text-LF.file'), "YSbPFmm71Yb1Sfdr213PFquTwzk+TLcSUkVQxDwQBioiyBeWd/RjeCvL4wLbavq+", 'blake2b_384 (base64/file/4)');
is( digest_file('BLAKE2b_384', 't/data/text-LF.file'), pack("H*","6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe"), 'blake2b_384 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2b_384', 't/data/text-LF.file'), "6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe", 'blake2b_384 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2b_384', 't/data/text-LF.file'), "YSbPFmm71Yb1Sfdr213PFquTwzk+TLcSUkVQxDwQBioiyBeWd/RjeCvL4wLbavq+", 'blake2b_384 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2b_384', 't/data/text-LF.file'), "YSbPFmm71Yb1Sfdr213PFquTwzk-TLcSUkVQxDwQBioiyBeWd_RjeCvL4wLbavq-", 'blake2b_384 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2b_384->new->addfile('t/data/text-LF.file')->hexdigest, "6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe", 'blake2b_384 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_384->new->addfile($fh)->hexdigest, "6126cf1669bbd586f549f76bdb5dcf16ab93c3393e4cb712524550c43c10062a22c8179677f463782bcbe302db6afabe", 'blake2b_384 (OO/filehandle/4)');
  close($fh);
}
