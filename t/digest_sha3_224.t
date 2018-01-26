### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA3_224 qw( sha3_224 sha3_224_hex sha3_224_b64 sha3_224_b64u sha3_224_file sha3_224_file_hex sha3_224_file_b64 sha3_224_file_b64u );

is( Crypt::Digest::hashsize('SHA3_224'), 28, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA3_224'), 28, 'hashsize/2');
is( Crypt::Digest::SHA3_224::hashsize, 28, 'hashsize/3');
is( Crypt::Digest::SHA3_224->hashsize, 28, 'hashsize/4');
is( Crypt::Digest->new('SHA3_224')->hashsize, 28, 'hashsize/5');
is( Crypt::Digest::SHA3_224->new->hashsize, 28, 'hashsize/6');

is( sha3_224("A","A","A"), pack("H*","c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b"), 'sha3_224 (raw/tripple_A)');
is( sha3_224_hex("A","A","A"), "c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b", 'sha3_224 (hex/tripple_A)');
is( sha3_224_b64("A","A","A"), "wJ1a99mgIcSEBBIY88N4f9QnS2T/0BLtyg/lWw==", 'sha3_224 (base64/tripple_A)');
is( sha3_224_b64u("A","A","A"), "wJ1a99mgIcSEBBIY88N4f9QnS2T_0BLtyg_lWw", 'sha3_224 (base64url/tripple_A)');
is( digest_data('SHA3_224', "A","A","A"), pack("H*","c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b"), 'sha3_224 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA3_224', "A","A","A"), "c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b", 'sha3_224 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA3_224', "A","A","A"), "wJ1a99mgIcSEBBIY88N4f9QnS2T/0BLtyg/lWw==", 'sha3_224 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA3_224', "A","A","A"), "wJ1a99mgIcSEBBIY88N4f9QnS2T_0BLtyg_lWw", 'sha3_224 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA3_224->new->add("A","A","A")->hexdigest, "c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b", 'sha3_224 (OO/tripple_A)');
is( Crypt::Digest::SHA3_224->new->add("A")->add("A")->add("A")->hexdigest, "c09d5af7d9a021c484041218f3c3787fd4274b64ffd012edca0fe55b", 'sha3_224 (OO3/tripple_A)');


is( sha3_224(""), pack("H*","6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"), 'sha3_224 (raw/1)');
is( sha3_224_hex(""), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", 'sha3_224 (hex/1)');
is( sha3_224_b64(""), "a04DQjZn27c7bhVFTw6xq9RZf5obB44/W1prxw==", 'sha3_224 (base64/1)');
is( digest_data('SHA3_224', ""), pack("H*","6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"), 'sha3_224 (digest_data_raw/1)');
is( digest_data_hex('SHA3_224', ""), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", 'sha3_224 (digest_data_hex/1)');
is( digest_data_b64('SHA3_224', ""), "a04DQjZn27c7bhVFTw6xq9RZf5obB44/W1prxw==", 'sha3_224 (digest_data_b64/1)');
is( digest_data_b64u('SHA3_224', ""), "a04DQjZn27c7bhVFTw6xq9RZf5obB44_W1prxw", 'sha3_224 (digest_data_b64u/1)');
is( Crypt::Digest::SHA3_224->new->add("")->hexdigest, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", 'sha3_224 (OO/1)');

is( sha3_224("123"), pack("H*","602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"), 'sha3_224 (raw/2)');
is( sha3_224_hex("123"), "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097", 'sha3_224 (hex/2)');
is( sha3_224_b64("123"), "YCvcIEFA2wFr7lN0iV5VaM5CL6vhfgZAYdgAlw==", 'sha3_224 (base64/2)');
is( digest_data('SHA3_224', "123"), pack("H*","602bdc204140db016bee5374895e5568ce422fabe17e064061d80097"), 'sha3_224 (digest_data_raw/2)');
is( digest_data_hex('SHA3_224', "123"), "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097", 'sha3_224 (digest_data_hex/2)');
is( digest_data_b64('SHA3_224', "123"), "YCvcIEFA2wFr7lN0iV5VaM5CL6vhfgZAYdgAlw==", 'sha3_224 (digest_data_b64/2)');
is( digest_data_b64u('SHA3_224', "123"), "YCvcIEFA2wFr7lN0iV5VaM5CL6vhfgZAYdgAlw", 'sha3_224 (digest_data_b64u/2)');
is( Crypt::Digest::SHA3_224->new->add("123")->hexdigest, "602bdc204140db016bee5374895e5568ce422fabe17e064061d80097", 'sha3_224 (OO/2)');

is( sha3_224("test\0test\0test\n"), pack("H*","ae786c2326ad35c1d50654029e54c298755324aaa152899efd443654"), 'sha3_224 (raw/3)');
is( sha3_224_hex("test\0test\0test\n"), "ae786c2326ad35c1d50654029e54c298755324aaa152899efd443654", 'sha3_224 (hex/3)');
is( sha3_224_b64("test\0test\0test\n"), "rnhsIyatNcHVBlQCnlTCmHVTJKqhUome/UQ2VA==", 'sha3_224 (base64/3)');
is( digest_data('SHA3_224', "test\0test\0test\n"), pack("H*","ae786c2326ad35c1d50654029e54c298755324aaa152899efd443654"), 'sha3_224 (digest_data_raw/3)');
is( digest_data_hex('SHA3_224', "test\0test\0test\n"), "ae786c2326ad35c1d50654029e54c298755324aaa152899efd443654", 'sha3_224 (digest_data_hex/3)');
is( digest_data_b64('SHA3_224', "test\0test\0test\n"), "rnhsIyatNcHVBlQCnlTCmHVTJKqhUome/UQ2VA==", 'sha3_224 (digest_data_b64/3)');
is( digest_data_b64u('SHA3_224', "test\0test\0test\n"), "rnhsIyatNcHVBlQCnlTCmHVTJKqhUome_UQ2VA", 'sha3_224 (digest_data_b64u/3)');
is( Crypt::Digest::SHA3_224->new->add("test\0test\0test\n")->hexdigest, "ae786c2326ad35c1d50654029e54c298755324aaa152899efd443654", 'sha3_224 (OO/3)');


is( sha3_224_file('t/data/binary-test.file'), pack("H*","823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85"), 'sha3_224 (raw/file/1)');
is( sha3_224_file_hex('t/data/binary-test.file'), "823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85", 'sha3_224 (hex/file/1)');
is( sha3_224_file_b64('t/data/binary-test.file'), "gj+6IcDMu8EtaDy5dwfaOp2Kc/AZOX0dYQUuhQ==", 'sha3_224 (base64/file/1)');
is( digest_file('SHA3_224', 't/data/binary-test.file'), pack("H*","823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85"), 'sha3_224 (digest_file_raw/file/1)');
is( digest_file_hex('SHA3_224', 't/data/binary-test.file'), "823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85", 'sha3_224 (digest_file_hex/file/1)');
is( digest_file_b64('SHA3_224', 't/data/binary-test.file'), "gj+6IcDMu8EtaDy5dwfaOp2Kc/AZOX0dYQUuhQ==", 'sha3_224 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA3_224', 't/data/binary-test.file'), "gj-6IcDMu8EtaDy5dwfaOp2Kc_AZOX0dYQUuhQ", 'sha3_224 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA3_224->new->addfile('t/data/binary-test.file')->hexdigest, "823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85", 'sha3_224 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_224->new->addfile($fh)->hexdigest, "823fba21c0ccbbc12d683cb97707da3a9d8a73f019397d1d61052e85", 'sha3_224 (OO/filehandle/1)');
  close($fh);
}

is( sha3_224_file('t/data/text-CR.file'), pack("H*","2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354"), 'sha3_224 (raw/file/2)');
is( sha3_224_file_hex('t/data/text-CR.file'), "2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354", 'sha3_224 (hex/file/2)');
is( sha3_224_file_b64('t/data/text-CR.file'), "KnZ3V4ohMP8SNMYtRZgi/mJW4zHcL5Kx3g/zVA==", 'sha3_224 (base64/file/2)');
is( digest_file('SHA3_224', 't/data/text-CR.file'), pack("H*","2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354"), 'sha3_224 (digest_file_raw/file/2)');
is( digest_file_hex('SHA3_224', 't/data/text-CR.file'), "2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354", 'sha3_224 (digest_file_hex/file/2)');
is( digest_file_b64('SHA3_224', 't/data/text-CR.file'), "KnZ3V4ohMP8SNMYtRZgi/mJW4zHcL5Kx3g/zVA==", 'sha3_224 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA3_224', 't/data/text-CR.file'), "KnZ3V4ohMP8SNMYtRZgi_mJW4zHcL5Kx3g_zVA", 'sha3_224 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA3_224->new->addfile('t/data/text-CR.file')->hexdigest, "2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354", 'sha3_224 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_224->new->addfile($fh)->hexdigest, "2a7677578a2130ff1234c62d459822fe6256e331dc2f92b1de0ff354", 'sha3_224 (OO/filehandle/2)');
  close($fh);
}

is( sha3_224_file('t/data/text-CRLF.file'), pack("H*","4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c"), 'sha3_224 (raw/file/3)');
is( sha3_224_file_hex('t/data/text-CRLF.file'), "4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c", 'sha3_224 (hex/file/3)');
is( sha3_224_file_b64('t/data/text-CRLF.file'), "QnboNbNn7taOviENKJU4KNKZXIR/HTXeXeV6XA==", 'sha3_224 (base64/file/3)');
is( digest_file('SHA3_224', 't/data/text-CRLF.file'), pack("H*","4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c"), 'sha3_224 (digest_file_raw/file/3)');
is( digest_file_hex('SHA3_224', 't/data/text-CRLF.file'), "4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c", 'sha3_224 (digest_file_hex/file/3)');
is( digest_file_b64('SHA3_224', 't/data/text-CRLF.file'), "QnboNbNn7taOviENKJU4KNKZXIR/HTXeXeV6XA==", 'sha3_224 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA3_224', 't/data/text-CRLF.file'), "QnboNbNn7taOviENKJU4KNKZXIR_HTXeXeV6XA", 'sha3_224 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA3_224->new->addfile('t/data/text-CRLF.file')->hexdigest, "4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c", 'sha3_224 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_224->new->addfile($fh)->hexdigest, "4276e835b367eed68ebe210d28953828d2995c847f1d35de5de57a5c", 'sha3_224 (OO/filehandle/3)');
  close($fh);
}

is( sha3_224_file('t/data/text-LF.file'), pack("H*","a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f"), 'sha3_224 (raw/file/4)');
is( sha3_224_file_hex('t/data/text-LF.file'), "a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f", 'sha3_224 (hex/file/4)');
is( sha3_224_file_b64('t/data/text-LF.file'), "pdhpdLYOf2wCLwp9xkCaq7TJ0hqTZl3+EiCALw==", 'sha3_224 (base64/file/4)');
is( digest_file('SHA3_224', 't/data/text-LF.file'), pack("H*","a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f"), 'sha3_224 (digest_file_raw/file/4)');
is( digest_file_hex('SHA3_224', 't/data/text-LF.file'), "a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f", 'sha3_224 (digest_file_hex/file/4)');
is( digest_file_b64('SHA3_224', 't/data/text-LF.file'), "pdhpdLYOf2wCLwp9xkCaq7TJ0hqTZl3+EiCALw==", 'sha3_224 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA3_224', 't/data/text-LF.file'), "pdhpdLYOf2wCLwp9xkCaq7TJ0hqTZl3-EiCALw", 'sha3_224 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA3_224->new->addfile('t/data/text-LF.file')->hexdigest, "a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f", 'sha3_224 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_224->new->addfile($fh)->hexdigest, "a5d86974b60e7f6c022f0a7dc6409aabb4c9d21a93665dfe1220802f", 'sha3_224 (OO/filehandle/4)');
  close($fh);
}
