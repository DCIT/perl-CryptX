### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::MD4 qw( md4 md4_hex md4_b64 md4_b64u md4_file md4_file_hex md4_file_b64 md4_file_b64u );

is( Crypt::Digest::hashsize('MD4'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('MD4'), 16, 'hashsize/2');
is( Crypt::Digest::MD4::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::MD4->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('MD4')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::MD4->new->hashsize, 16, 'hashsize/6');

is( md4("A","A","A"), pack("H*","17c3b38c112ac61c1f0d46555f379f14"), 'md4 (raw/tripple_A)');
is( md4_hex("A","A","A"), "17c3b38c112ac61c1f0d46555f379f14", 'md4 (hex/tripple_A)');
is( md4_b64("A","A","A"), "F8OzjBEqxhwfDUZVXzefFA==", 'md4 (base64/tripple_A)');
is( md4_b64u("A","A","A"), "F8OzjBEqxhwfDUZVXzefFA", 'md4 (base64url/tripple_A)');
is( digest_data('MD4', "A","A","A"), pack("H*","17c3b38c112ac61c1f0d46555f379f14"), 'md4 (digest_data_raw/tripple_A)');
is( digest_data_hex('MD4', "A","A","A"), "17c3b38c112ac61c1f0d46555f379f14", 'md4 (digest_data_hex/tripple_A)');
is( digest_data_b64('MD4', "A","A","A"), "F8OzjBEqxhwfDUZVXzefFA==", 'md4 (digest_data_b64/tripple_A)');
is( digest_data_b64u('MD4', "A","A","A"), "F8OzjBEqxhwfDUZVXzefFA", 'md4 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::MD4->new->add("A","A","A")->hexdigest, "17c3b38c112ac61c1f0d46555f379f14", 'md4 (OO/tripple_A)');
is( Crypt::Digest::MD4->new->add("A")->add("A")->add("A")->hexdigest, "17c3b38c112ac61c1f0d46555f379f14", 'md4 (OO3/tripple_A)');


is( md4(""), pack("H*","31d6cfe0d16ae931b73c59d7e0c089c0"), 'md4 (raw/1)');
is( md4_hex(""), "31d6cfe0d16ae931b73c59d7e0c089c0", 'md4 (hex/1)');
is( md4_b64(""), "MdbP4NFq6TG3PFnX4MCJwA==", 'md4 (base64/1)');
is( digest_data('MD4', ""), pack("H*","31d6cfe0d16ae931b73c59d7e0c089c0"), 'md4 (digest_data_raw/1)');
is( digest_data_hex('MD4', ""), "31d6cfe0d16ae931b73c59d7e0c089c0", 'md4 (digest_data_hex/1)');
is( digest_data_b64('MD4', ""), "MdbP4NFq6TG3PFnX4MCJwA==", 'md4 (digest_data_b64/1)');
is( digest_data_b64u('MD4', ""), "MdbP4NFq6TG3PFnX4MCJwA", 'md4 (digest_data_b64u/1)');
is( Crypt::Digest::MD4->new->add("")->hexdigest, "31d6cfe0d16ae931b73c59d7e0c089c0", 'md4 (OO/1)');

is( md4("123"), pack("H*","c58cda49f00748a3bc0fcfa511d516cb"), 'md4 (raw/2)');
is( md4_hex("123"), "c58cda49f00748a3bc0fcfa511d516cb", 'md4 (hex/2)');
is( md4_b64("123"), "xYzaSfAHSKO8D8+lEdUWyw==", 'md4 (base64/2)');
is( digest_data('MD4', "123"), pack("H*","c58cda49f00748a3bc0fcfa511d516cb"), 'md4 (digest_data_raw/2)');
is( digest_data_hex('MD4', "123"), "c58cda49f00748a3bc0fcfa511d516cb", 'md4 (digest_data_hex/2)');
is( digest_data_b64('MD4', "123"), "xYzaSfAHSKO8D8+lEdUWyw==", 'md4 (digest_data_b64/2)');
is( digest_data_b64u('MD4', "123"), "xYzaSfAHSKO8D8-lEdUWyw", 'md4 (digest_data_b64u/2)');
is( Crypt::Digest::MD4->new->add("123")->hexdigest, "c58cda49f00748a3bc0fcfa511d516cb", 'md4 (OO/2)');

is( md4("test\0test\0test\n"), pack("H*","6c94f5386a75255cb008ea5ef7979eed"), 'md4 (raw/3)');
is( md4_hex("test\0test\0test\n"), "6c94f5386a75255cb008ea5ef7979eed", 'md4 (hex/3)');
is( md4_b64("test\0test\0test\n"), "bJT1OGp1JVywCOpe95ee7Q==", 'md4 (base64/3)');
is( digest_data('MD4', "test\0test\0test\n"), pack("H*","6c94f5386a75255cb008ea5ef7979eed"), 'md4 (digest_data_raw/3)');
is( digest_data_hex('MD4', "test\0test\0test\n"), "6c94f5386a75255cb008ea5ef7979eed", 'md4 (digest_data_hex/3)');
is( digest_data_b64('MD4', "test\0test\0test\n"), "bJT1OGp1JVywCOpe95ee7Q==", 'md4 (digest_data_b64/3)');
is( digest_data_b64u('MD4', "test\0test\0test\n"), "bJT1OGp1JVywCOpe95ee7Q", 'md4 (digest_data_b64u/3)');
is( Crypt::Digest::MD4->new->add("test\0test\0test\n")->hexdigest, "6c94f5386a75255cb008ea5ef7979eed", 'md4 (OO/3)');


is( md4_file('t/data/binary-test.file'), pack("H*","dc293e17d9dad79a9311a145c6a96b31"), 'md4 (raw/file/1)');
is( md4_file_hex('t/data/binary-test.file'), "dc293e17d9dad79a9311a145c6a96b31", 'md4 (hex/file/1)');
is( md4_file_b64('t/data/binary-test.file'), "3Ck+F9na15qTEaFFxqlrMQ==", 'md4 (base64/file/1)');
is( digest_file('MD4', 't/data/binary-test.file'), pack("H*","dc293e17d9dad79a9311a145c6a96b31"), 'md4 (digest_file_raw/file/1)');
is( digest_file_hex('MD4', 't/data/binary-test.file'), "dc293e17d9dad79a9311a145c6a96b31", 'md4 (digest_file_hex/file/1)');
is( digest_file_b64('MD4', 't/data/binary-test.file'), "3Ck+F9na15qTEaFFxqlrMQ==", 'md4 (digest_file_b64/file/1)');
is( digest_file_b64u('MD4', 't/data/binary-test.file'), "3Ck-F9na15qTEaFFxqlrMQ", 'md4 (digest_file_b64u/file/1)');
is( Crypt::Digest::MD4->new->addfile('t/data/binary-test.file')->hexdigest, "dc293e17d9dad79a9311a145c6a96b31", 'md4 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::MD4->new->addfile($fh)->hexdigest, "dc293e17d9dad79a9311a145c6a96b31", 'md4 (OO/filehandle/1)');
  close($fh);
}

is( md4_file('t/data/text-CR.file'), pack("H*","f0060ad3ed8081c8d55ede445cd19133"), 'md4 (raw/file/2)');
is( md4_file_hex('t/data/text-CR.file'), "f0060ad3ed8081c8d55ede445cd19133", 'md4 (hex/file/2)');
is( md4_file_b64('t/data/text-CR.file'), "8AYK0+2AgcjVXt5EXNGRMw==", 'md4 (base64/file/2)');
is( digest_file('MD4', 't/data/text-CR.file'), pack("H*","f0060ad3ed8081c8d55ede445cd19133"), 'md4 (digest_file_raw/file/2)');
is( digest_file_hex('MD4', 't/data/text-CR.file'), "f0060ad3ed8081c8d55ede445cd19133", 'md4 (digest_file_hex/file/2)');
is( digest_file_b64('MD4', 't/data/text-CR.file'), "8AYK0+2AgcjVXt5EXNGRMw==", 'md4 (digest_file_b64/file/2)');
is( digest_file_b64u('MD4', 't/data/text-CR.file'), "8AYK0-2AgcjVXt5EXNGRMw", 'md4 (digest_file_b64u/file/2)');
is( Crypt::Digest::MD4->new->addfile('t/data/text-CR.file')->hexdigest, "f0060ad3ed8081c8d55ede445cd19133", 'md4 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::MD4->new->addfile($fh)->hexdigest, "f0060ad3ed8081c8d55ede445cd19133", 'md4 (OO/filehandle/2)');
  close($fh);
}

is( md4_file('t/data/text-CRLF.file'), pack("H*","2c3026b3dea9ef3089d5ff750054b38b"), 'md4 (raw/file/3)');
is( md4_file_hex('t/data/text-CRLF.file'), "2c3026b3dea9ef3089d5ff750054b38b", 'md4 (hex/file/3)');
is( md4_file_b64('t/data/text-CRLF.file'), "LDAms96p7zCJ1f91AFSziw==", 'md4 (base64/file/3)');
is( digest_file('MD4', 't/data/text-CRLF.file'), pack("H*","2c3026b3dea9ef3089d5ff750054b38b"), 'md4 (digest_file_raw/file/3)');
is( digest_file_hex('MD4', 't/data/text-CRLF.file'), "2c3026b3dea9ef3089d5ff750054b38b", 'md4 (digest_file_hex/file/3)');
is( digest_file_b64('MD4', 't/data/text-CRLF.file'), "LDAms96p7zCJ1f91AFSziw==", 'md4 (digest_file_b64/file/3)');
is( digest_file_b64u('MD4', 't/data/text-CRLF.file'), "LDAms96p7zCJ1f91AFSziw", 'md4 (digest_file_b64u/file/3)');
is( Crypt::Digest::MD4->new->addfile('t/data/text-CRLF.file')->hexdigest, "2c3026b3dea9ef3089d5ff750054b38b", 'md4 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::MD4->new->addfile($fh)->hexdigest, "2c3026b3dea9ef3089d5ff750054b38b", 'md4 (OO/filehandle/3)');
  close($fh);
}

is( md4_file('t/data/text-LF.file'), pack("H*","3c87e1ed3fb63667f87a3ec8217f20ef"), 'md4 (raw/file/4)');
is( md4_file_hex('t/data/text-LF.file'), "3c87e1ed3fb63667f87a3ec8217f20ef", 'md4 (hex/file/4)');
is( md4_file_b64('t/data/text-LF.file'), "PIfh7T+2Nmf4ej7IIX8g7w==", 'md4 (base64/file/4)');
is( digest_file('MD4', 't/data/text-LF.file'), pack("H*","3c87e1ed3fb63667f87a3ec8217f20ef"), 'md4 (digest_file_raw/file/4)');
is( digest_file_hex('MD4', 't/data/text-LF.file'), "3c87e1ed3fb63667f87a3ec8217f20ef", 'md4 (digest_file_hex/file/4)');
is( digest_file_b64('MD4', 't/data/text-LF.file'), "PIfh7T+2Nmf4ej7IIX8g7w==", 'md4 (digest_file_b64/file/4)');
is( digest_file_b64u('MD4', 't/data/text-LF.file'), "PIfh7T-2Nmf4ej7IIX8g7w", 'md4 (digest_file_b64u/file/4)');
is( Crypt::Digest::MD4->new->addfile('t/data/text-LF.file')->hexdigest, "3c87e1ed3fb63667f87a3ec8217f20ef", 'md4 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::MD4->new->addfile($fh)->hexdigest, "3c87e1ed3fb63667f87a3ec8217f20ef", 'md4 (OO/filehandle/4)');
  close($fh);
}
