### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA512_256 qw( sha512_256 sha512_256_hex sha512_256_b64 sha512_256_b64u sha512_256_file sha512_256_file_hex sha512_256_file_b64 sha512_256_file_b64u );

is( Crypt::Digest::hashsize('SHA512_256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA512_256'), 32, 'hashsize/2');
is( Crypt::Digest::SHA512_256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::SHA512_256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('SHA512_256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::SHA512_256->new->hashsize, 32, 'hashsize/6');

is( sha512_256("A","A","A"), pack("H*","b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4"), 'sha512_256 (raw/tripple_A)');
is( sha512_256_hex("A","A","A"), "b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4", 'sha512_256 (hex/tripple_A)');
is( sha512_256_b64("A","A","A"), "sopilp2LmwIpe6YVxIW+Lf/vkHykGcKklABAJtbEvfQ=", 'sha512_256 (base64/tripple_A)');
is( sha512_256_b64u("A","A","A"), "sopilp2LmwIpe6YVxIW-Lf_vkHykGcKklABAJtbEvfQ", 'sha512_256 (base64url/tripple_A)');
is( digest_data('SHA512_256', "A","A","A"), pack("H*","b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4"), 'sha512_256 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA512_256', "A","A","A"), "b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4", 'sha512_256 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA512_256', "A","A","A"), "sopilp2LmwIpe6YVxIW+Lf/vkHykGcKklABAJtbEvfQ=", 'sha512_256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA512_256', "A","A","A"), "sopilp2LmwIpe6YVxIW-Lf_vkHykGcKklABAJtbEvfQ", 'sha512_256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA512_256->new->add("A","A","A")->hexdigest, "b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4", 'sha512_256 (OO/tripple_A)');
is( Crypt::Digest::SHA512_256->new->add("A")->add("A")->add("A")->hexdigest, "b28a62969d8b9b02297ba615c485be2dffef907ca419c2a494004026d6c4bdf4", 'sha512_256 (OO3/tripple_A)');


is( sha512_256(""), pack("H*","c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"), 'sha512_256 (raw/1)');
is( sha512_256_hex(""), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", 'sha512_256 (hex/1)');
is( sha512_256_b64(""), "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=", 'sha512_256 (base64/1)');
is( digest_data('SHA512_256', ""), pack("H*","c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"), 'sha512_256 (digest_data_raw/1)');
is( digest_data_hex('SHA512_256', ""), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", 'sha512_256 (digest_data_hex/1)');
is( digest_data_b64('SHA512_256', ""), "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=", 'sha512_256 (digest_data_b64/1)');
is( digest_data_b64u('SHA512_256', ""), "xnK40e9W7Sirh8NiLFEUBpvdOte4-XN0mNDAHs7wlno", 'sha512_256 (digest_data_b64u/1)');
is( Crypt::Digest::SHA512_256->new->add("")->hexdigest, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", 'sha512_256 (OO/1)');

is( sha512_256("123"), pack("H*","f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10"), 'sha512_256 (raw/2)');
is( sha512_256_hex("123"), "f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10", 'sha512_256 (hex/2)');
is( sha512_256_b64("123"), "9RgsNPZsRrpcGF+62PcdscjaFztvbEwbyOz8/dQm/RA=", 'sha512_256 (base64/2)');
is( digest_data('SHA512_256', "123"), pack("H*","f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10"), 'sha512_256 (digest_data_raw/2)');
is( digest_data_hex('SHA512_256', "123"), "f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10", 'sha512_256 (digest_data_hex/2)');
is( digest_data_b64('SHA512_256', "123"), "9RgsNPZsRrpcGF+62PcdscjaFztvbEwbyOz8/dQm/RA=", 'sha512_256 (digest_data_b64/2)');
is( digest_data_b64u('SHA512_256', "123"), "9RgsNPZsRrpcGF-62PcdscjaFztvbEwbyOz8_dQm_RA", 'sha512_256 (digest_data_b64u/2)');
is( Crypt::Digest::SHA512_256->new->add("123")->hexdigest, "f5182c34f66c46ba5c185fbad8f71db1c8da173b6f6c4c1bc8ecfcfdd426fd10", 'sha512_256 (OO/2)');

is( sha512_256("test\0test\0test\n"), pack("H*","a6a117dcf996903422e8daee13ea130e7192d055bf07e4b534f9ed1df9167264"), 'sha512_256 (raw/3)');
is( sha512_256_hex("test\0test\0test\n"), "a6a117dcf996903422e8daee13ea130e7192d055bf07e4b534f9ed1df9167264", 'sha512_256 (hex/3)');
is( sha512_256_b64("test\0test\0test\n"), "pqEX3PmWkDQi6NruE+oTDnGS0FW/B+S1NPntHfkWcmQ=", 'sha512_256 (base64/3)');
is( digest_data('SHA512_256', "test\0test\0test\n"), pack("H*","a6a117dcf996903422e8daee13ea130e7192d055bf07e4b534f9ed1df9167264"), 'sha512_256 (digest_data_raw/3)');
is( digest_data_hex('SHA512_256', "test\0test\0test\n"), "a6a117dcf996903422e8daee13ea130e7192d055bf07e4b534f9ed1df9167264", 'sha512_256 (digest_data_hex/3)');
is( digest_data_b64('SHA512_256', "test\0test\0test\n"), "pqEX3PmWkDQi6NruE+oTDnGS0FW/B+S1NPntHfkWcmQ=", 'sha512_256 (digest_data_b64/3)');
is( digest_data_b64u('SHA512_256', "test\0test\0test\n"), "pqEX3PmWkDQi6NruE-oTDnGS0FW_B-S1NPntHfkWcmQ", 'sha512_256 (digest_data_b64u/3)');
is( Crypt::Digest::SHA512_256->new->add("test\0test\0test\n")->hexdigest, "a6a117dcf996903422e8daee13ea130e7192d055bf07e4b534f9ed1df9167264", 'sha512_256 (OO/3)');


is( sha512_256_file('t/data/binary-test.file'), pack("H*","0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af"), 'sha512_256 (raw/file/1)');
is( sha512_256_file_hex('t/data/binary-test.file'), "0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af", 'sha512_256 (hex/file/1)');
is( sha512_256_file_b64('t/data/binary-test.file'), "C3P1eHSbc2damNPY2vNFfDJtt3W4ekg9DBJF7eSEZ68=", 'sha512_256 (base64/file/1)');
is( digest_file('SHA512_256', 't/data/binary-test.file'), pack("H*","0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af"), 'sha512_256 (digest_file_raw/file/1)');
is( digest_file_hex('SHA512_256', 't/data/binary-test.file'), "0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af", 'sha512_256 (digest_file_hex/file/1)');
is( digest_file_b64('SHA512_256', 't/data/binary-test.file'), "C3P1eHSbc2damNPY2vNFfDJtt3W4ekg9DBJF7eSEZ68=", 'sha512_256 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA512_256', 't/data/binary-test.file'), "C3P1eHSbc2damNPY2vNFfDJtt3W4ekg9DBJF7eSEZ68", 'sha512_256 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA512_256->new->addfile('t/data/binary-test.file')->hexdigest, "0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af", 'sha512_256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_256->new->addfile($fh)->hexdigest, "0b73f578749b73675a98d3d8daf3457c326db775b87a483d0c1245ede48467af", 'sha512_256 (OO/filehandle/1)');
  close($fh);
}

is( sha512_256_file('t/data/text-CR.file'), pack("H*","8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb"), 'sha512_256 (raw/file/2)');
is( sha512_256_file_hex('t/data/text-CR.file'), "8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb", 'sha512_256 (hex/file/2)');
is( sha512_256_file_b64('t/data/text-CR.file'), "j2tjOLRlbtK3HwRNH928Lh0EcLMo4ZYvnNsRUr2zP7s=", 'sha512_256 (base64/file/2)');
is( digest_file('SHA512_256', 't/data/text-CR.file'), pack("H*","8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb"), 'sha512_256 (digest_file_raw/file/2)');
is( digest_file_hex('SHA512_256', 't/data/text-CR.file'), "8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb", 'sha512_256 (digest_file_hex/file/2)');
is( digest_file_b64('SHA512_256', 't/data/text-CR.file'), "j2tjOLRlbtK3HwRNH928Lh0EcLMo4ZYvnNsRUr2zP7s=", 'sha512_256 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA512_256', 't/data/text-CR.file'), "j2tjOLRlbtK3HwRNH928Lh0EcLMo4ZYvnNsRUr2zP7s", 'sha512_256 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA512_256->new->addfile('t/data/text-CR.file')->hexdigest, "8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb", 'sha512_256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_256->new->addfile($fh)->hexdigest, "8f6b6338b4656ed2b71f044d1fddbc2e1d0470b328e1962f9cdb1152bdb33fbb", 'sha512_256 (OO/filehandle/2)');
  close($fh);
}

is( sha512_256_file('t/data/text-CRLF.file'), pack("H*","432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18"), 'sha512_256 (raw/file/3)');
is( sha512_256_file_hex('t/data/text-CRLF.file'), "432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18", 'sha512_256 (hex/file/3)');
is( sha512_256_file_b64('t/data/text-CRLF.file'), "Qyyd3L+N61yhYOOgp+BmBrO6rjnWZitFauPDYwTq7Rg=", 'sha512_256 (base64/file/3)');
is( digest_file('SHA512_256', 't/data/text-CRLF.file'), pack("H*","432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18"), 'sha512_256 (digest_file_raw/file/3)');
is( digest_file_hex('SHA512_256', 't/data/text-CRLF.file'), "432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18", 'sha512_256 (digest_file_hex/file/3)');
is( digest_file_b64('SHA512_256', 't/data/text-CRLF.file'), "Qyyd3L+N61yhYOOgp+BmBrO6rjnWZitFauPDYwTq7Rg=", 'sha512_256 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA512_256', 't/data/text-CRLF.file'), "Qyyd3L-N61yhYOOgp-BmBrO6rjnWZitFauPDYwTq7Rg", 'sha512_256 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA512_256->new->addfile('t/data/text-CRLF.file')->hexdigest, "432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18", 'sha512_256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_256->new->addfile($fh)->hexdigest, "432c9ddcbf8deb5ca160e3a0a7e06606b3baae39d6662b456ae3c36304eaed18", 'sha512_256 (OO/filehandle/3)');
  close($fh);
}

is( sha512_256_file('t/data/text-LF.file'), pack("H*","26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2"), 'sha512_256 (raw/file/4)');
is( sha512_256_file_hex('t/data/text-LF.file'), "26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2", 'sha512_256 (hex/file/4)');
is( sha512_256_file_b64('t/data/text-LF.file'), "Js4Es6UppSsUNaNIF1cjt4iFs16YBaywm9Qz4WOguMI=", 'sha512_256 (base64/file/4)');
is( digest_file('SHA512_256', 't/data/text-LF.file'), pack("H*","26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2"), 'sha512_256 (digest_file_raw/file/4)');
is( digest_file_hex('SHA512_256', 't/data/text-LF.file'), "26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2", 'sha512_256 (digest_file_hex/file/4)');
is( digest_file_b64('SHA512_256', 't/data/text-LF.file'), "Js4Es6UppSsUNaNIF1cjt4iFs16YBaywm9Qz4WOguMI=", 'sha512_256 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA512_256', 't/data/text-LF.file'), "Js4Es6UppSsUNaNIF1cjt4iFs16YBaywm9Qz4WOguMI", 'sha512_256 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA512_256->new->addfile('t/data/text-LF.file')->hexdigest, "26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2", 'sha512_256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_256->new->addfile($fh)->hexdigest, "26ce04b3a529a52b1435a348175723b78885b35e9805acb09bd433e163a0b8c2", 'sha512_256 (OO/filehandle/4)');
  close($fh);
}
