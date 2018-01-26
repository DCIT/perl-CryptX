### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2s_256 qw( blake2s_256 blake2s_256_hex blake2s_256_b64 blake2s_256_b64u blake2s_256_file blake2s_256_file_hex blake2s_256_file_b64 blake2s_256_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2s_256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2s_256'), 32, 'hashsize/2');
is( Crypt::Digest::BLAKE2s_256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::BLAKE2s_256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2s_256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::BLAKE2s_256->new->hashsize, 32, 'hashsize/6');

is( blake2s_256("A","A","A"), pack("H*","8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6"), 'blake2s_256 (raw/tripple_A)');
is( blake2s_256_hex("A","A","A"), "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6", 'blake2s_256 (hex/tripple_A)');
is( blake2s_256_b64("A","A","A"), "jU/p9TaP85fOdERkD1IvCQWXWRwhOSJiE42mdQvx3/Y=", 'blake2s_256 (base64/tripple_A)');
is( blake2s_256_b64u("A","A","A"), "jU_p9TaP85fOdERkD1IvCQWXWRwhOSJiE42mdQvx3_Y", 'blake2s_256 (base64url/tripple_A)');
is( digest_data('BLAKE2s_256', "A","A","A"), pack("H*","8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6"), 'blake2s_256 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2s_256', "A","A","A"), "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6", 'blake2s_256 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2s_256', "A","A","A"), "jU/p9TaP85fOdERkD1IvCQWXWRwhOSJiE42mdQvx3/Y=", 'blake2s_256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2s_256', "A","A","A"), "jU_p9TaP85fOdERkD1IvCQWXWRwhOSJiE42mdQvx3_Y", 'blake2s_256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2s_256->new->add("A","A","A")->hexdigest, "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6", 'blake2s_256 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2s_256->new->add("A")->add("A")->add("A")->hexdigest, "8d4fe9f5368ff397ce7444640f522f090597591c21392262138da6750bf1dff6", 'blake2s_256 (OO3/tripple_A)');


is( blake2s_256(""), pack("H*","69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"), 'blake2s_256 (raw/1)');
is( blake2s_256_hex(""), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 'blake2s_256 (hex/1)');
is( blake2s_256_b64(""), "aSF6MHmQgJThESHQQjVKfB9VtkgsoaUeGyUN/R7Q7vk=", 'blake2s_256 (base64/1)');
is( digest_data('BLAKE2s_256', ""), pack("H*","69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"), 'blake2s_256 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2s_256', ""), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 'blake2s_256 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2s_256', ""), "aSF6MHmQgJThESHQQjVKfB9VtkgsoaUeGyUN/R7Q7vk=", 'blake2s_256 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2s_256', ""), "aSF6MHmQgJThESHQQjVKfB9VtkgsoaUeGyUN_R7Q7vk", 'blake2s_256 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2s_256->new->add("")->hexdigest, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 'blake2s_256 (OO/1)');

is( blake2s_256("123"), pack("H*","e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605"), 'blake2s_256 (raw/2)');
is( blake2s_256_hex("123"), "e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605", 'blake2s_256 (hex/2)');
is( blake2s_256_b64("123"), "6QZkSthhtY1HUA5sY27jv0y0uwABa7NSsdLQPRIsFgU=", 'blake2s_256 (base64/2)');
is( digest_data('BLAKE2s_256', "123"), pack("H*","e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605"), 'blake2s_256 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2s_256', "123"), "e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605", 'blake2s_256 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2s_256', "123"), "6QZkSthhtY1HUA5sY27jv0y0uwABa7NSsdLQPRIsFgU=", 'blake2s_256 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2s_256', "123"), "6QZkSthhtY1HUA5sY27jv0y0uwABa7NSsdLQPRIsFgU", 'blake2s_256 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2s_256->new->add("123")->hexdigest, "e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605", 'blake2s_256 (OO/2)');

is( blake2s_256("test\0test\0test\n"), pack("H*","01f3bf97dce139caa74eb5cb02d2f01e4afac0c49ebf655db3168d1ca7e1442b"), 'blake2s_256 (raw/3)');
is( blake2s_256_hex("test\0test\0test\n"), "01f3bf97dce139caa74eb5cb02d2f01e4afac0c49ebf655db3168d1ca7e1442b", 'blake2s_256 (hex/3)');
is( blake2s_256_b64("test\0test\0test\n"), "AfO/l9zhOcqnTrXLAtLwHkr6wMSev2VdsxaNHKfhRCs=", 'blake2s_256 (base64/3)');
is( digest_data('BLAKE2s_256', "test\0test\0test\n"), pack("H*","01f3bf97dce139caa74eb5cb02d2f01e4afac0c49ebf655db3168d1ca7e1442b"), 'blake2s_256 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2s_256', "test\0test\0test\n"), "01f3bf97dce139caa74eb5cb02d2f01e4afac0c49ebf655db3168d1ca7e1442b", 'blake2s_256 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2s_256', "test\0test\0test\n"), "AfO/l9zhOcqnTrXLAtLwHkr6wMSev2VdsxaNHKfhRCs=", 'blake2s_256 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2s_256', "test\0test\0test\n"), "AfO_l9zhOcqnTrXLAtLwHkr6wMSev2VdsxaNHKfhRCs", 'blake2s_256 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2s_256->new->add("test\0test\0test\n")->hexdigest, "01f3bf97dce139caa74eb5cb02d2f01e4afac0c49ebf655db3168d1ca7e1442b", 'blake2s_256 (OO/3)');


is( blake2s_256_file('t/data/binary-test.file'), pack("H*","af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad"), 'blake2s_256 (raw/file/1)');
is( blake2s_256_file_hex('t/data/binary-test.file'), "af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad", 'blake2s_256 (hex/file/1)');
is( blake2s_256_file_b64('t/data/binary-test.file'), "r24/HPK/vkvjkRQmCfsW48OvSUoIUpJwMqcNWH9oZa0=", 'blake2s_256 (base64/file/1)');
is( digest_file('BLAKE2s_256', 't/data/binary-test.file'), pack("H*","af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad"), 'blake2s_256 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2s_256', 't/data/binary-test.file'), "af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad", 'blake2s_256 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2s_256', 't/data/binary-test.file'), "r24/HPK/vkvjkRQmCfsW48OvSUoIUpJwMqcNWH9oZa0=", 'blake2s_256 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2s_256', 't/data/binary-test.file'), "r24_HPK_vkvjkRQmCfsW48OvSUoIUpJwMqcNWH9oZa0", 'blake2s_256 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2s_256->new->addfile('t/data/binary-test.file')->hexdigest, "af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad", 'blake2s_256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_256->new->addfile($fh)->hexdigest, "af6e3f1cf2bfbe4be391142609fb16e3c3af494a0852927032a70d587f6865ad", 'blake2s_256 (OO/filehandle/1)');
  close($fh);
}

is( blake2s_256_file('t/data/text-CR.file'), pack("H*","4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449"), 'blake2s_256 (raw/file/2)');
is( blake2s_256_file_hex('t/data/text-CR.file'), "4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449", 'blake2s_256 (hex/file/2)');
is( blake2s_256_file_b64('t/data/text-CR.file'), "QpfdsmNx8xu/sLT7vkesjIQ775KF9yqRg8/9vZrcBEk=", 'blake2s_256 (base64/file/2)');
is( digest_file('BLAKE2s_256', 't/data/text-CR.file'), pack("H*","4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449"), 'blake2s_256 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2s_256', 't/data/text-CR.file'), "4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449", 'blake2s_256 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2s_256', 't/data/text-CR.file'), "QpfdsmNx8xu/sLT7vkesjIQ775KF9yqRg8/9vZrcBEk=", 'blake2s_256 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2s_256', 't/data/text-CR.file'), "QpfdsmNx8xu_sLT7vkesjIQ775KF9yqRg8_9vZrcBEk", 'blake2s_256 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2s_256->new->addfile('t/data/text-CR.file')->hexdigest, "4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449", 'blake2s_256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_256->new->addfile($fh)->hexdigest, "4297ddb26371f31bbfb0b4fbbe47ac8c843bef9285f72a9183cffdbd9adc0449", 'blake2s_256 (OO/filehandle/2)');
  close($fh);
}

is( blake2s_256_file('t/data/text-CRLF.file'), pack("H*","ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267"), 'blake2s_256 (raw/file/3)');
is( blake2s_256_file_hex('t/data/text-CRLF.file'), "ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267", 'blake2s_256 (hex/file/3)');
is( blake2s_256_file_b64('t/data/text-CRLF.file'), "rp1wMBufD85jRjocO93GQ4yTQrE+ZwFSMjrVAmeE4mc=", 'blake2s_256 (base64/file/3)');
is( digest_file('BLAKE2s_256', 't/data/text-CRLF.file'), pack("H*","ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267"), 'blake2s_256 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2s_256', 't/data/text-CRLF.file'), "ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267", 'blake2s_256 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2s_256', 't/data/text-CRLF.file'), "rp1wMBufD85jRjocO93GQ4yTQrE+ZwFSMjrVAmeE4mc=", 'blake2s_256 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2s_256', 't/data/text-CRLF.file'), "rp1wMBufD85jRjocO93GQ4yTQrE-ZwFSMjrVAmeE4mc", 'blake2s_256 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2s_256->new->addfile('t/data/text-CRLF.file')->hexdigest, "ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267", 'blake2s_256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_256->new->addfile($fh)->hexdigest, "ae9d70301b9f0fce63463a1c3bddc6438c9342b13e670152323ad5026784e267", 'blake2s_256 (OO/filehandle/3)');
  close($fh);
}

is( blake2s_256_file('t/data/text-LF.file'), pack("H*","34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8"), 'blake2s_256 (raw/file/4)');
is( blake2s_256_file_hex('t/data/text-LF.file'), "34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8", 'blake2s_256 (hex/file/4)');
is( blake2s_256_file_b64('t/data/text-LF.file'), "NMnbgUlOiIZhvalWnYysnSqRBKfvfkZKq85wHo2Qk9g=", 'blake2s_256 (base64/file/4)');
is( digest_file('BLAKE2s_256', 't/data/text-LF.file'), pack("H*","34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8"), 'blake2s_256 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2s_256', 't/data/text-LF.file'), "34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8", 'blake2s_256 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2s_256', 't/data/text-LF.file'), "NMnbgUlOiIZhvalWnYysnSqRBKfvfkZKq85wHo2Qk9g=", 'blake2s_256 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2s_256', 't/data/text-LF.file'), "NMnbgUlOiIZhvalWnYysnSqRBKfvfkZKq85wHo2Qk9g", 'blake2s_256 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2s_256->new->addfile('t/data/text-LF.file')->hexdigest, "34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8", 'blake2s_256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_256->new->addfile($fh)->hexdigest, "34c9db81494e888661bda9569d8cac9d2a9104a7ef7e464aabce701e8d9093d8", 'blake2s_256 (OO/filehandle/4)');
  close($fh);
}
