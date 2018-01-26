### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA3_256 qw( sha3_256 sha3_256_hex sha3_256_b64 sha3_256_b64u sha3_256_file sha3_256_file_hex sha3_256_file_b64 sha3_256_file_b64u );

is( Crypt::Digest::hashsize('SHA3_256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA3_256'), 32, 'hashsize/2');
is( Crypt::Digest::SHA3_256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::SHA3_256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('SHA3_256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::SHA3_256->new->hashsize, 32, 'hashsize/6');

is( sha3_256("A","A","A"), pack("H*","7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa"), 'sha3_256 (raw/tripple_A)');
is( sha3_256_hex("A","A","A"), "7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa", 'sha3_256 (hex/tripple_A)');
is( sha3_256_b64("A","A","A"), "fcuCeh9afL6kI+djp90MeCTjUSx/HOSM1XEPYDtPHvo=", 'sha3_256 (base64/tripple_A)');
is( sha3_256_b64u("A","A","A"), "fcuCeh9afL6kI-djp90MeCTjUSx_HOSM1XEPYDtPHvo", 'sha3_256 (base64url/tripple_A)');
is( digest_data('SHA3_256', "A","A","A"), pack("H*","7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa"), 'sha3_256 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA3_256', "A","A","A"), "7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa", 'sha3_256 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA3_256', "A","A","A"), "fcuCeh9afL6kI+djp90MeCTjUSx/HOSM1XEPYDtPHvo=", 'sha3_256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA3_256', "A","A","A"), "fcuCeh9afL6kI-djp90MeCTjUSx_HOSM1XEPYDtPHvo", 'sha3_256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA3_256->new->add("A","A","A")->hexdigest, "7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa", 'sha3_256 (OO/tripple_A)');
is( Crypt::Digest::SHA3_256->new->add("A")->add("A")->add("A")->hexdigest, "7dcb827a1f5a7cbea423e763a7dd0c7824e3512c7f1ce48cd5710f603b4f1efa", 'sha3_256 (OO3/tripple_A)');


is( sha3_256(""), pack("H*","a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), 'sha3_256 (raw/1)');
is( sha3_256_hex(""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 'sha3_256 (hex/1)');
is( sha3_256_b64(""), "p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=", 'sha3_256 (base64/1)');
is( digest_data('SHA3_256', ""), pack("H*","a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), 'sha3_256 (digest_data_raw/1)');
is( digest_data_hex('SHA3_256', ""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 'sha3_256 (digest_data_hex/1)');
is( digest_data_b64('SHA3_256', ""), "p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=", 'sha3_256 (digest_data_b64/1)');
is( digest_data_b64u('SHA3_256', ""), "p__G-L8e12ZRwUdWoGHWYvWA_03kO0n6gtgKS4D4Q0o", 'sha3_256 (digest_data_b64u/1)');
is( Crypt::Digest::SHA3_256->new->add("")->hexdigest, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 'sha3_256 (OO/1)');

is( sha3_256("123"), pack("H*","a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"), 'sha3_256 (raw/2)');
is( sha3_256_hex("123"), "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", 'sha3_256 (hex/2)');
is( sha3_256_b64("123"), "oDqxm4ZvxYW1yxgSovY8qGHn52Q+5dQ/1xBrYjcl/Wc=", 'sha3_256 (base64/2)');
is( digest_data('SHA3_256', "123"), pack("H*","a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"), 'sha3_256 (digest_data_raw/2)');
is( digest_data_hex('SHA3_256', "123"), "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", 'sha3_256 (digest_data_hex/2)');
is( digest_data_b64('SHA3_256', "123"), "oDqxm4ZvxYW1yxgSovY8qGHn52Q+5dQ/1xBrYjcl/Wc=", 'sha3_256 (digest_data_b64/2)');
is( digest_data_b64u('SHA3_256', "123"), "oDqxm4ZvxYW1yxgSovY8qGHn52Q-5dQ_1xBrYjcl_Wc", 'sha3_256 (digest_data_b64u/2)');
is( Crypt::Digest::SHA3_256->new->add("123")->hexdigest, "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", 'sha3_256 (OO/2)');

is( sha3_256("test\0test\0test\n"), pack("H*","fb08b084e0cff0f17d0d7054aaed12269d2fa08e4c770c4ad497d4f0372f7963"), 'sha3_256 (raw/3)');
is( sha3_256_hex("test\0test\0test\n"), "fb08b084e0cff0f17d0d7054aaed12269d2fa08e4c770c4ad497d4f0372f7963", 'sha3_256 (hex/3)');
is( sha3_256_b64("test\0test\0test\n"), "+wiwhODP8PF9DXBUqu0SJp0voI5MdwxK1JfU8DcveWM=", 'sha3_256 (base64/3)');
is( digest_data('SHA3_256', "test\0test\0test\n"), pack("H*","fb08b084e0cff0f17d0d7054aaed12269d2fa08e4c770c4ad497d4f0372f7963"), 'sha3_256 (digest_data_raw/3)');
is( digest_data_hex('SHA3_256', "test\0test\0test\n"), "fb08b084e0cff0f17d0d7054aaed12269d2fa08e4c770c4ad497d4f0372f7963", 'sha3_256 (digest_data_hex/3)');
is( digest_data_b64('SHA3_256', "test\0test\0test\n"), "+wiwhODP8PF9DXBUqu0SJp0voI5MdwxK1JfU8DcveWM=", 'sha3_256 (digest_data_b64/3)');
is( digest_data_b64u('SHA3_256', "test\0test\0test\n"), "-wiwhODP8PF9DXBUqu0SJp0voI5MdwxK1JfU8DcveWM", 'sha3_256 (digest_data_b64u/3)');
is( Crypt::Digest::SHA3_256->new->add("test\0test\0test\n")->hexdigest, "fb08b084e0cff0f17d0d7054aaed12269d2fa08e4c770c4ad497d4f0372f7963", 'sha3_256 (OO/3)');


is( sha3_256_file('t/data/binary-test.file'), pack("H*","9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4"), 'sha3_256 (raw/file/1)');
is( sha3_256_file_hex('t/data/binary-test.file'), "9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4", 'sha3_256 (hex/file/1)');
is( sha3_256_file_b64('t/data/binary-test.file'), "nF0BV6vNeOse5Oi+2OA7j64smj+YoJ7CjrdtGuKpq9Q=", 'sha3_256 (base64/file/1)');
is( digest_file('SHA3_256', 't/data/binary-test.file'), pack("H*","9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4"), 'sha3_256 (digest_file_raw/file/1)');
is( digest_file_hex('SHA3_256', 't/data/binary-test.file'), "9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4", 'sha3_256 (digest_file_hex/file/1)');
is( digest_file_b64('SHA3_256', 't/data/binary-test.file'), "nF0BV6vNeOse5Oi+2OA7j64smj+YoJ7CjrdtGuKpq9Q=", 'sha3_256 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA3_256', 't/data/binary-test.file'), "nF0BV6vNeOse5Oi-2OA7j64smj-YoJ7CjrdtGuKpq9Q", 'sha3_256 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA3_256->new->addfile('t/data/binary-test.file')->hexdigest, "9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4", 'sha3_256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_256->new->addfile($fh)->hexdigest, "9c5d0157abcd78eb1ee4e8bed8e03b8fae2c9a3f98a09ec28eb76d1ae2a9abd4", 'sha3_256 (OO/filehandle/1)');
  close($fh);
}

is( sha3_256_file('t/data/text-CR.file'), pack("H*","56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475"), 'sha3_256 (raw/file/2)');
is( sha3_256_file_hex('t/data/text-CR.file'), "56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475", 'sha3_256 (hex/file/2)');
is( sha3_256_file_b64('t/data/text-CR.file'), "VqFUXPP3w1Rm+Vh6tEVpMSrpE5ckA2/AmNcWzt+xZHU=", 'sha3_256 (base64/file/2)');
is( digest_file('SHA3_256', 't/data/text-CR.file'), pack("H*","56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475"), 'sha3_256 (digest_file_raw/file/2)');
is( digest_file_hex('SHA3_256', 't/data/text-CR.file'), "56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475", 'sha3_256 (digest_file_hex/file/2)');
is( digest_file_b64('SHA3_256', 't/data/text-CR.file'), "VqFUXPP3w1Rm+Vh6tEVpMSrpE5ckA2/AmNcWzt+xZHU=", 'sha3_256 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA3_256', 't/data/text-CR.file'), "VqFUXPP3w1Rm-Vh6tEVpMSrpE5ckA2_AmNcWzt-xZHU", 'sha3_256 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA3_256->new->addfile('t/data/text-CR.file')->hexdigest, "56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475", 'sha3_256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_256->new->addfile($fh)->hexdigest, "56a1545cf3f7c35466f9587ab44569312ae9139724036fc098d716cedfb16475", 'sha3_256 (OO/filehandle/2)');
  close($fh);
}

is( sha3_256_file('t/data/text-CRLF.file'), pack("H*","82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72"), 'sha3_256 (raw/file/3)');
is( sha3_256_file_hex('t/data/text-CRLF.file'), "82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72", 'sha3_256 (hex/file/3)');
is( sha3_256_file_b64('t/data/text-CRLF.file'), "gomKe9WdidTwmJTV0zrdZq5cGXHA/iKcoDcdfSI5n3I=", 'sha3_256 (base64/file/3)');
is( digest_file('SHA3_256', 't/data/text-CRLF.file'), pack("H*","82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72"), 'sha3_256 (digest_file_raw/file/3)');
is( digest_file_hex('SHA3_256', 't/data/text-CRLF.file'), "82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72", 'sha3_256 (digest_file_hex/file/3)');
is( digest_file_b64('SHA3_256', 't/data/text-CRLF.file'), "gomKe9WdidTwmJTV0zrdZq5cGXHA/iKcoDcdfSI5n3I=", 'sha3_256 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA3_256', 't/data/text-CRLF.file'), "gomKe9WdidTwmJTV0zrdZq5cGXHA_iKcoDcdfSI5n3I", 'sha3_256 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA3_256->new->addfile('t/data/text-CRLF.file')->hexdigest, "82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72", 'sha3_256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_256->new->addfile($fh)->hexdigest, "82898a7bd59d89d4f09894d5d33add66ae5c1971c0fe229ca0371d7d22399f72", 'sha3_256 (OO/filehandle/3)');
  close($fh);
}

is( sha3_256_file('t/data/text-LF.file'), pack("H*","8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7"), 'sha3_256 (raw/file/4)');
is( sha3_256_file_hex('t/data/text-LF.file'), "8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7", 'sha3_256 (hex/file/4)');
is( sha3_256_file_b64('t/data/text-LF.file'), "ghjvbfsygvvQB5waHVDmic324wRvK5IZzSHk01EwSLc=", 'sha3_256 (base64/file/4)');
is( digest_file('SHA3_256', 't/data/text-LF.file'), pack("H*","8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7"), 'sha3_256 (digest_file_raw/file/4)');
is( digest_file_hex('SHA3_256', 't/data/text-LF.file'), "8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7", 'sha3_256 (digest_file_hex/file/4)');
is( digest_file_b64('SHA3_256', 't/data/text-LF.file'), "ghjvbfsygvvQB5waHVDmic324wRvK5IZzSHk01EwSLc=", 'sha3_256 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA3_256', 't/data/text-LF.file'), "ghjvbfsygvvQB5waHVDmic324wRvK5IZzSHk01EwSLc", 'sha3_256 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA3_256->new->addfile('t/data/text-LF.file')->hexdigest, "8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7", 'sha3_256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA3_256->new->addfile($fh)->hexdigest, "8218ef6dfb3282fbd0079c1a1d50e689cdf6e3046f2b9219cd21e4d3513048b7", 'sha3_256 (OO/filehandle/4)');
  close($fh);
}
