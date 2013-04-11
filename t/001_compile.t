use strict;
use warnings;

use Test::More tests => 1;

diag( "Testing CryptX $CryptX::VERSION, Perl $], $^X" );

my $ok;
END { die "Could not load all modules" unless $ok }

use CryptX;
use Crypt::Cipher::AES;
use Crypt::Cipher::Anubis;
use Crypt::Cipher::Blowfish;
use Crypt::Cipher::Camellia;
use Crypt::Cipher::CAST5;
use Crypt::Cipher::DES;
use Crypt::Cipher::DES_EDE;
use Crypt::Cipher::KASUMI;
use Crypt::Cipher::Khazad;
use Crypt::Cipher::MULTI2;
use Crypt::Cipher::Noekeon;
use Crypt::Cipher::RC2;
use Crypt::Cipher::RC5;
use Crypt::Cipher::RC6;
use Crypt::Cipher::SAFERP;
use Crypt::Cipher::SAFER_K128;
use Crypt::Cipher::SAFER_K64;
use Crypt::Cipher::SAFER_SK128;
use Crypt::Cipher::SAFER_SK64;
use Crypt::Cipher::SEED;
use Crypt::Cipher::Skipjack;
use Crypt::Cipher::Twofish;
use Crypt::Cipher::XTEA;
use Crypt::Cipher;
use Crypt::Digest::CHAES;
use Crypt::Digest::MD2;
use Crypt::Digest::MD4;
use Crypt::Digest::MD5;
use Crypt::Digest::RIPEMD128;
use Crypt::Digest::RIPEMD160;
use Crypt::Digest::RIPEMD256;
use Crypt::Digest::RIPEMD320;
use Crypt::Digest::SHA1;
use Crypt::Digest::SHA224;
use Crypt::Digest::SHA256;
use Crypt::Digest::SHA384;
use Crypt::Digest::SHA512;
use Crypt::Digest::Tiger192;
use Crypt::Digest::Whirlpool;
use Crypt::Digest;
use Crypt::Mac::F9;
use Crypt::Mac::HMAC;
use Crypt::Mac::OMAC;
use Crypt::Mac::Pelican;
use Crypt::Mac::PMAC;
use Crypt::Mac::XCBC;

ok 1, 'All modules loaded successfully';
$ok = 1;

