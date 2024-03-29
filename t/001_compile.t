use strict;
use warnings;

use Config;
use Test::More tests => 1;

diag( "Testing CryptX $CryptX::VERSION, Perl $] $^O $^X" );

my $ok;
END { die "Could not load all modules" unless $ok }

use Crypt::AuthEnc::CCM;
use Crypt::AuthEnc::ChaCha20Poly1305;
use Crypt::AuthEnc::EAX;
use Crypt::AuthEnc::GCM;
use Crypt::AuthEnc::OCB;
use Crypt::AuthEnc;
use Crypt::Checksum::Adler32;
use Crypt::Checksum::CRC32;
use Crypt::Checksum;
use Crypt::Cipher::AES;
use Crypt::Cipher::Anubis;
use Crypt::Cipher::Blowfish;
use Crypt::Cipher::Camellia;
use Crypt::Cipher::CAST5;
use Crypt::Cipher::DES;
use Crypt::Cipher::DES_EDE;
use Crypt::Cipher::IDEA;
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
use Crypt::Cipher::Serpent;
use Crypt::Cipher::Skipjack;
use Crypt::Cipher::Twofish;
use Crypt::Cipher::XTEA;
use Crypt::Cipher;
use Crypt::Digest::BLAKE2b_160;
use Crypt::Digest::BLAKE2b_256;
use Crypt::Digest::BLAKE2b_384;
use Crypt::Digest::BLAKE2b_512;
use Crypt::Digest::BLAKE2s_128;
use Crypt::Digest::BLAKE2s_160;
use Crypt::Digest::BLAKE2s_224;
use Crypt::Digest::BLAKE2s_256;
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
use Crypt::Digest::SHA3_224;
use Crypt::Digest::SHA3_256;
use Crypt::Digest::SHA3_384;
use Crypt::Digest::SHA3_512;
use Crypt::Digest::Keccak224;
use Crypt::Digest::Keccak256;
use Crypt::Digest::Keccak384;
use Crypt::Digest::Keccak512;
use Crypt::Digest::SHA512;
use Crypt::Digest::SHA512_224;
use Crypt::Digest::SHA512_256;
use Crypt::Digest::SHAKE;
use Crypt::Digest::Tiger192;
use Crypt::Digest::Whirlpool;
use Crypt::Digest;
use Crypt::KeyDerivation;
use Crypt::Mac::BLAKE2b;
use Crypt::Mac::BLAKE2s;
use Crypt::Mac::F9;
use Crypt::Mac::HMAC;
use Crypt::Mac::OMAC;
use Crypt::Mac::Pelican;
use Crypt::Mac::PMAC;
use Crypt::Mac::Poly1305;
use Crypt::Mac::XCBC;
use Crypt::Mac;
use Crypt::Misc;
use Crypt::Mode::CBC;
use Crypt::Mode::CFB;
use Crypt::Mode::CTR;
use Crypt::Mode::ECB;
use Crypt::Mode::OFB;
use Crypt::Mode;
use Crypt::PK::DH;
use Crypt::PK::DSA;
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::PK::X25519;
use Crypt::PK::Ed25519;
use Crypt::PK;
use Crypt::PRNG::ChaCha20;
use Crypt::PRNG::Fortuna;
use Crypt::PRNG::RC4;
use Crypt::PRNG::Sober128;
use Crypt::PRNG::Yarrow;
use Crypt::PRNG;
use Crypt::Stream::ChaCha;
use Crypt::Stream::RC4;
use Crypt::Stream::Salsa20;
use Crypt::Stream::Sober128;
use Crypt::Stream::Sosemanuk;
use Crypt::Stream::Rabbit;
use CryptX;
use Math::BigInt::LTM;

diag( "osname       = $Config{osname}" );
diag( "osvers       = $Config{osvers}" );
diag( "archname     = $Config{archname}" );
diag( "uname        = $Config{uname}" );
diag( "myarchname   = $Config{myarchname}" );
diag( "myuname      = $Config{myuname}" );
diag( "gccversion   = $Config{gccversion}" );
diag( "ccversion    = $Config{ccversion}" );
diag( "cc           = $Config{cc}" );
diag( "intsize      = $Config{intsize}" );
diag( "longsize     = $Config{longsize}" );
diag( "longlongsize = $Config{longlongsize}" );
diag( "ptrsize      = $Config{ptrsize}" );
diag( "byteorder    = $Config{byteorder}" );
diag( "" );
diag( CryptX::_ltc_build_settings );
diag( "" );
diag( "MP_PROVIDER  = " . CryptX::_ltc_mp_name );
diag( "MP_DIGIT_BIT = " . CryptX::_ltc_mp_bits_per_digit );
diag( "" );

ok 1, 'All modules loaded successfully';
$ok = 1;
