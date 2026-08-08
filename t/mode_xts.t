use strict;
use warnings;
use Test::More tests => 77;
use Config;
use Crypt::Mode::XTS;

sub h { pack "H*", shift }

my $pt512 = unpack "H*", pack "C*", ((0..255) x 2);

# XTS-AES test vectors from IEEE 1619-2007 (V4, V10, V15-V18) plus additional
# units; all cross-checked against OpenSSL (EVP aes-128-xts / aes-256-xts)
my $k128 = '2718281828459045235360287471352631415926535897932384626433832795';
my $kcts = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0';
my $k256 = '27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592';

my @tests = (
  { name=>'IEEE1619 V4 (AES-128, 512B)', cipher=>'AES', key=>$k128, seq=>0,
    tweak=>'00000000000000000000000000000000',
    pt=>$pt512,
    ct=>'27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568' },
  { name=>'IEEE1619 V15 (AES-128, 17B, CTS)', cipher=>'AES', key=>$kcts, seq=>78187493530, seq64=>1,
    tweak=>'9a785634120000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f10',
    ct=>'6c1625db4671522d3d7599601de7ca09ed' },
  { name=>'IEEE1619 V16 (AES-128, 18B, CTS)', cipher=>'AES', key=>$kcts, seq=>78187493530, seq64=>1,
    tweak=>'9a785634120000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f1011',
    ct=>'d069444b7a7e0cab09e24447d24deb1fedbf' },
  { name=>'IEEE1619 V17 (AES-128, 19B, CTS)', cipher=>'AES', key=>$kcts, seq=>78187493530, seq64=>1,
    tweak=>'9a785634120000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f101112',
    ct=>'e5df1351c0544ba1350b3363cd8ef4beedbf9d' },
  { name=>'IEEE1619 V18 (AES-128, 20B, CTS)', cipher=>'AES', key=>$kcts, seq=>78187493530, seq64=>1,
    tweak=>'9a785634120000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f10111213',
    ct=>'9d84c813f719aa2c7be3f66171c7c5c2edbf9dac' },
  { name=>'AES-128, exactly one block', cipher=>'AES', key=>$k128, seq=>2,
    tweak=>'02000000000000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f',
    ct=>'6fc5047ca79b062207be6385d3b6bd44' },
  { name=>'IEEE1619 V10 (AES-256, 512B)', cipher=>'AES', key=>$k256, seq=>255,
    tweak=>'ff000000000000000000000000000000',
    pt=>$pt512,
    ct=>'1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151' },
  { name=>'AES-256, exactly one block', cipher=>'AES', key=>$k256, seq=>1,
    tweak=>'01000000000000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f',
    ct=>'cdd765f24ea1d4ecfc5af7233967ef61' },
  { name=>'AES-256, 33B (CTS)', cipher=>'AES', key=>$k256, seq=>1099511627775, seq64=>1,
    tweak=>'ffffffffff0000000000000000000000',
    pt=>'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    ct=>'64497e5a831e4a932c09be3e5393376def5e83dd76a0ea36c1b26e4b8dc944f2aa' },
  { name=>'AES-256, full binary tweak', cipher=>'AES', key=>$k256,
    tweak=>'000102030405060708090a0b0c0d0e0f',
    pt=>'000102030405060708090a0b0c0d0e0f',
    ct=>'91a4f2aee571c4f510c35c849e09dabe' },
);

for my $t (@tests) {
  my $xts = Crypt::Mode::XTS->new($t->{cipher}, h($t->{key}));
  my ($pt, $ct, $tw) = (h($t->{pt}), h($t->{ct}), h($t->{tweak}));
  is(unpack('H*', $xts->encrypt($pt, $tw)), $t->{ct}, "$t->{name} encrypt (binary tweak)");
  is(unpack('H*', $xts->decrypt($ct, $tw)), $t->{pt}, "$t->{name} decrypt (binary tweak)");
  SKIP: {
    skip "$t->{name}: vector has no data unit number", 2 unless defined $t->{seq};
    skip "$t->{name}: data unit number needs 64-bit UV", 2 if $t->{seq64} && $Config{uvsize} < 8;
    is(unpack('H*', $xts->encrypt($pt, $t->{seq})), $t->{ct}, "$t->{name} encrypt (integer tweak)");
    is(unpack('H*', $xts->decrypt($ct, $t->{seq})), $t->{pt}, "$t->{name} decrypt (integer tweak)");
  }
}

### round trips with other 128-bit block ciphers (one object encrypts + decrypts)

for my $cipher (qw/AES Twofish Serpent Camellia ARIA SM4/) {
  my $xts = Crypt::Mode::XTS->new($cipher, pack 'C*', 1..32);
  for my $len (16, 33, 512) {
    my $pt = pack 'C*', map { $_ % 256 } 1..$len;
    is($xts->decrypt($xts->encrypt($pt, $len), $len), $pt, "round trip $cipher len=$len");
  }
}

### tweak forms

{
  my $xts = Crypt::Mode::XTS->new('AES', h($k128));
  my $pt = h('000102030405060708090a0b0c0d0e0f');
  is($xts->encrypt($pt, "\x02" . "\x00" x 15), $xts->encrypt($pt, 2), 'binary tweak equals data unit number');
  is($xts->encrypt($pt, "2"), $xts->encrypt($pt, 2), 'numeric string tweak equals integer tweak');
  isnt(unpack('H*', $xts->encrypt($pt, "0000000000000002")),
       unpack('H*', $xts->encrypt($pt, 2)), '16-byte digit string is a raw binary tweak, not a number');
}

### croak coverage

{
  my $key = 'A' x 16 . 'B' x 16;

  eval { Crypt::Mode::XTS->new('AES', 'A' x 32) };
  like($@, qr/key1 != key2/, 'croak: key1 == key2 (FIPS 140 IG A.9)');

  eval { Crypt::Mode::XTS->new('AES', 'A' x 33) };
  like($@, qr/two equal-length/, 'croak: odd key length');

  eval { Crypt::Mode::XTS->new('AES', 'A' x 20 . 'B' x 20) };
  like($@, qr/not a valid key size/, 'croak: invalid half key size');

  eval { Crypt::Mode::XTS->new('Blowfish', $key) };
  like($@, qr/128-bit block cipher/, 'croak: 64-bit block cipher');

  eval { Crypt::Mode::XTS->new('NoSuchCipher', $key) };
  like($@, qr/find_cipher failed/, 'croak: unknown cipher');

  eval { Crypt::Mode::XTS->new($key, 'AES') };
  like($@, qr/did you mean new\(cipher, key\)\?/, 'croak: swapped new() args');

  my $xts = Crypt::Mode::XTS->new('AES', $key);

  eval { $xts->encrypt('x' x 15, 0) };
  like($@, qr/at least 16 bytes/, 'croak: data unit shorter than one block');

  eval { $xts->encrypt('x' x 16) };
  like($@, qr/Usage/, 'croak: missing tweak');

  eval { $xts->encrypt('x' x 16, $key, 'some-iv') };
  like($@, qr/Usage/, 'croak: 3-arg CBC-style encrypt(data, key, iv)');

  eval { $xts->encrypt('x' x 16, "\x00" x 15) };
  like($@, qr/tweak must be/, 'croak: 15-byte tweak');

  eval { $xts->encrypt('x' x 16, "\x00" x 17) };
  like($@, qr/tweak must be/, 'croak: 17-byte tweak');

  eval { $xts->encrypt('x' x 16, -1) };
  like($@, qr/tweak must be/, 'croak: negative tweak');

  eval { $xts->encrypt('x' x 16, 'abc') };
  like($@, qr/tweak must be/, 'croak: non-numeric tweak');

  eval { $xts->encrypt('x' x 16, undef) };
  like($@, qr/tweak must be/, 'croak: undef tweak');

  eval { $xts->encrypt('x' x (16 * 1024 * 1024 + 1), 0) };
  like($@, qr/2\^20 blocks/, 'croak: data unit above 2^20 blocks');

  is(length($xts->encrypt('x' x (16 * 1024 * 1024), 0)), 16 * 1024 * 1024, 'exactly 2^20 blocks is accepted');
}
