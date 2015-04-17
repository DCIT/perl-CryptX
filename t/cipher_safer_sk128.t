### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::SAFER_SK128;

is( Crypt::Cipher::SAFER_SK128::blocksize, 8, '::blocksize');
is( Crypt::Cipher::SAFER_SK128::keysize, 16, '::keysize');
is( Crypt::Cipher::SAFER_SK128::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::SAFER_SK128::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::SAFER_SK128::default_rounds, 10, '::default_rounds');

is( Crypt::Cipher::SAFER_SK128->blocksize, 8, '->blocksize');
is( Crypt::Cipher::SAFER_SK128->keysize, 16, '->keysize');
is( Crypt::Cipher::SAFER_SK128->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::SAFER_SK128->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::SAFER_SK128->default_rounds, 10, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('SAFER_SK128'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SAFER_SK128'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SAFER_SK128'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SAFER_SK128'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SAFER_SK128'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SAFER_SK128'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SAFER_SK128'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SAFER_SK128'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SAFER_SK128'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SAFER_SK128'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher::SAFER_SK128->new($min_key)->blocksize, 8, 'SAFER_SK128->new()->blocksize');
is( Crypt::Cipher::SAFER_SK128->new($min_key)->keysize, 16, 'SAFER_SK128->new()->keysize');
is( Crypt::Cipher::SAFER_SK128->new($min_key)->max_keysize, 16, 'SAFER_SK128->new()->max_keysize');
is( Crypt::Cipher::SAFER_SK128->new($min_key)->min_keysize, 16, 'SAFER_SK128->new()->min_keysize');
is( Crypt::Cipher::SAFER_SK128->new($min_key)->default_rounds, 10, 'SAFER_SK128->new()->default_rounds');

is( Crypt::Cipher->new('SAFER_SK128', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SAFER_SK128', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SAFER_SK128', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SAFER_SK128', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SAFER_SK128', $min_key)->default_rounds, 10, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'f61b32cc7e1a09b9';
my $block_encrypted_max_key_hex = '621d57c58719cb34';

is( unpack('H*', Crypt::Cipher::SAFER_SK128->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SAFER_SK128->encrypt');
is( Crypt::Cipher::SAFER_SK128->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SAFER_SK128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK128', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK128', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SAFER_SK128->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SAFER_SK128->encrypt');
is( Crypt::Cipher::SAFER_SK128->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SAFER_SK128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK128', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK128', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSSSSSSSSSS';
my $spec_rounds = '11';
my $spec_block_encrypted_hex = '8c62673889cb02a2';

is( unpack('H*', Crypt::Cipher::SAFER_SK128->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'SAFER_SK128->encrypt');
is( Crypt::Cipher::SAFER_SK128->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'SAFER_SK128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK128', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK128', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
