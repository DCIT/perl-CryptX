### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::XTEA;

is( Crypt::Cipher::XTEA::blocksize, 8, '::blocksize');
is( Crypt::Cipher::XTEA::keysize, 16, '::keysize');
is( Crypt::Cipher::XTEA::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::XTEA::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::XTEA::default_rounds, 32, '::default_rounds');

is( Crypt::Cipher::XTEA->blocksize, 8, '->blocksize');
is( Crypt::Cipher::XTEA->keysize, 16, '->keysize');
is( Crypt::Cipher::XTEA->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::XTEA->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::XTEA->default_rounds, 32, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('XTEA'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('XTEA'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('XTEA'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('XTEA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('XTEA'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('XTEA'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('XTEA'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('XTEA'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('XTEA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('XTEA'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher::XTEA->new($min_key)->blocksize, 8, 'XTEA->new()->blocksize');
is( Crypt::Cipher::XTEA->new($min_key)->keysize, 16, 'XTEA->new()->keysize');
is( Crypt::Cipher::XTEA->new($min_key)->max_keysize, 16, 'XTEA->new()->max_keysize');
is( Crypt::Cipher::XTEA->new($min_key)->min_keysize, 16, 'XTEA->new()->min_keysize');
is( Crypt::Cipher::XTEA->new($min_key)->default_rounds, 32, 'XTEA->new()->default_rounds');

is( Crypt::Cipher->new('XTEA', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('XTEA', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('XTEA', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('XTEA', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('XTEA', $min_key)->default_rounds, 32, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '29917be6d71868b4';
my $block_encrypted_max_key_hex = '6b5f7efad4270837';

is( unpack('H*', Crypt::Cipher::XTEA->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'XTEA->encrypt');
is( Crypt::Cipher::XTEA->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'XTEA->decrypt');

is( unpack('H*', Crypt::Cipher->new('XTEA', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('XTEA', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::XTEA->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'XTEA->encrypt');
is( Crypt::Cipher::XTEA->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'XTEA->decrypt');

is( unpack('H*', Crypt::Cipher->new('XTEA', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('XTEA', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

