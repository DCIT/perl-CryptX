### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Khazad;

is( Crypt::Cipher::Khazad::blocksize, 8, '::blocksize');
is( Crypt::Cipher::Khazad::keysize, 16, '::keysize');
is( Crypt::Cipher::Khazad::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::Khazad::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Khazad::default_rounds, 8, '::default_rounds');

is( Crypt::Cipher::Khazad->blocksize, 8, '->blocksize');
is( Crypt::Cipher::Khazad->keysize, 16, '->keysize');
is( Crypt::Cipher::Khazad->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::Khazad->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Khazad->default_rounds, 8, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Khazad'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Khazad'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Khazad'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Khazad'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Khazad'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Khazad'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Khazad'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Khazad'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Khazad'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Khazad'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher::Khazad->new($min_key)->blocksize, 8, 'Khazad->new()->blocksize');
is( Crypt::Cipher::Khazad->new($min_key)->keysize, 16, 'Khazad->new()->keysize');
is( Crypt::Cipher::Khazad->new($min_key)->max_keysize, 16, 'Khazad->new()->max_keysize');
is( Crypt::Cipher::Khazad->new($min_key)->min_keysize, 16, 'Khazad->new()->min_keysize');
is( Crypt::Cipher::Khazad->new($min_key)->default_rounds, 8, 'Khazad->new()->default_rounds');

is( Crypt::Cipher->new('Khazad', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Khazad', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Khazad', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Khazad', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Khazad', $min_key)->default_rounds, 8, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '8c686199eeb0100a';
my $block_encrypted_max_key_hex = '0e9815a0167dd474';

is( unpack('H*', Crypt::Cipher::Khazad->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Khazad->encrypt');
is( Crypt::Cipher::Khazad->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Khazad->decrypt');

is( unpack('H*', Crypt::Cipher->new('Khazad', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Khazad', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Khazad->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Khazad->encrypt');
is( Crypt::Cipher::Khazad->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Khazad->decrypt');

is( unpack('H*', Crypt::Cipher->new('Khazad', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Khazad', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

