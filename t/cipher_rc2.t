### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::RC2;

is( Crypt::Cipher::RC2::blocksize, 8, '::blocksize');
is( Crypt::Cipher::RC2::keysize, 128, '::keysize');
is( Crypt::Cipher::RC2::max_keysize, 128, '::max_keysize');
is( Crypt::Cipher::RC2::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::RC2::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::RC2->blocksize, 8, '->blocksize');
is( Crypt::Cipher::RC2->keysize, 128, '->keysize');
is( Crypt::Cipher::RC2->max_keysize, 128, '->max_keysize');
is( Crypt::Cipher::RC2->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::RC2->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('RC2'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('RC2'), 128, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('RC2'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('RC2'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('RC2'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('RC2'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('RC2'), 128, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('RC2'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('RC2'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('RC2'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::RC2->new($min_key)->blocksize, 8, 'RC2->new()->blocksize');
is( Crypt::Cipher::RC2->new($min_key)->keysize, 128, 'RC2->new()->keysize');
is( Crypt::Cipher::RC2->new($min_key)->max_keysize, 128, 'RC2->new()->max_keysize');
is( Crypt::Cipher::RC2->new($min_key)->min_keysize, 8, 'RC2->new()->min_keysize');
is( Crypt::Cipher::RC2->new($min_key)->default_rounds, 16, 'RC2->new()->default_rounds');

is( Crypt::Cipher->new('RC2', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('RC2', $min_key)->keysize, 128, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('RC2', $min_key)->max_keysize, 128, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('RC2', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('RC2', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '63b6aed38ebea067';
my $block_encrypted_max_key_hex = '0579997e392f3d50';

is( unpack('H*', Crypt::Cipher::RC2->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'RC2->encrypt');
is( Crypt::Cipher::RC2->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'RC2->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC2', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC2', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::RC2->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'RC2->encrypt');
is( Crypt::Cipher::RC2->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'RC2->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC2', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC2', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

