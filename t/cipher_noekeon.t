### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Noekeon;

is( Crypt::Cipher::Noekeon::blocksize, 16, '::blocksize');
is( Crypt::Cipher::Noekeon::keysize, 16, '::keysize');
is( Crypt::Cipher::Noekeon::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::Noekeon::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Noekeon::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::Noekeon->blocksize, 16, '->blocksize');
is( Crypt::Cipher::Noekeon->keysize, 16, '->keysize');
is( Crypt::Cipher::Noekeon->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::Noekeon->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Noekeon->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Noekeon'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Noekeon'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Noekeon'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Noekeon'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Noekeon'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Noekeon'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Noekeon'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Noekeon'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Noekeon'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Noekeon'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::Noekeon->new($min_key)->blocksize, 16, 'Noekeon->new()->blocksize');
is( Crypt::Cipher::Noekeon->new($min_key)->keysize, 16, 'Noekeon->new()->keysize');
is( Crypt::Cipher::Noekeon->new($min_key)->max_keysize, 16, 'Noekeon->new()->max_keysize');
is( Crypt::Cipher::Noekeon->new($min_key)->min_keysize, 16, 'Noekeon->new()->min_keysize');
is( Crypt::Cipher::Noekeon->new($min_key)->default_rounds, 16, 'Noekeon->new()->default_rounds');

is( Crypt::Cipher->new('Noekeon', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Noekeon', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Noekeon', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Noekeon', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Noekeon', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = 'e0d99f05c90e974bc6d8d0740e0dee44';
my $block_encrypted_max_key_hex = '67220154141a0c32d92cb080df1fb081';

is( unpack('H*', Crypt::Cipher::Noekeon->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Noekeon->encrypt');
is( Crypt::Cipher::Noekeon->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Noekeon->decrypt');

is( unpack('H*', Crypt::Cipher->new('Noekeon', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Noekeon', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Noekeon->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Noekeon->encrypt');
is( Crypt::Cipher::Noekeon->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Noekeon->decrypt');

is( unpack('H*', Crypt::Cipher->new('Noekeon', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Noekeon', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

