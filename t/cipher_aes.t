### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::AES;

is( Crypt::Cipher::AES::blocksize, 16, '::blocksize');
is( Crypt::Cipher::AES::keysize, 32, '::keysize');
is( Crypt::Cipher::AES::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::AES::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::AES::default_rounds, 10, '::default_rounds');

is( Crypt::Cipher::AES->blocksize, 16, '->blocksize');
is( Crypt::Cipher::AES->keysize, 32, '->keysize');
is( Crypt::Cipher::AES->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::AES->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::AES->default_rounds, 10, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('AES'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('AES'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('AES'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('AES'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('AES'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('AES'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('AES'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('AES'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('AES'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('AES'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher::AES->new($min_key)->blocksize, 16, 'AES->new()->blocksize');
is( Crypt::Cipher::AES->new($min_key)->keysize, 32, 'AES->new()->keysize');
is( Crypt::Cipher::AES->new($min_key)->max_keysize, 32, 'AES->new()->max_keysize');
is( Crypt::Cipher::AES->new($min_key)->min_keysize, 16, 'AES->new()->min_keysize');
is( Crypt::Cipher::AES->new($min_key)->default_rounds, 10, 'AES->new()->default_rounds');

is( Crypt::Cipher->new('AES', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('AES', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('AES', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('AES', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('AES', $min_key)->default_rounds, 10, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '41920fa7d2902a858bb292e7a6605aba';
my $block_encrypted_max_key_hex = '42c97158e8bca4a7706e37138e4e2dbf';

is( unpack('H*', Crypt::Cipher::AES->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'AES->encrypt');
is( Crypt::Cipher::AES->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'AES->decrypt');

is( unpack('H*', Crypt::Cipher->new('AES', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('AES', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::AES->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'AES->encrypt');
is( Crypt::Cipher::AES->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'AES->decrypt');

is( unpack('H*', Crypt::Cipher->new('AES', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('AES', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

