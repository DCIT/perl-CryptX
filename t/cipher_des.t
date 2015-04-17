### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::DES;

is( Crypt::Cipher::DES::blocksize, 8, '::blocksize');
is( Crypt::Cipher::DES::keysize, 8, '::keysize');
is( Crypt::Cipher::DES::max_keysize, 8, '::max_keysize');
is( Crypt::Cipher::DES::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::DES::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::DES->blocksize, 8, '->blocksize');
is( Crypt::Cipher::DES->keysize, 8, '->keysize');
is( Crypt::Cipher::DES->max_keysize, 8, '->max_keysize');
is( Crypt::Cipher::DES->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::DES->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKK';

is( Crypt::Cipher::blocksize('DES'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('DES'), 8, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('DES'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('DES'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('DES'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('DES'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('DES'), 8, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('DES'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('DES'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('DES'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::DES->new($min_key)->blocksize, 8, 'DES->new()->blocksize');
is( Crypt::Cipher::DES->new($min_key)->keysize, 8, 'DES->new()->keysize');
is( Crypt::Cipher::DES->new($min_key)->max_keysize, 8, 'DES->new()->max_keysize');
is( Crypt::Cipher::DES->new($min_key)->min_keysize, 8, 'DES->new()->min_keysize');
is( Crypt::Cipher::DES->new($min_key)->default_rounds, 16, 'DES->new()->default_rounds');

is( Crypt::Cipher->new('DES', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('DES', $min_key)->keysize, 8, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('DES', $min_key)->max_keysize, 8, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('DES', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('DES', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'dc58fab575ba33d8';
my $block_encrypted_max_key_hex = 'c6b60209d8ef7379';

is( unpack('H*', Crypt::Cipher::DES->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'DES->encrypt');
is( Crypt::Cipher::DES->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'DES->decrypt');

is( unpack('H*', Crypt::Cipher->new('DES', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('DES', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::DES->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'DES->encrypt');
is( Crypt::Cipher::DES->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'DES->decrypt');

is( unpack('H*', Crypt::Cipher->new('DES', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('DES', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

