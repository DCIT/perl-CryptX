### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::SEED;

is( Crypt::Cipher::SEED::blocksize, 16, '::blocksize');
is( Crypt::Cipher::SEED::keysize, 16, '::keysize');
is( Crypt::Cipher::SEED::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::SEED::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::SEED::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::SEED->blocksize, 16, '->blocksize');
is( Crypt::Cipher::SEED->keysize, 16, '->keysize');
is( Crypt::Cipher::SEED->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::SEED->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::SEED->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('SEED'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SEED'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SEED'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SEED'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SEED'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SEED'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SEED'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SEED'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SEED'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SEED'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::SEED->new($min_key)->blocksize, 16, 'SEED->new()->blocksize');
is( Crypt::Cipher::SEED->new($min_key)->keysize, 16, 'SEED->new()->keysize');
is( Crypt::Cipher::SEED->new($min_key)->max_keysize, 16, 'SEED->new()->max_keysize');
is( Crypt::Cipher::SEED->new($min_key)->min_keysize, 16, 'SEED->new()->min_keysize');
is( Crypt::Cipher::SEED->new($min_key)->default_rounds, 16, 'SEED->new()->default_rounds');

is( Crypt::Cipher->new('SEED', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SEED', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SEED', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SEED', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SEED', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '64f1614aeda40bc2943a13b1c4c93fa4';
my $block_encrypted_max_key_hex = '4cebfb51827596091fd3ee4e5923bd05';

is( unpack('H*', Crypt::Cipher::SEED->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SEED->encrypt');
is( Crypt::Cipher::SEED->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SEED->decrypt');

is( unpack('H*', Crypt::Cipher->new('SEED', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SEED', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SEED->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SEED->encrypt');
is( Crypt::Cipher::SEED->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SEED->decrypt');

is( unpack('H*', Crypt::Cipher->new('SEED', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SEED', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

