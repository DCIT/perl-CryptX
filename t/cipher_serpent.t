### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Serpent;

is( Crypt::Cipher::Serpent::blocksize, 16, '::blocksize');
is( Crypt::Cipher::Serpent::keysize, 32, '::keysize');
is( Crypt::Cipher::Serpent::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::Serpent::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Serpent::default_rounds, 32, '::default_rounds');

is( Crypt::Cipher::Serpent->blocksize, 16, '->blocksize');
is( Crypt::Cipher::Serpent->keysize, 32, '->keysize');
is( Crypt::Cipher::Serpent->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::Serpent->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Serpent->default_rounds, 32, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Serpent'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Serpent'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Serpent'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Serpent'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Serpent'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Serpent'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Serpent'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Serpent'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Serpent'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Serpent'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher::Serpent->new($min_key)->blocksize, 16, 'Serpent->new()->blocksize');
is( Crypt::Cipher::Serpent->new($min_key)->keysize, 32, 'Serpent->new()->keysize');
is( Crypt::Cipher::Serpent->new($min_key)->max_keysize, 32, 'Serpent->new()->max_keysize');
is( Crypt::Cipher::Serpent->new($min_key)->min_keysize, 16, 'Serpent->new()->min_keysize');
is( Crypt::Cipher::Serpent->new($min_key)->default_rounds, 32, 'Serpent->new()->default_rounds');

is( Crypt::Cipher->new('Serpent', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Serpent', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Serpent', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Serpent', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Serpent', $min_key)->default_rounds, 32, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '094d7ab58dc7b85796ffe99969ddef9a';
my $block_encrypted_max_key_hex = '93b33ee7b88de79c6045e461552403f0';

is( unpack('H*', Crypt::Cipher::Serpent->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Serpent->encrypt');
is( Crypt::Cipher::Serpent->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Serpent->decrypt');

is( unpack('H*', Crypt::Cipher->new('Serpent', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Serpent', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Serpent->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Serpent->encrypt');
is( Crypt::Cipher::Serpent->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Serpent->decrypt');

is( unpack('H*', Crypt::Cipher->new('Serpent', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Serpent', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

