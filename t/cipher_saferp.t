### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::SAFERP;

is( Crypt::Cipher::SAFERP::blocksize, 16, '::blocksize');
is( Crypt::Cipher::SAFERP::keysize, 32, '::keysize');
is( Crypt::Cipher::SAFERP::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::SAFERP::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::SAFERP::default_rounds, 8, '::default_rounds');

is( Crypt::Cipher::SAFERP->blocksize, 16, '->blocksize');
is( Crypt::Cipher::SAFERP->keysize, 32, '->keysize');
is( Crypt::Cipher::SAFERP->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::SAFERP->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::SAFERP->default_rounds, 8, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('SAFERP'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SAFERP'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SAFERP'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SAFERP'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SAFERP'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SAFERP'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SAFERP'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SAFERP'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SAFERP'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SAFERP'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher::SAFERP->new($min_key)->blocksize, 16, 'SAFERP->new()->blocksize');
is( Crypt::Cipher::SAFERP->new($min_key)->keysize, 32, 'SAFERP->new()->keysize');
is( Crypt::Cipher::SAFERP->new($min_key)->max_keysize, 32, 'SAFERP->new()->max_keysize');
is( Crypt::Cipher::SAFERP->new($min_key)->min_keysize, 16, 'SAFERP->new()->min_keysize');
is( Crypt::Cipher::SAFERP->new($min_key)->default_rounds, 8, 'SAFERP->new()->default_rounds');

is( Crypt::Cipher->new('SAFERP', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SAFERP', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SAFERP', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SAFERP', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SAFERP', $min_key)->default_rounds, 8, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = 'ca40dc929ecb6cd6d8c193f2008b7b0f';
my $block_encrypted_max_key_hex = 'd4c5aea977b9545517f451d84c3c0b31';

is( unpack('H*', Crypt::Cipher::SAFERP->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SAFERP->encrypt');
is( Crypt::Cipher::SAFERP->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SAFERP->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFERP', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFERP', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SAFERP->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SAFERP->encrypt');
is( Crypt::Cipher::SAFERP->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SAFERP->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFERP', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFERP', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

