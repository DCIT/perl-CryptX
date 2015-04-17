### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Skipjack;

is( Crypt::Cipher::Skipjack::blocksize, 8, '::blocksize');
is( Crypt::Cipher::Skipjack::keysize, 10, '::keysize');
is( Crypt::Cipher::Skipjack::max_keysize, 10, '::max_keysize');
is( Crypt::Cipher::Skipjack::min_keysize, 10, '::min_keysize');
is( Crypt::Cipher::Skipjack::default_rounds, 32, '::default_rounds');

is( Crypt::Cipher::Skipjack->blocksize, 8, '->blocksize');
is( Crypt::Cipher::Skipjack->keysize, 10, '->keysize');
is( Crypt::Cipher::Skipjack->max_keysize, 10, '->max_keysize');
is( Crypt::Cipher::Skipjack->min_keysize, 10, '->min_keysize');
is( Crypt::Cipher::Skipjack->default_rounds, 32, '->default_rounds');

my $min_key = 'kkkkkkkkkk';
my $max_key = 'KKKKKKKKKK';

is( Crypt::Cipher::blocksize('Skipjack'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Skipjack'), 10, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Skipjack'), 10, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Skipjack'), 10, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Skipjack'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Skipjack'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Skipjack'), 10, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Skipjack'), 10, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Skipjack'), 10, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Skipjack'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher::Skipjack->new($min_key)->blocksize, 8, 'Skipjack->new()->blocksize');
is( Crypt::Cipher::Skipjack->new($min_key)->keysize, 10, 'Skipjack->new()->keysize');
is( Crypt::Cipher::Skipjack->new($min_key)->max_keysize, 10, 'Skipjack->new()->max_keysize');
is( Crypt::Cipher::Skipjack->new($min_key)->min_keysize, 10, 'Skipjack->new()->min_keysize');
is( Crypt::Cipher::Skipjack->new($min_key)->default_rounds, 32, 'Skipjack->new()->default_rounds');

is( Crypt::Cipher->new('Skipjack', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Skipjack', $min_key)->keysize, 10, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Skipjack', $min_key)->max_keysize, 10, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Skipjack', $min_key)->min_keysize, 10, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Skipjack', $min_key)->default_rounds, 32, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'c3341aa246606dec';
my $block_encrypted_max_key_hex = 'bcad31948086062d';

is( unpack('H*', Crypt::Cipher::Skipjack->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Skipjack->encrypt');
is( Crypt::Cipher::Skipjack->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Skipjack->decrypt');

is( unpack('H*', Crypt::Cipher->new('Skipjack', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Skipjack', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Skipjack->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Skipjack->encrypt');
is( Crypt::Cipher::Skipjack->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Skipjack->decrypt');

is( unpack('H*', Crypt::Cipher->new('Skipjack', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Skipjack', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

