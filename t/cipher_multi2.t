### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::MULTI2;

is( Crypt::Cipher::MULTI2::blocksize, 8, '::blocksize');
is( Crypt::Cipher::MULTI2::keysize, 40, '::keysize');
is( Crypt::Cipher::MULTI2::max_keysize, 40, '::max_keysize');
is( Crypt::Cipher::MULTI2::min_keysize, 40, '::min_keysize');
is( Crypt::Cipher::MULTI2::default_rounds, 128, '::default_rounds');

is( Crypt::Cipher::MULTI2->blocksize, 8, '->blocksize');
is( Crypt::Cipher::MULTI2->keysize, 40, '->keysize');
is( Crypt::Cipher::MULTI2->max_keysize, 40, '->max_keysize');
is( Crypt::Cipher::MULTI2->min_keysize, 40, '->min_keysize');
is( Crypt::Cipher::MULTI2->default_rounds, 128, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('MULTI2'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('MULTI2'), 40, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('MULTI2'), 40, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('MULTI2'), 40, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('MULTI2'), 128, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('MULTI2'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('MULTI2'), 40, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('MULTI2'), 40, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('MULTI2'), 40, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('MULTI2'), 128, 'Cipher->default_rounds');

is( Crypt::Cipher::MULTI2->new($min_key)->blocksize, 8, 'MULTI2->new()->blocksize');
is( Crypt::Cipher::MULTI2->new($min_key)->keysize, 40, 'MULTI2->new()->keysize');
is( Crypt::Cipher::MULTI2->new($min_key)->max_keysize, 40, 'MULTI2->new()->max_keysize');
is( Crypt::Cipher::MULTI2->new($min_key)->min_keysize, 40, 'MULTI2->new()->min_keysize');
is( Crypt::Cipher::MULTI2->new($min_key)->default_rounds, 128, 'MULTI2->new()->default_rounds');

is( Crypt::Cipher->new('MULTI2', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('MULTI2', $min_key)->keysize, 40, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('MULTI2', $min_key)->max_keysize, 40, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('MULTI2', $min_key)->min_keysize, 40, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('MULTI2', $min_key)->default_rounds, 128, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '321f187e9d9810aa';
my $block_encrypted_max_key_hex = '435923e078988203';

is( unpack('H*', Crypt::Cipher::MULTI2->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'MULTI2->encrypt');
is( Crypt::Cipher::MULTI2->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'MULTI2->decrypt');

is( unpack('H*', Crypt::Cipher->new('MULTI2', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('MULTI2', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::MULTI2->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'MULTI2->encrypt');
is( Crypt::Cipher::MULTI2->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'MULTI2->decrypt');

is( unpack('H*', Crypt::Cipher->new('MULTI2', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('MULTI2', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS';
my $spec_rounds = '199';
my $spec_block_encrypted_hex = 'ec944aa441dac52b';

is( unpack('H*', Crypt::Cipher::MULTI2->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'MULTI2->encrypt');
is( Crypt::Cipher::MULTI2->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'MULTI2->decrypt');

is( unpack('H*', Crypt::Cipher->new('MULTI2', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('MULTI2', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
