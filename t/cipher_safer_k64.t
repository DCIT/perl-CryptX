### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::SAFER_K64;

is( Crypt::Cipher::SAFER_K64::blocksize, 8, '::blocksize');
is( Crypt::Cipher::SAFER_K64::keysize, 8, '::keysize');
is( Crypt::Cipher::SAFER_K64::max_keysize, 8, '::max_keysize');
is( Crypt::Cipher::SAFER_K64::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::SAFER_K64::default_rounds, 6, '::default_rounds');

is( Crypt::Cipher::SAFER_K64->blocksize, 8, '->blocksize');
is( Crypt::Cipher::SAFER_K64->keysize, 8, '->keysize');
is( Crypt::Cipher::SAFER_K64->max_keysize, 8, '->max_keysize');
is( Crypt::Cipher::SAFER_K64->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::SAFER_K64->default_rounds, 6, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKK';

is( Crypt::Cipher::blocksize('SAFER_K64'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SAFER_K64'), 8, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SAFER_K64'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SAFER_K64'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SAFER_K64'), 6, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SAFER_K64'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SAFER_K64'), 8, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SAFER_K64'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SAFER_K64'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SAFER_K64'), 6, 'Cipher->default_rounds');

is( Crypt::Cipher::SAFER_K64->new($min_key)->blocksize, 8, 'SAFER_K64->new()->blocksize');
is( Crypt::Cipher::SAFER_K64->new($min_key)->keysize, 8, 'SAFER_K64->new()->keysize');
is( Crypt::Cipher::SAFER_K64->new($min_key)->max_keysize, 8, 'SAFER_K64->new()->max_keysize');
is( Crypt::Cipher::SAFER_K64->new($min_key)->min_keysize, 8, 'SAFER_K64->new()->min_keysize');
is( Crypt::Cipher::SAFER_K64->new($min_key)->default_rounds, 6, 'SAFER_K64->new()->default_rounds');

is( Crypt::Cipher->new('SAFER_K64', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SAFER_K64', $min_key)->keysize, 8, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SAFER_K64', $min_key)->max_keysize, 8, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SAFER_K64', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SAFER_K64', $min_key)->default_rounds, 6, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '7d24754eca0a4f1d';
my $block_encrypted_max_key_hex = '89ea357f69ed7c27';

is( unpack('H*', Crypt::Cipher::SAFER_K64->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SAFER_K64->encrypt');
is( Crypt::Cipher::SAFER_K64->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SAFER_K64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K64', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K64', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SAFER_K64->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SAFER_K64->encrypt');
is( Crypt::Cipher::SAFER_K64->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SAFER_K64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K64', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K64', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSS';
my $spec_rounds = '9';
my $spec_block_encrypted_hex = 'b501503f773d146e';

is( unpack('H*', Crypt::Cipher::SAFER_K64->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'SAFER_K64->encrypt');
is( Crypt::Cipher::SAFER_K64->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'SAFER_K64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K64', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K64', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
