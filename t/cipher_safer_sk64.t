### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::SAFER_SK64;

is( Crypt::Cipher::SAFER_SK64::blocksize, 8, '::blocksize');
is( Crypt::Cipher::SAFER_SK64::keysize, 8, '::keysize');
is( Crypt::Cipher::SAFER_SK64::max_keysize, 8, '::max_keysize');
is( Crypt::Cipher::SAFER_SK64::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::SAFER_SK64::default_rounds, 8, '::default_rounds');

is( Crypt::Cipher::SAFER_SK64->blocksize, 8, '->blocksize');
is( Crypt::Cipher::SAFER_SK64->keysize, 8, '->keysize');
is( Crypt::Cipher::SAFER_SK64->max_keysize, 8, '->max_keysize');
is( Crypt::Cipher::SAFER_SK64->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::SAFER_SK64->default_rounds, 8, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKK';

is( Crypt::Cipher::blocksize('SAFER_SK64'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SAFER_SK64'), 8, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SAFER_SK64'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SAFER_SK64'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SAFER_SK64'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SAFER_SK64'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SAFER_SK64'), 8, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SAFER_SK64'), 8, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SAFER_SK64'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SAFER_SK64'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher::SAFER_SK64->new($min_key)->blocksize, 8, 'SAFER_SK64->new()->blocksize');
is( Crypt::Cipher::SAFER_SK64->new($min_key)->keysize, 8, 'SAFER_SK64->new()->keysize');
is( Crypt::Cipher::SAFER_SK64->new($min_key)->max_keysize, 8, 'SAFER_SK64->new()->max_keysize');
is( Crypt::Cipher::SAFER_SK64->new($min_key)->min_keysize, 8, 'SAFER_SK64->new()->min_keysize');
is( Crypt::Cipher::SAFER_SK64->new($min_key)->default_rounds, 8, 'SAFER_SK64->new()->default_rounds');

is( Crypt::Cipher->new('SAFER_SK64', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SAFER_SK64', $min_key)->keysize, 8, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SAFER_SK64', $min_key)->max_keysize, 8, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SAFER_SK64', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SAFER_SK64', $min_key)->default_rounds, 8, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '639b30226c23e91f';
my $block_encrypted_max_key_hex = 'd41cceb6c422eb99';

is( unpack('H*', Crypt::Cipher::SAFER_SK64->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SAFER_SK64->encrypt');
is( Crypt::Cipher::SAFER_SK64->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SAFER_SK64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK64', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK64', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SAFER_SK64->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SAFER_SK64->encrypt');
is( Crypt::Cipher::SAFER_SK64->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SAFER_SK64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK64', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK64', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSS';
my $spec_rounds = '9';
my $spec_block_encrypted_hex = '5f8826052c1202ab';

is( unpack('H*', Crypt::Cipher::SAFER_SK64->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'SAFER_SK64->encrypt');
is( Crypt::Cipher::SAFER_SK64->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'SAFER_SK64->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_SK64', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_SK64', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
