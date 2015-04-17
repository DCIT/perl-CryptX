### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::SAFER_K128;

is( Crypt::Cipher::SAFER_K128::blocksize, 8, '::blocksize');
is( Crypt::Cipher::SAFER_K128::keysize, 16, '::keysize');
is( Crypt::Cipher::SAFER_K128::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::SAFER_K128::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::SAFER_K128::default_rounds, 10, '::default_rounds');

is( Crypt::Cipher::SAFER_K128->blocksize, 8, '->blocksize');
is( Crypt::Cipher::SAFER_K128->keysize, 16, '->keysize');
is( Crypt::Cipher::SAFER_K128->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::SAFER_K128->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::SAFER_K128->default_rounds, 10, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('SAFER_K128'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SAFER_K128'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SAFER_K128'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SAFER_K128'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SAFER_K128'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SAFER_K128'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SAFER_K128'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SAFER_K128'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SAFER_K128'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SAFER_K128'), 10, 'Cipher->default_rounds');

is( Crypt::Cipher::SAFER_K128->new($min_key)->blocksize, 8, 'SAFER_K128->new()->blocksize');
is( Crypt::Cipher::SAFER_K128->new($min_key)->keysize, 16, 'SAFER_K128->new()->keysize');
is( Crypt::Cipher::SAFER_K128->new($min_key)->max_keysize, 16, 'SAFER_K128->new()->max_keysize');
is( Crypt::Cipher::SAFER_K128->new($min_key)->min_keysize, 16, 'SAFER_K128->new()->min_keysize');
is( Crypt::Cipher::SAFER_K128->new($min_key)->default_rounds, 10, 'SAFER_K128->new()->default_rounds');

is( Crypt::Cipher->new('SAFER_K128', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SAFER_K128', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SAFER_K128', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SAFER_K128', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SAFER_K128', $min_key)->default_rounds, 10, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'e526bb4621fe70e3';
my $block_encrypted_max_key_hex = 'b932ad8042552f3e';

is( unpack('H*', Crypt::Cipher::SAFER_K128->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SAFER_K128->encrypt');
is( Crypt::Cipher::SAFER_K128->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SAFER_K128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K128', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K128', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SAFER_K128->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SAFER_K128->encrypt');
is( Crypt::Cipher::SAFER_K128->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SAFER_K128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K128', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K128', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSSSSSSSSSS';
my $spec_rounds = '11';
my $spec_block_encrypted_hex = '74874afc69ae6cd6';

is( unpack('H*', Crypt::Cipher::SAFER_K128->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'SAFER_K128->encrypt');
is( Crypt::Cipher::SAFER_K128->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'SAFER_K128->decrypt');

is( unpack('H*', Crypt::Cipher->new('SAFER_K128', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SAFER_K128', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
