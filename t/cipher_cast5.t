### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::CAST5;

is( Crypt::Cipher::CAST5::blocksize, 8, '::blocksize');
is( Crypt::Cipher::CAST5::keysize, 16, '::keysize');
is( Crypt::Cipher::CAST5::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::CAST5::min_keysize, 5, '::min_keysize');
is( Crypt::Cipher::CAST5::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::CAST5->blocksize, 8, '->blocksize');
is( Crypt::Cipher::CAST5->keysize, 16, '->keysize');
is( Crypt::Cipher::CAST5->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::CAST5->min_keysize, 5, '->min_keysize');
is( Crypt::Cipher::CAST5->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('CAST5'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('CAST5'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('CAST5'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('CAST5'), 5, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('CAST5'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('CAST5'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('CAST5'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('CAST5'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('CAST5'), 5, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('CAST5'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::CAST5->new($min_key)->blocksize, 8, 'CAST5->new()->blocksize');
is( Crypt::Cipher::CAST5->new($min_key)->keysize, 16, 'CAST5->new()->keysize');
is( Crypt::Cipher::CAST5->new($min_key)->max_keysize, 16, 'CAST5->new()->max_keysize');
is( Crypt::Cipher::CAST5->new($min_key)->min_keysize, 5, 'CAST5->new()->min_keysize');
is( Crypt::Cipher::CAST5->new($min_key)->default_rounds, 16, 'CAST5->new()->default_rounds');

is( Crypt::Cipher->new('CAST5', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('CAST5', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('CAST5', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('CAST5', $min_key)->min_keysize, 5, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('CAST5', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '33eb97c2c524cebc';
my $block_encrypted_max_key_hex = 'aa493efb8bba2a45';

is( unpack('H*', Crypt::Cipher::CAST5->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'CAST5->encrypt');
is( Crypt::Cipher::CAST5->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'CAST5->decrypt');

is( unpack('H*', Crypt::Cipher->new('CAST5', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('CAST5', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::CAST5->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'CAST5->encrypt');
is( Crypt::Cipher::CAST5->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'CAST5->decrypt');

is( unpack('H*', Crypt::Cipher->new('CAST5', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('CAST5', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

