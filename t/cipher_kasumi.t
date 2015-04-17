### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::KASUMI;

is( Crypt::Cipher::KASUMI::blocksize, 8, '::blocksize');
is( Crypt::Cipher::KASUMI::keysize, 16, '::keysize');
is( Crypt::Cipher::KASUMI::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::KASUMI::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::KASUMI::default_rounds, 8, '::default_rounds');

is( Crypt::Cipher::KASUMI->blocksize, 8, '->blocksize');
is( Crypt::Cipher::KASUMI->keysize, 16, '->keysize');
is( Crypt::Cipher::KASUMI->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::KASUMI->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::KASUMI->default_rounds, 8, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('KASUMI'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('KASUMI'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('KASUMI'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('KASUMI'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('KASUMI'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('KASUMI'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('KASUMI'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('KASUMI'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('KASUMI'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('KASUMI'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher::KASUMI->new($min_key)->blocksize, 8, 'KASUMI->new()->blocksize');
is( Crypt::Cipher::KASUMI->new($min_key)->keysize, 16, 'KASUMI->new()->keysize');
is( Crypt::Cipher::KASUMI->new($min_key)->max_keysize, 16, 'KASUMI->new()->max_keysize');
is( Crypt::Cipher::KASUMI->new($min_key)->min_keysize, 16, 'KASUMI->new()->min_keysize');
is( Crypt::Cipher::KASUMI->new($min_key)->default_rounds, 8, 'KASUMI->new()->default_rounds');

is( Crypt::Cipher->new('KASUMI', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('KASUMI', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('KASUMI', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('KASUMI', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('KASUMI', $min_key)->default_rounds, 8, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '01882ff16cfff4f5';
my $block_encrypted_max_key_hex = '748aeb4153b38bf2';

is( unpack('H*', Crypt::Cipher::KASUMI->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'KASUMI->encrypt');
is( Crypt::Cipher::KASUMI->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'KASUMI->decrypt');

is( unpack('H*', Crypt::Cipher->new('KASUMI', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('KASUMI', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::KASUMI->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'KASUMI->encrypt');
is( Crypt::Cipher::KASUMI->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'KASUMI->decrypt');

is( unpack('H*', Crypt::Cipher->new('KASUMI', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('KASUMI', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

