### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::RC6;

is( Crypt::Cipher::RC6::blocksize, 16, '::blocksize');
is( Crypt::Cipher::RC6::keysize, 128, '::keysize');
is( Crypt::Cipher::RC6::max_keysize, 128, '::max_keysize');
is( Crypt::Cipher::RC6::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::RC6::default_rounds, 20, '::default_rounds');

is( Crypt::Cipher::RC6->blocksize, 16, '->blocksize');
is( Crypt::Cipher::RC6->keysize, 128, '->keysize');
is( Crypt::Cipher::RC6->max_keysize, 128, '->max_keysize');
is( Crypt::Cipher::RC6->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::RC6->default_rounds, 20, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('RC6'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('RC6'), 128, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('RC6'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('RC6'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('RC6'), 20, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('RC6'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('RC6'), 128, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('RC6'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('RC6'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('RC6'), 20, 'Cipher->default_rounds');

is( Crypt::Cipher::RC6->new($min_key)->blocksize, 16, 'RC6->new()->blocksize');
is( Crypt::Cipher::RC6->new($min_key)->keysize, 128, 'RC6->new()->keysize');
is( Crypt::Cipher::RC6->new($min_key)->max_keysize, 128, 'RC6->new()->max_keysize');
is( Crypt::Cipher::RC6->new($min_key)->min_keysize, 8, 'RC6->new()->min_keysize');
is( Crypt::Cipher::RC6->new($min_key)->default_rounds, 20, 'RC6->new()->default_rounds');

is( Crypt::Cipher->new('RC6', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('RC6', $min_key)->keysize, 128, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('RC6', $min_key)->max_keysize, 128, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('RC6', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('RC6', $min_key)->default_rounds, 20, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '404128633835b738252ba97d3f30e19a';
my $block_encrypted_max_key_hex = '626d64582f8c75ac21211cd15ca23f1e';

is( unpack('H*', Crypt::Cipher::RC6->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'RC6->encrypt');
is( Crypt::Cipher::RC6->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'RC6->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC6', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC6', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::RC6->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'RC6->encrypt');
is( Crypt::Cipher::RC6->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'RC6->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC6', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC6', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

