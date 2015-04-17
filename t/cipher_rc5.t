### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 42;

use Crypt::Cipher;
use Crypt::Cipher::RC5;

is( Crypt::Cipher::RC5::blocksize, 8, '::blocksize');
is( Crypt::Cipher::RC5::keysize, 128, '::keysize');
is( Crypt::Cipher::RC5::max_keysize, 128, '::max_keysize');
is( Crypt::Cipher::RC5::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::RC5::default_rounds, 12, '::default_rounds');

is( Crypt::Cipher::RC5->blocksize, 8, '->blocksize');
is( Crypt::Cipher::RC5->keysize, 128, '->keysize');
is( Crypt::Cipher::RC5->max_keysize, 128, '->max_keysize');
is( Crypt::Cipher::RC5->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::RC5->default_rounds, 12, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('RC5'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('RC5'), 128, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('RC5'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('RC5'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('RC5'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('RC5'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('RC5'), 128, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('RC5'), 128, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('RC5'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('RC5'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher::RC5->new($min_key)->blocksize, 8, 'RC5->new()->blocksize');
is( Crypt::Cipher::RC5->new($min_key)->keysize, 128, 'RC5->new()->keysize');
is( Crypt::Cipher::RC5->new($min_key)->max_keysize, 128, 'RC5->new()->max_keysize');
is( Crypt::Cipher::RC5->new($min_key)->min_keysize, 8, 'RC5->new()->min_keysize');
is( Crypt::Cipher::RC5->new($min_key)->default_rounds, 12, 'RC5->new()->default_rounds');

is( Crypt::Cipher->new('RC5', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('RC5', $min_key)->keysize, 128, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('RC5', $min_key)->max_keysize, 128, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('RC5', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('RC5', $min_key)->default_rounds, 12, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '7c6231e94d317190';
my $block_encrypted_max_key_hex = '94ffb45366bd4dda';

is( unpack('H*', Crypt::Cipher::RC5->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'RC5->encrypt');
is( Crypt::Cipher::RC5->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'RC5->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC5', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC5', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::RC5->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'RC5->encrypt');
is( Crypt::Cipher::RC5->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'RC5->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC5', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC5', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


my $spec_key = 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS';
my $spec_rounds = '19';
my $spec_block_encrypted_hex = 'a7ef4525157fb4e6';

is( unpack('H*', Crypt::Cipher::RC5->new($spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'RC5->encrypt');
is( Crypt::Cipher::RC5->new($spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'RC5->decrypt');

is( unpack('H*', Crypt::Cipher->new('RC5', $spec_key, $spec_rounds)->encrypt($block_plain)), $spec_block_encrypted_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('RC5', $spec_key, $spec_rounds)->decrypt(pack('H*', $spec_block_encrypted_hex)), $block_plain, 'Cipher->decrypt');
