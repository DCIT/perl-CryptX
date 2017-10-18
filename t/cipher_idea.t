### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::IDEA;

is( Crypt::Cipher::IDEA::blocksize, 8, '::blocksize');
is( Crypt::Cipher::IDEA::keysize, 16, '::keysize');
is( Crypt::Cipher::IDEA::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::IDEA::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::IDEA::default_rounds, 8, '::default_rounds');

is( Crypt::Cipher::IDEA->blocksize, 8, '->blocksize');
is( Crypt::Cipher::IDEA->keysize, 16, '->keysize');
is( Crypt::Cipher::IDEA->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::IDEA->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::IDEA->default_rounds, 8, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('IDEA'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('IDEA'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('IDEA'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('IDEA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('IDEA'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('IDEA'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('IDEA'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('IDEA'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('IDEA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('IDEA'), 8, 'Cipher->default_rounds');

is( Crypt::Cipher::IDEA->new($min_key)->blocksize, 8, 'IDEA->new()->blocksize');
is( Crypt::Cipher::IDEA->new($min_key)->keysize, 16, 'IDEA->new()->keysize');
is( Crypt::Cipher::IDEA->new($min_key)->max_keysize, 16, 'IDEA->new()->max_keysize');
is( Crypt::Cipher::IDEA->new($min_key)->min_keysize, 16, 'IDEA->new()->min_keysize');
is( Crypt::Cipher::IDEA->new($min_key)->default_rounds, 8, 'IDEA->new()->default_rounds');

is( Crypt::Cipher->new('IDEA', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('IDEA', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('IDEA', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('IDEA', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('IDEA', $min_key)->default_rounds, 8, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = '02bb362ef47743bc';
my $block_encrypted_max_key_hex = '041aa0caeb50668f';

is( unpack('H*', Crypt::Cipher::IDEA->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'IDEA->encrypt');
is( Crypt::Cipher::IDEA->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'IDEA->decrypt');

is( unpack('H*', Crypt::Cipher->new('IDEA', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('IDEA', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::IDEA->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'IDEA->encrypt');
is( Crypt::Cipher::IDEA->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'IDEA->decrypt');

is( unpack('H*', Crypt::Cipher->new('IDEA', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('IDEA', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

