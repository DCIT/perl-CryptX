### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::DES_EDE;

is( Crypt::Cipher::DES_EDE::blocksize, 8, '::blocksize');
is( Crypt::Cipher::DES_EDE::keysize, 24, '::keysize');
is( Crypt::Cipher::DES_EDE::max_keysize, 24, '::max_keysize');
is( Crypt::Cipher::DES_EDE::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::DES_EDE::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::DES_EDE->blocksize, 8, '->blocksize');
is( Crypt::Cipher::DES_EDE->keysize, 24, '->keysize');
is( Crypt::Cipher::DES_EDE->max_keysize, 24, '->max_keysize');
is( Crypt::Cipher::DES_EDE->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::DES_EDE->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('DES_EDE'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('DES_EDE'), 24, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('DES_EDE'), 24, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('DES_EDE'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('DES_EDE'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('DES_EDE'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('DES_EDE'), 24, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('DES_EDE'), 24, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('DES_EDE'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('DES_EDE'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::DES_EDE->new($min_key)->blocksize, 8, 'DES_EDE->new()->blocksize');
is( Crypt::Cipher::DES_EDE->new($min_key)->keysize, 24, 'DES_EDE->new()->keysize');
is( Crypt::Cipher::DES_EDE->new($min_key)->max_keysize, 24, 'DES_EDE->new()->max_keysize');
is( Crypt::Cipher::DES_EDE->new($min_key)->min_keysize, 16, 'DES_EDE->new()->min_keysize');
is( Crypt::Cipher::DES_EDE->new($min_key)->default_rounds, 16, 'DES_EDE->new()->default_rounds');

is( Crypt::Cipher->new('DES_EDE', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('DES_EDE', $min_key)->keysize, 24, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('DES_EDE', $min_key)->max_keysize, 24, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('DES_EDE', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('DES_EDE', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'dc58fab575ba33d8';
my $block_encrypted_max_key_hex = 'c6b60209d8ef7379';

is( unpack('H*', Crypt::Cipher::DES_EDE->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'DES_EDE->encrypt');
is( Crypt::Cipher::DES_EDE->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'DES_EDE->decrypt');

is( unpack('H*', Crypt::Cipher->new('DES_EDE', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('DES_EDE', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::DES_EDE->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'DES_EDE->encrypt');
is( Crypt::Cipher::DES_EDE->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'DES_EDE->decrypt');

is( unpack('H*', Crypt::Cipher->new('DES_EDE', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('DES_EDE', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

