### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Twofish;

is( Crypt::Cipher::Twofish::blocksize, 16, '::blocksize');
is( Crypt::Cipher::Twofish::keysize, 32, '::keysize');
is( Crypt::Cipher::Twofish::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::Twofish::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Twofish::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::Twofish->blocksize, 16, '->blocksize');
is( Crypt::Cipher::Twofish->keysize, 32, '->keysize');
is( Crypt::Cipher::Twofish->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::Twofish->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Twofish->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Twofish'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Twofish'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Twofish'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Twofish'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Twofish'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Twofish'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Twofish'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Twofish'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Twofish'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Twofish'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::Twofish->new($min_key)->blocksize, 16, 'Twofish->new()->blocksize');
is( Crypt::Cipher::Twofish->new($min_key)->keysize, 32, 'Twofish->new()->keysize');
is( Crypt::Cipher::Twofish->new($min_key)->max_keysize, 32, 'Twofish->new()->max_keysize');
is( Crypt::Cipher::Twofish->new($min_key)->min_keysize, 16, 'Twofish->new()->min_keysize');
is( Crypt::Cipher::Twofish->new($min_key)->default_rounds, 16, 'Twofish->new()->default_rounds');

is( Crypt::Cipher->new('Twofish', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Twofish', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Twofish', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Twofish', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Twofish', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '7fb9ade3245d2c1a230e03a94bcfb0ce';
my $block_encrypted_max_key_hex = '2ff825152c6b500a3bf53cb334626e65';

is( unpack('H*', Crypt::Cipher::Twofish->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Twofish->encrypt');
is( Crypt::Cipher::Twofish->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Twofish->decrypt');

is( unpack('H*', Crypt::Cipher->new('Twofish', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Twofish', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Twofish->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Twofish->encrypt');
is( Crypt::Cipher::Twofish->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Twofish->decrypt');

is( unpack('H*', Crypt::Cipher->new('Twofish', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Twofish', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

