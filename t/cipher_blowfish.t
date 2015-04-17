### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Blowfish;

is( Crypt::Cipher::Blowfish::blocksize, 8, '::blocksize');
is( Crypt::Cipher::Blowfish::keysize, 56, '::keysize');
is( Crypt::Cipher::Blowfish::max_keysize, 56, '::max_keysize');
is( Crypt::Cipher::Blowfish::min_keysize, 8, '::min_keysize');
is( Crypt::Cipher::Blowfish::default_rounds, 16, '::default_rounds');

is( Crypt::Cipher::Blowfish->blocksize, 8, '->blocksize');
is( Crypt::Cipher::Blowfish->keysize, 56, '->keysize');
is( Crypt::Cipher::Blowfish->max_keysize, 56, '->max_keysize');
is( Crypt::Cipher::Blowfish->min_keysize, 8, '->min_keysize');
is( Crypt::Cipher::Blowfish->default_rounds, 16, '->default_rounds');

my $min_key = 'kkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Blowfish'), 8, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Blowfish'), 56, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Blowfish'), 56, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Blowfish'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Blowfish'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Blowfish'), 8, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Blowfish'), 56, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Blowfish'), 56, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Blowfish'), 8, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Blowfish'), 16, 'Cipher->default_rounds');

is( Crypt::Cipher::Blowfish->new($min_key)->blocksize, 8, 'Blowfish->new()->blocksize');
is( Crypt::Cipher::Blowfish->new($min_key)->keysize, 56, 'Blowfish->new()->keysize');
is( Crypt::Cipher::Blowfish->new($min_key)->max_keysize, 56, 'Blowfish->new()->max_keysize');
is( Crypt::Cipher::Blowfish->new($min_key)->min_keysize, 8, 'Blowfish->new()->min_keysize');
is( Crypt::Cipher::Blowfish->new($min_key)->default_rounds, 16, 'Blowfish->new()->default_rounds');

is( Crypt::Cipher->new('Blowfish', $min_key)->blocksize, 8, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Blowfish', $min_key)->keysize, 56, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Blowfish', $min_key)->max_keysize, 56, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Blowfish', $min_key)->min_keysize, 8, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Blowfish', $min_key)->default_rounds, 16, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBB';
my $block_encrypted_min_key_hex = 'b224e1799d6e0f7d';
my $block_encrypted_max_key_hex = 'd060619385d48889';

is( unpack('H*', Crypt::Cipher::Blowfish->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Blowfish->encrypt');
is( Crypt::Cipher::Blowfish->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Blowfish->decrypt');

is( unpack('H*', Crypt::Cipher->new('Blowfish', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Blowfish', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Blowfish->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Blowfish->encrypt');
is( Crypt::Cipher::Blowfish->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Blowfish->decrypt');

is( unpack('H*', Crypt::Cipher->new('Blowfish', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Blowfish', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

