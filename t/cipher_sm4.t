### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 39;

use Crypt::Cipher;
use Crypt::Cipher::SM4;

is( Crypt::Cipher::SM4::blocksize, 16, '::blocksize');
is( Crypt::Cipher::SM4::keysize, 16, '::keysize');
is( Crypt::Cipher::SM4::max_keysize, 16, '::max_keysize');
is( Crypt::Cipher::SM4::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::SM4::default_rounds, 32, '::default_rounds');

is( Crypt::Cipher::SM4->blocksize, 16, '->blocksize');
is( Crypt::Cipher::SM4->keysize, 16, '->keysize');
is( Crypt::Cipher::SM4->max_keysize, 16, '->max_keysize');
is( Crypt::Cipher::SM4->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::SM4->default_rounds, 32, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKK';

ok(Crypt::Cipher::SM4->new($min_key)->isa('Crypt::Cipher::SM4'), 'SM4->new returns subclass instance');

is( Crypt::Cipher::blocksize('SM4'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('SM4'), 16, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('SM4'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('SM4'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('SM4'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('SM4'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('SM4'), 16, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('SM4'), 16, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('SM4'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('SM4'), 32, 'Cipher->default_rounds');

is( Crypt::Cipher::SM4->new($min_key)->blocksize, 16, 'SM4->new()->blocksize');
is( Crypt::Cipher::SM4->new($min_key)->keysize, 16, 'SM4->new()->keysize');
is( Crypt::Cipher::SM4->new($min_key)->max_keysize, 16, 'SM4->new()->max_keysize');
is( Crypt::Cipher::SM4->new($min_key)->min_keysize, 16, 'SM4->new()->min_keysize');
is( Crypt::Cipher::SM4->new($min_key)->default_rounds, 32, 'SM4->new()->default_rounds');

is( Crypt::Cipher->new('SM4', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('SM4', $min_key)->keysize, 16, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('SM4', $min_key)->max_keysize, 16, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('SM4', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('SM4', $min_key)->default_rounds, 32, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = '379eedede55b2a70d01d9f957bacd263';
my $block_encrypted_max_key_hex = '39faba0ba66ac3e58cec728b6d67a159';

is( unpack('H*', Crypt::Cipher::SM4->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'SM4->encrypt');
is( Crypt::Cipher::SM4->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'SM4->decrypt');

is( unpack('H*', Crypt::Cipher->new('SM4', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SM4', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::SM4->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'SM4->encrypt');
is( Crypt::Cipher::SM4->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'SM4->decrypt');

is( unpack('H*', Crypt::Cipher->new('SM4', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('SM4', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


