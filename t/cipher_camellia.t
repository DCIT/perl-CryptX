### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Camellia;

is( Crypt::Cipher::Camellia::blocksize, 16, '::blocksize');
is( Crypt::Cipher::Camellia::keysize, 32, '::keysize');
is( Crypt::Cipher::Camellia::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::Camellia::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Camellia::default_rounds, 18, '::default_rounds');

is( Crypt::Cipher::Camellia->blocksize, 16, '->blocksize');
is( Crypt::Cipher::Camellia->keysize, 32, '->keysize');
is( Crypt::Cipher::Camellia->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::Camellia->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Camellia->default_rounds, 18, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Camellia'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Camellia'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Camellia'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Camellia'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Camellia'), 18, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Camellia'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Camellia'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Camellia'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Camellia'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Camellia'), 18, 'Cipher->default_rounds');

is( Crypt::Cipher::Camellia->new($min_key)->blocksize, 16, 'Camellia->new()->blocksize');
is( Crypt::Cipher::Camellia->new($min_key)->keysize, 32, 'Camellia->new()->keysize');
is( Crypt::Cipher::Camellia->new($min_key)->max_keysize, 32, 'Camellia->new()->max_keysize');
is( Crypt::Cipher::Camellia->new($min_key)->min_keysize, 16, 'Camellia->new()->min_keysize');
is( Crypt::Cipher::Camellia->new($min_key)->default_rounds, 18, 'Camellia->new()->default_rounds');

is( Crypt::Cipher->new('Camellia', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Camellia', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Camellia', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Camellia', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Camellia', $min_key)->default_rounds, 18, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = 'f492579d09aa161b527d944df13c01ab';
my $block_encrypted_max_key_hex = 'a8f95dc649586f8c366c226cc728ccb4';

is( unpack('H*', Crypt::Cipher::Camellia->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Camellia->encrypt');
is( Crypt::Cipher::Camellia->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Camellia->decrypt');

is( unpack('H*', Crypt::Cipher->new('Camellia', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Camellia', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Camellia->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Camellia->encrypt');
is( Crypt::Cipher::Camellia->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Camellia->decrypt');

is( unpack('H*', Crypt::Cipher->new('Camellia', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Camellia', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

