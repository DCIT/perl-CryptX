### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 38;

use Crypt::Cipher;
use Crypt::Cipher::Anubis;

is( Crypt::Cipher::Anubis::blocksize, 16, '::blocksize');
is( Crypt::Cipher::Anubis::keysize, 40, '::keysize');
is( Crypt::Cipher::Anubis::max_keysize, 40, '::max_keysize');
is( Crypt::Cipher::Anubis::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::Anubis::default_rounds, 12, '::default_rounds');

is( Crypt::Cipher::Anubis->blocksize, 16, '->blocksize');
is( Crypt::Cipher::Anubis->keysize, 40, '->keysize');
is( Crypt::Cipher::Anubis->max_keysize, 40, '->max_keysize');
is( Crypt::Cipher::Anubis->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::Anubis->default_rounds, 12, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

is( Crypt::Cipher::blocksize('Anubis'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('Anubis'), 40, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('Anubis'), 40, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('Anubis'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('Anubis'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('Anubis'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('Anubis'), 40, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('Anubis'), 40, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('Anubis'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('Anubis'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher::Anubis->new($min_key)->blocksize, 16, 'Anubis->new()->blocksize');
is( Crypt::Cipher::Anubis->new($min_key)->keysize, 40, 'Anubis->new()->keysize');
is( Crypt::Cipher::Anubis->new($min_key)->max_keysize, 40, 'Anubis->new()->max_keysize');
is( Crypt::Cipher::Anubis->new($min_key)->min_keysize, 16, 'Anubis->new()->min_keysize');
is( Crypt::Cipher::Anubis->new($min_key)->default_rounds, 12, 'Anubis->new()->default_rounds');

is( Crypt::Cipher->new('Anubis', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('Anubis', $min_key)->keysize, 40, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('Anubis', $min_key)->max_keysize, 40, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('Anubis', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('Anubis', $min_key)->default_rounds, 12, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = 'a60b68b88d24d85f3b0cd708196ed99b';
my $block_encrypted_max_key_hex = 'b71e0006978b57d6bf9b792cd4cacfe2';

is( unpack('H*', Crypt::Cipher::Anubis->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Anubis->encrypt');
is( Crypt::Cipher::Anubis->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Anubis->decrypt');

is( unpack('H*', Crypt::Cipher->new('Anubis', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Anubis', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::Anubis->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Anubis->encrypt');
is( Crypt::Cipher::Anubis->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Anubis->decrypt');

is( unpack('H*', Crypt::Cipher->new('Anubis', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('Anubis', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');

