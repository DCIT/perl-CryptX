### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 39;

use Crypt::Cipher;
use Crypt::Cipher::ARIA;

is( Crypt::Cipher::ARIA::blocksize, 16, '::blocksize');
is( Crypt::Cipher::ARIA::keysize, 32, '::keysize');
is( Crypt::Cipher::ARIA::max_keysize, 32, '::max_keysize');
is( Crypt::Cipher::ARIA::min_keysize, 16, '::min_keysize');
is( Crypt::Cipher::ARIA::default_rounds, 12, '::default_rounds');

is( Crypt::Cipher::ARIA->blocksize, 16, '->blocksize');
is( Crypt::Cipher::ARIA->keysize, 32, '->keysize');
is( Crypt::Cipher::ARIA->max_keysize, 32, '->max_keysize');
is( Crypt::Cipher::ARIA->min_keysize, 16, '->min_keysize');
is( Crypt::Cipher::ARIA->default_rounds, 12, '->default_rounds');

my $min_key = 'kkkkkkkkkkkkkkkk';
my $max_key = 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK';

ok(Crypt::Cipher::ARIA->new($min_key)->isa('Crypt::Cipher::ARIA'), 'ARIA->new returns subclass instance');

is( Crypt::Cipher::blocksize('ARIA'), 16, 'Cipher->blocksize');
is( Crypt::Cipher::keysize('ARIA'), 32, 'Cipher->keysize');
is( Crypt::Cipher::max_keysize('ARIA'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher::min_keysize('ARIA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher::default_rounds('ARIA'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher->blocksize('ARIA'), 16, 'Cipher->blocksize');
is( Crypt::Cipher->keysize('ARIA'), 32, 'Cipher->keysize');
is( Crypt::Cipher->max_keysize('ARIA'), 32, 'Cipher->max_keysize');
is( Crypt::Cipher->min_keysize('ARIA'), 16, 'Cipher->min_keysize');
is( Crypt::Cipher->default_rounds('ARIA'), 12, 'Cipher->default_rounds');

is( Crypt::Cipher::ARIA->new($min_key)->blocksize, 16, 'ARIA->new()->blocksize');
is( Crypt::Cipher::ARIA->new($min_key)->keysize, 32, 'ARIA->new()->keysize');
is( Crypt::Cipher::ARIA->new($min_key)->max_keysize, 32, 'ARIA->new()->max_keysize');
is( Crypt::Cipher::ARIA->new($min_key)->min_keysize, 16, 'ARIA->new()->min_keysize');
is( Crypt::Cipher::ARIA->new($min_key)->default_rounds, 12, 'ARIA->new()->default_rounds');

is( Crypt::Cipher->new('ARIA', $min_key)->blocksize, 16, 'Cipher->new()->blocksize');
is( Crypt::Cipher->new('ARIA', $min_key)->keysize, 32, 'Cipher->new()->keysize');
is( Crypt::Cipher->new('ARIA', $min_key)->max_keysize, 32, 'Cipher->new()->max_keysize');
is( Crypt::Cipher->new('ARIA', $min_key)->min_keysize, 16, 'Cipher->new()->min_keysize');
is( Crypt::Cipher->new('ARIA', $min_key)->default_rounds, 12, 'Cipher->new()->default_rounds');

my $block_plain = 'BBBBBBBBBBBBBBBB';
my $block_encrypted_min_key_hex = 'b887329e6228922fccc5c22c68fa0e5e';
my $block_encrypted_max_key_hex = '2ed0964c66cc66ab00223a3cd17e8247';

is( unpack('H*', Crypt::Cipher::ARIA->new($min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'ARIA->encrypt');
is( Crypt::Cipher::ARIA->new($min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'ARIA->decrypt');

is( unpack('H*', Crypt::Cipher->new('ARIA', $min_key)->encrypt($block_plain)), $block_encrypted_min_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('ARIA', $min_key)->decrypt(pack('H*', $block_encrypted_min_key_hex)), $block_plain, 'Cipher->decrypt');

is( unpack('H*', Crypt::Cipher::ARIA->new($max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'ARIA->encrypt');
is( Crypt::Cipher::ARIA->new($max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'ARIA->decrypt');

is( unpack('H*', Crypt::Cipher->new('ARIA', $max_key)->encrypt($block_plain)), $block_encrypted_max_key_hex, 'Cipher->encrypt');
is( Crypt::Cipher->new('ARIA', $max_key)->decrypt(pack('H*', $block_encrypted_max_key_hex)), $block_plain, 'Cipher->decrypt');


