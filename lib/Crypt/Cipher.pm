package Crypt::Cipher;

use strict;
use warnings;
our $VERSION = '0.088_005';

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

### the following methods/functions are implemented in XS:
# - new
# - DESTROY
# - blocksize
# - decrypt
# - default_rounds
# - encrypt
# - max_keysize
# - min_keysize

sub keysize { goto \&max_keysize; } # for Crypt::CBC compatibility

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Cipher - Generic interface to cipher functions

=head1 SYNOPSIS

   #### example 1 (encrypting single block)
   use Crypt::Cipher;

   my $key = '1234567890abcdef'; # 16 bytes, valid for AES-128
   my $plaintext_block = '1234567890123456'; # one AES block (16 bytes)
   my $c = Crypt::Cipher->new('AES', $key);
   my $blocksize  = $c->blocksize;
   my $ciphertext = $c->encrypt($plaintext_block);   # encrypt 1 block
   my $plaintext  = $c->decrypt($ciphertext);         #decrypt 1 block

   ### example 2 (using CBC mode)
   use Crypt::Mode::CBC;

   my $cbc_key = '1234567890abcdef'; # 16 bytes, valid for AES-128
   my $iv = 'fedcba0987654321';      # 16 bytes
   my $cbc = Crypt::Mode::CBC->new('AES');
   my $cbc_ciphertext = $cbc->encrypt("secret data", $cbc_key, $iv);

   #### example 3 (compatibility with Crypt::CBC)
   use Crypt::CBC;
   use Crypt::Cipher;

   my $compat_key = '1234567890abcdef'; # 16 bytes, valid for AES-128
   my $compat_iv = 'fedcba0987654321';  # 16 bytes
   my $cipher = Crypt::Cipher->new('AES', $compat_key);
   my $compat_cbc = Crypt::CBC->new( -cipher=>$cipher, -iv=>$compat_iv );
   my $compat_ciphertext = $compat_cbc->encrypt("secret data");

=head1 DESCRIPTION

Provides an interface to various symmetric cipher algorithms.

B<Note:> This module only implements single-block encryption and decryption.
For general data, use a block mode such as
L<Crypt::Mode::CBC>, L<Crypt::Mode::CTR>, or L<Crypt::CBC> (which is slower).

=head1 METHODS

Unless noted otherwise, assume C<$c> is an existing cipher object created via
C<new>, for example:

 my $c = Crypt::Cipher->new('AES', '1234567890abcdef');

=head2 new

Constructor. Returns a reference to the cipher object.

 ## basic scenario
 my $c = Crypt::Cipher->new($name, $key);
 # $name = one of 'AES', 'Anubis', 'Blowfish', 'CAST5', 'Camellia', 'DES', 'DES_EDE',
 #                'KASUMI', 'Khazad', 'MULTI2', 'Noekeon', 'RC2', 'RC5', 'RC6',
 #                'SAFERP', 'SAFER_K128', 'SAFER_K64', 'SAFER_SK128', 'SAFER_SK64',
 #                'SEED', 'SM4', 'Skipjack', 'Twofish', 'XTEA', 'IDEA', 'Serpent'
 #                or any <NAME> for which there is a Crypt::Cipher::<NAME> module
 # $key = binary key (keysize should comply with selected cipher requirements)

 ## some of the ciphers (e.g. MULTI2, RC5, SAFER) allow one to set number of rounds
 my $c = Crypt::Cipher->new('MULTI2', $key, $rounds);
 # $rounds = positive integer (should comply with selected cipher requirements)

=head2 encrypt

Encrypts C<$plaintext> and returns C<$ciphertext>. An empty string is
accepted and returned unchanged; otherwise C<$plaintext> must be exactly
B<blocksize> bytes long.

 my $ciphertext = $c->encrypt($plaintext);

=head2 decrypt

Decrypts C<$ciphertext> and returns C<$plaintext>. An empty string is
accepted and returned unchanged; otherwise C<$ciphertext> must be exactly
B<blocksize> bytes long.

 my $plaintext = $c->decrypt($ciphertext);

=head2 keysize

Just an alias for B<max_keysize> (needed for L<Crypt::CBC> compatibility).

=head2 max_keysize

Returns the maximum allowed key size in bytes for the given cipher.

 $c->max_keysize;
 #or
 Crypt::Cipher->max_keysize('AES');
 #or
 Crypt::Cipher::max_keysize('AES');

=head2 min_keysize

Returns the minimum allowed key size in bytes for the given cipher.

 $c->min_keysize;
 #or
 Crypt::Cipher->min_keysize('AES');
 #or
 Crypt::Cipher::min_keysize('AES');

=head2 blocksize

Returns the block size in bytes for the given cipher.

 $c->blocksize;
 #or
 Crypt::Cipher->blocksize('AES');
 #or
 Crypt::Cipher::blocksize('AES');

=head2 default_rounds

Returns the default number of rounds for the given cipher. Only some ciphers,
such as MULTI2, RC5, and SAFER, let you set the number of rounds via C<new()>.

 $c->default_rounds;
 #or
 Crypt::Cipher->default_rounds('AES');
 #or
 Crypt::Cipher::default_rounds('AES');

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * See subclasses such as L<Crypt::Cipher::AES>, L<Crypt::Cipher::Blowfish>, ...

=back

=cut
