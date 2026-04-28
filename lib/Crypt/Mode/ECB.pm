package Crypt::Mode::ECB;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_002';

use Crypt::Cipher;

sub encrypt {
  my ($self, $pt) = (shift, shift);
  local $SIG{__DIE__} = \&CryptX::_croak;
  $self->start_encrypt(@_)->add($pt) . $self->finish;
}

sub decrypt {
  my ($self, $ct) = (shift, shift);
  local $SIG{__DIE__} = \&CryptX::_croak;
  $self->start_decrypt(@_)->add($ct) . $self->finish;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Mode::ECB - Block cipher mode ECB [Electronic codebook]

=head1 SYNOPSIS

   use Crypt::Mode::ECB;
   my $m = Crypt::Mode::ECB->new('AES');
   my $key = '1234567890123456';
   my $plaintext = 'example plaintext';
   my $chunk1 = 'example ';
   my $chunk2 = 'plaintext';

   #(en|de)crypt at once
   my $single_ciphertext = $m->encrypt($plaintext, $key);
   my $single_plaintext = $m->decrypt($single_ciphertext, $key);

   #encrypt more chunks
   $m->start_encrypt($key);
   my $chunked_ciphertext = '';
   $chunked_ciphertext .= $m->add($chunk1);
   $chunked_ciphertext .= $m->add($chunk2);
   $chunked_ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key);
   my $chunked_plaintext = '';
   $chunked_plaintext .= $m->add($chunked_ciphertext);
   $chunked_plaintext .= $m->finish;

=head1 DESCRIPTION

This module implements ECB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).
B<BEWARE: ECB is inherently insecure>, if you are not sure go for L<Crypt::Mode::CBC>!

=head1 METHODS

Unless noted otherwise, assume C<$m> is an existing mode object created via
C<new>, for example:

 my $m = Crypt::Mode::ECB->new('AES');

=head2 new

 my $m = Crypt::Mode::ECB->new($name);
 #or
 my $m = Crypt::Mode::ECB->new($name, $padding);
 #or
 my $m = Crypt::Mode::ECB->new($name, $padding, $cipher_rounds);

 # $name ....... [string] one of 'AES', 'Anubis', 'Blowfish', 'CAST5', 'Camellia', 'DES', 'DES_EDE',
 #               'KASUMI', 'Khazad', 'MULTI2', 'Noekeon', 'RC2', 'RC5', 'RC6',
 #               'SAFERP', 'SAFER_K128', 'SAFER_K64', 'SAFER_SK128', 'SAFER_SK64',
 #               'SEED', 'Skipjack', 'Twofish', 'XTEA', 'IDEA', 'Serpent'
 #               simply any <NAME> for which there exists Crypt::Cipher::<NAME>
 # $padding .... [integer] 0 no padding (plaintext size has to be multiple of block length)
 #               1 PKCS5 padding, Crypt::CBC's "standard" - DEFAULT
 #               2 Crypt::CBC's "oneandzeroes"
 #               3 ANSI X.923 padding
 #               4 zero padding
 #               5 zero padding (+a block of zeros if the output length is divisible by the blocksize)
 # $cipher_rounds ... [integer] optional, num of rounds for given cipher

=head2 encrypt

Encrypts the plaintext in a single call. Returns the ciphertext as a binary string.
The plaintext scalar is converted to bytes using Perl's usual scalar
stringification. Defined scalars, including numbers and string-overloaded
objects, are accepted. C<undef> is treated as an empty string and may emit
Perl's usual "uninitialized value" warning.

   my $ciphertext = $m->encrypt($plaintext, $key);

=head2 decrypt

Decrypts the ciphertext in a single call. Returns the plaintext as a binary string.
The ciphertext scalar is converted to bytes using Perl's usual scalar
stringification. Defined scalars, including numbers and string-overloaded
objects, are accepted. C<undef> is treated as an empty string and may emit
Perl's usual "uninitialized value" warning.

   my $plaintext = $m->decrypt($ciphertext, $key);

=head2 start_encrypt

Initializes encryption mode. Returns the object itself.

   $m->start_encrypt($key);

=head2 start_decrypt

Initializes decryption mode. Returns the object itself.

   $m->start_decrypt($key);

=head2 add

Feeds data to the encryption or decryption stream. Returns a binary string.

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

   # in encrypt mode
   my $ciphertext = $m->add($plaintext);

   # in decrypt mode
   my $plaintext = $m->add($ciphertext);

=head2 finish

   #encrypt more chunks
   $m->start_encrypt($key);
   my $chunk1 = 'example ';
   my $chunk2 = 'plaintext';
   my $ciphertext = '';
   $ciphertext .= $m->add($chunk1);
   $ciphertext .= $m->add($chunk2);
   $ciphertext .= $m->finish;

   #decrypt more chunks
   $m->start_decrypt($key);
   my $plaintext = '';
   $plaintext .= $m->add($ciphertext);
   $plaintext .= $m->finish;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher>

=item * L<Crypt::Cipher::AES>, L<Crypt::Cipher::Blowfish>, ...

=item * L<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29>

=back

=cut
