package Crypt::Mode::CFB;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use Crypt::Cipher;

sub encrypt {
  my ($self, $pt) = (shift, shift);
  local $SIG{__DIE__} = \&CryptX::_croak;
  $self->start_encrypt(@_)->add($pt);
}

sub decrypt {
  my ($self, $ct) = (shift, shift);
  local $SIG{__DIE__} = \&CryptX::_croak;
  $self->start_decrypt(@_)->add($ct);
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Mode::CFB - Block cipher mode CFB [Cipher feedback]

=head1 SYNOPSIS

   use Crypt::Mode::CFB;
   my $m = Crypt::Mode::CFB->new('AES');
   my $key = '1234567890123456';
   my $iv = '1234567890123456';
   my $plaintext = 'example plaintext';
   my $chunk1 = 'example ';
   my $chunk2 = 'plaintext';

   #(en|de)crypt at once
   my $single_ciphertext = $m->encrypt($plaintext, $key, $iv);
   my $single_plaintext = $m->decrypt($single_ciphertext, $key, $iv);

   #encrypt more chunks
   $m->start_encrypt($key, $iv);
   my $chunked_ciphertext = '';
   $chunked_ciphertext .= $m->add($chunk1);
   $chunked_ciphertext .= $m->add($chunk2);

   #decrypt more chunks
   $m->start_decrypt($key, $iv);
   my $chunked_plaintext = '';
   $chunked_plaintext .= $m->add($chunked_ciphertext);

=head1 DESCRIPTION

This module implements CFB cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).

=head1 METHODS

Unless noted otherwise, assume C<$m> is an existing mode object created via
C<new>, for example:

 my $m = Crypt::Mode::CFB->new('AES');

=head2 new

 my $m = Crypt::Mode::CFB->new($name);
 #or
 my $m = Crypt::Mode::CFB->new($name, $cipher_rounds);

 # $name ............ [string] one of 'AES', 'Anubis', 'Blowfish', 'CAST5', 'Camellia', 'DES', 'DES_EDE',
 #                    'KASUMI', 'Khazad', 'MULTI2', 'Noekeon', 'RC2', 'RC5', 'RC6',
 #                    'SAFERP', 'SAFER_K128', 'SAFER_K64', 'SAFER_SK128', 'SAFER_SK64',
 #                    'SEED', 'Skipjack', 'Twofish', 'XTEA', 'IDEA', 'Serpent'
 #                    simply any <NAME> for which there exists Crypt::Cipher::<NAME>
 # $cipher_rounds ... [integer] optional, num of rounds for given cipher

=head2 encrypt

Encrypts the plaintext in a single call. Returns the ciphertext as a binary string.

   my $ciphertext = $m->encrypt($plaintext, $key, $iv);

=head2 decrypt

Decrypts the ciphertext in a single call. Returns the plaintext as a binary string.

   my $plaintext = $m->decrypt($ciphertext, $key, $iv);

=head2 start_encrypt

Initializes encryption mode. Returns the object itself.

   $m->start_encrypt($key, $iv);

=head2 start_decrypt

Initializes decryption mode. Returns the object itself.

   $m->start_decrypt($key, $iv);

=head2 add

Feeds data to the encryption or decryption stream. Returns a binary string.

   # in encrypt mode
   my $ciphertext = $m->add($plaintext);

   # in decrypt mode
   my $plaintext = $m->add($ciphertext);

=head2 finish

CFB is a streaming mode and does not use padding, so C<finish> returns an empty
string. It exists for API consistency with L<Crypt::Mode::CBC> and
L<Crypt::Mode::ECB> and may be safely called or omitted.

   $m->start_encrypt($key, $iv);
   my $ciphertext = '';
   $ciphertext .= $m->add($chunk1);
   $ciphertext .= $m->add($chunk2);
   $ciphertext .= $m->finish;   # returns ''

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher>

=item * L<Crypt::Cipher::AES>, L<Crypt::Cipher::Blowfish>, ...

=item * L<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_.28CFB.29>

=back

=cut
