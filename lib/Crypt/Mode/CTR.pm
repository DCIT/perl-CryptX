package Crypt::Mode::CTR;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_004';

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

Crypt::Mode::CTR - Block cipher mode CTR [Counter mode]

=head1 SYNOPSIS

   use Crypt::Mode::CTR;
   my $m = Crypt::Mode::CTR->new('AES');
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

This module implements CTR cipher mode. B<NOTE:> it works only with ciphers from L<CryptX> (Crypt::Cipher::NNNN).

=head1 METHODS

Unless noted otherwise, assume C<$m> is an existing mode object created via
C<new>, for example:

 my $m = Crypt::Mode::CTR->new('AES');

=head2 new

 my $m = Crypt::Mode::CTR->new($cipher_name);
 #or
 my $m = Crypt::Mode::CTR->new($cipher_name, $ctr_mode, $ctr_width);
 #or
 my $m = Crypt::Mode::CTR->new($cipher_name, $ctr_mode, $ctr_width, $cipher_rounds);

 # $cipher_name .. [string] one of 'AES', 'Anubis', 'Blowfish', 'CAST5', 'Camellia', 'DES', 'DES_EDE',
 #                 'KASUMI', 'Khazad', 'MULTI2', 'Noekeon', 'RC2', 'RC5', 'RC6',
 #                 'SAFERP', 'SAFER_K128', 'SAFER_K64', 'SAFER_SK128', 'SAFER_SK64',
 #                 'SEED', 'Skipjack', 'Twofish', 'XTEA', 'IDEA', 'Serpent'
 #                 simply any <NAME> for which there exists Crypt::Cipher::<NAME>
 # $ctr_mode ..... [integer] CTR_COUNTER_LITTLE_ENDIAN    (0) - little-endian counter (DEFAULT)
 #                 CTR_COUNTER_BIG_ENDIAN       (1) - big-endian counter
 #                 CTR_COUNTER_LITTLE_ENDIAN | 2 (2) - little-endian + RFC 3686 initial-counter-incrementing
 #                 CTR_COUNTER_BIG_ENDIAN | 2    (3) - big-endian + RFC 3686 initial-counter-incrementing
 # $ctr_width .... [integer] counter width in bytes (DEFAULT = full block width, e.g. 16 for AES)
 # $cipher_rounds ... [integer] optional, num of rounds for given cipher

=head2 encrypt

Encrypts the plaintext in a single call. Returns the ciphertext as a binary string.
The plaintext scalar is converted to bytes using Perl's usual scalar
stringification. Defined scalars, including numbers and string-overloaded
objects, are accepted. C<undef> is treated as an empty string and may emit
Perl's usual "uninitialized value" warning.

   my $ciphertext = $m->encrypt($plaintext, $key, $iv);

=head2 decrypt

Decrypts the ciphertext in a single call. Returns the plaintext as a binary string.
The ciphertext scalar is converted to bytes using Perl's usual scalar
stringification. Defined scalars, including numbers and string-overloaded
objects, are accepted. C<undef> is treated as an empty string and may emit
Perl's usual "uninitialized value" warning.

   my $plaintext = $m->decrypt($ciphertext, $key, $iv);

=head2 start_encrypt

Initializes encryption mode. Returns the object itself.

   $m->start_encrypt($key, $iv);

=head2 start_decrypt

Initializes decryption mode. Returns the object itself.

   $m->start_decrypt($key, $iv);

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

CTR is a streaming mode and does not use padding, so C<finish> returns an empty
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

=item * L<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29>

=back

=cut
