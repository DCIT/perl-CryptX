package Crypt::Cipher::IDEA;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Cipher);

sub blocksize      { Crypt::Cipher::blocksize('IDEA')      }
sub keysize        { Crypt::Cipher::keysize('IDEA')        }
sub max_keysize    { Crypt::Cipher::max_keysize('IDEA')    }
sub min_keysize    { Crypt::Cipher::min_keysize('IDEA')    }
sub default_rounds { Crypt::Cipher::default_rounds('IDEA') }

1;

=pod

=head1 NAME

Crypt::Cipher::IDEA - Symmetric cipher IDEA, key size: 128 bits

=head1 SYNOPSIS

  ### example 1
  use Crypt::Mode::CBC;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::Mode::CBC->new('IDEA');
  my $ciphertext = $cbc->encrypt("secret data", $key, $iv);

  ### example 2 (slower)
  use Crypt::CBC;
  use Crypt::Cipher::IDEA;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::CBC->new( -cipher=>'Cipher::IDEA', -key=>$key, -iv=>$iv );
  my $ciphertext = $cbc->encrypt("secret data");

=head1 DESCRIPTION

This module implements the IDEA cipher. Provided interface is compliant with L<Crypt::CBC|Crypt::CBC> module.

B<BEWARE:> This module implements just elementary "one-block-(en|de)cryption" operation - if you want to
encrypt/decrypt generic data you have to use some of the cipher block modes - check for example
L<Crypt::Mode::CBC|Crypt::Mode::CBC>, L<Crypt::Mode::CTR|Crypt::Mode::CTR> or L<Crypt::CBC|Crypt::CBC> (which will be slower).

=head1 METHODS

Unless noted otherwise, assume C<$c> is an existing cipher object created via
C<new>, for example:

 my $c = Crypt::Cipher::IDEA->new($key);

=head2 new

 my $c = Crypt::Cipher::IDEA->new($key);
 #or
 my $c = Crypt::Cipher::IDEA->new($key, $rounds);

 # $key .... [binary string] key of an accepted length (see keysize, min_keysize, max_keysize)
 # $rounds . [integer] optional, number of rounds (if supported by the cipher; croaks on invalid value)

=head2 encrypt

Encrypts exactly one block of plaintext. The length of C<$plaintext> must
equal L</blocksize>; croaks otherwise.



 my $ciphertext = $c->encrypt($plaintext);

Returns the encrypted block as a binary string (raw bytes).

=head2 decrypt

Decrypts exactly one block of ciphertext. The length of C<$ciphertext> must
equal L</blocksize>; croaks otherwise.

 my $plaintext = $c->decrypt($ciphertext);

Returns the decrypted block as a binary string (raw bytes).

=head2 keysize

Returns the default key size (in bytes).

  $c->keysize;
  #or
  Crypt::Cipher::IDEA->keysize;
  #or
  Crypt::Cipher::IDEA::keysize;

=head2 blocksize

Returns the cipher block size (in bytes).

  $c->blocksize;
  #or
  Crypt::Cipher::IDEA->blocksize;
  #or
  Crypt::Cipher::IDEA::blocksize;

=head2 max_keysize

Returns the maximum key size (in bytes).

  $c->max_keysize;
  #or
  Crypt::Cipher::IDEA->max_keysize;
  #or
  Crypt::Cipher::IDEA::max_keysize;

=head2 min_keysize

Returns the minimum key size (in bytes).

  $c->min_keysize;
  #or
  Crypt::Cipher::IDEA->min_keysize;
  #or
  Crypt::Cipher::IDEA::min_keysize;

=head2 default_rounds

Returns the default number of rounds for the cipher, or C<0> if the
number of rounds is fixed.

  $c->default_rounds;
  #or
  Crypt::Cipher::IDEA->default_rounds;
  #or
  Crypt::Cipher::IDEA::default_rounds;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher>

=item * L<https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm>

=back

=cut
