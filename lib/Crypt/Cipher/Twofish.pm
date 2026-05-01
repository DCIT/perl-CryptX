package Crypt::Cipher::Twofish;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_005';

use base qw(Crypt::Cipher);

sub new {
  my ($class, @args) = @_;
  my $obj = Crypt::Cipher->new('Twofish', @args);
  return bless $obj, $class;
}

sub blocksize      { Crypt::Cipher::blocksize('Twofish')      }
sub keysize        { Crypt::Cipher::keysize('Twofish')        }
sub max_keysize    { Crypt::Cipher::max_keysize('Twofish')    }
sub min_keysize    { Crypt::Cipher::min_keysize('Twofish')    }
sub default_rounds { Crypt::Cipher::default_rounds('Twofish') }

1;

=pod

=head1 NAME

Crypt::Cipher::Twofish - Symmetric cipher Twofish, key size: 128/192/256 bits

=head1 SYNOPSIS

  ### example 1
  use Crypt::Mode::CBC;

  my $key = '...'; # length must be a valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::Mode::CBC->new('Twofish');
  my $ciphertext = $cbc->encrypt("secret data", $key, $iv);

  ### example 2 (slower)
  use Crypt::CBC;
  use Crypt::Cipher::Twofish;

  my $key = '...'; # length must be a valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::CBC->new( -cipher=>'Cipher::Twofish', -key=>$key, -iv=>$iv );
  my $ciphertext = $cbc->encrypt("secret data");

=head1 DESCRIPTION

This module implements the Twofish cipher. Its interface is compatible with L<Crypt::CBC>.

B<Note:> This module only implements single-block encryption and decryption.
For general data, use a block mode such as
L<Crypt::Mode::CBC>, L<Crypt::Mode::CTR>, or L<Crypt::CBC> (which is slower).

=head1 METHODS

Unless noted otherwise, assume C<$c> is an existing cipher object created via
C<new>, for example:

 my $c = Crypt::Cipher::Twofish->new($key);

=head2 new

 my $c = Crypt::Cipher::Twofish->new($key);
 #or
 my $c = Crypt::Cipher::Twofish->new($key, $rounds);

 # $key .... [binary string] key of an accepted length (see keysize, min_keysize, max_keysize)
 # $rounds . [integer] optional, number of rounds (if supported by the cipher; croaks on invalid value)

=head2 encrypt

Encrypts exactly one block of plaintext. The length of C<$plaintext> must
equal L</blocksize>; croaks otherwise. An empty string is accepted and
returned unchanged.

 my $ciphertext = $c->encrypt($plaintext);

Returns the encrypted block as a binary string (raw bytes).

=head2 decrypt

Decrypts exactly one block of ciphertext. The length of C<$ciphertext> must
equal L</blocksize>; croaks otherwise. An empty string is accepted and
returned unchanged.

 my $plaintext = $c->decrypt($ciphertext);

Returns the decrypted block as a binary string (raw bytes).

=head2 keysize

Just an alias for C<max_keysize>.

  $c->keysize;
  #or
  Crypt::Cipher::Twofish->keysize;
  #or
  Crypt::Cipher::Twofish::keysize;

=head2 blocksize

Returns the cipher block size (in bytes).

  $c->blocksize;
  #or
  Crypt::Cipher::Twofish->blocksize;
  #or
  Crypt::Cipher::Twofish::blocksize;

=head2 max_keysize

Returns the maximum key size (in bytes).

  $c->max_keysize;
  #or
  Crypt::Cipher::Twofish->max_keysize;
  #or
  Crypt::Cipher::Twofish::max_keysize;

=head2 min_keysize

Returns the minimum key size (in bytes).

  $c->min_keysize;
  #or
  Crypt::Cipher::Twofish->min_keysize;
  #or
  Crypt::Cipher::Twofish::min_keysize;

=head2 default_rounds

Returns the cipher's default round count.

  $c->default_rounds;
  #or
  Crypt::Cipher::Twofish->default_rounds;
  #or
  Crypt::Cipher::Twofish::default_rounds;

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Cipher>

=item * L<https://en.wikipedia.org/wiki/Twofish>

=back

=cut
