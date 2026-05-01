package Crypt::Cipher::Noekeon;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_005';

use base qw(Crypt::Cipher);

sub new {
  my ($class, @args) = @_;
  my $obj = Crypt::Cipher->new('Noekeon', @args);
  return bless $obj, $class;
}

sub blocksize      { Crypt::Cipher::blocksize('Noekeon')      }
sub keysize        { Crypt::Cipher::keysize('Noekeon')        }
sub max_keysize    { Crypt::Cipher::max_keysize('Noekeon')    }
sub min_keysize    { Crypt::Cipher::min_keysize('Noekeon')    }
sub default_rounds { Crypt::Cipher::default_rounds('Noekeon') }

1;

=pod

=head1 NAME

Crypt::Cipher::Noekeon - Symmetric cipher Noekeon, key size: 128 bits

=head1 SYNOPSIS

  ### example 1
  use Crypt::Mode::CBC;

  my $key = '...'; # length must be a valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::Mode::CBC->new('Noekeon');
  my $ciphertext = $cbc->encrypt("secret data", $key, $iv);

  ### example 2 (slower)
  use Crypt::CBC;
  use Crypt::Cipher::Noekeon;

  my $key = '...'; # length must be a valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::CBC->new( -cipher=>'Cipher::Noekeon', -key=>$key, -iv=>$iv );
  my $ciphertext = $cbc->encrypt("secret data");

=head1 DESCRIPTION

This module implements the Noekeon cipher. Its interface is compatible with L<Crypt::CBC>.

B<Note:> This module only implements single-block encryption and decryption.
For general data, use a block mode such as
L<Crypt::Mode::CBC>, L<Crypt::Mode::CTR>, or L<Crypt::CBC> (which is slower).

=head1 METHODS

Unless noted otherwise, assume C<$c> is an existing cipher object created via
C<new>, for example:

 my $c = Crypt::Cipher::Noekeon->new($key);

=head2 new

 my $c = Crypt::Cipher::Noekeon->new($key);
 #or
 my $c = Crypt::Cipher::Noekeon->new($key, $rounds);

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
  Crypt::Cipher::Noekeon->keysize;
  #or
  Crypt::Cipher::Noekeon::keysize;

=head2 blocksize

Returns the cipher block size (in bytes).

  $c->blocksize;
  #or
  Crypt::Cipher::Noekeon->blocksize;
  #or
  Crypt::Cipher::Noekeon::blocksize;

=head2 max_keysize

Returns the maximum key size (in bytes).

  $c->max_keysize;
  #or
  Crypt::Cipher::Noekeon->max_keysize;
  #or
  Crypt::Cipher::Noekeon::max_keysize;

=head2 min_keysize

Returns the minimum key size (in bytes).

  $c->min_keysize;
  #or
  Crypt::Cipher::Noekeon->min_keysize;
  #or
  Crypt::Cipher::Noekeon::min_keysize;

=head2 default_rounds

Returns the cipher's default round count.

  $c->default_rounds;
  #or
  Crypt::Cipher::Noekeon->default_rounds;
  #or
  Crypt::Cipher::Noekeon::default_rounds;

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Cipher>

=item * L<https://en.wikipedia.org/wiki/NOEKEON>

=back

=cut
