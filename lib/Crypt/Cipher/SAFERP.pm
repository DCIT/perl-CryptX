package Crypt::Cipher::SAFERP;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_005';

use base qw(Crypt::Cipher);

sub new {
  my ($class, @args) = @_;
  my $obj = Crypt::Cipher->new('SAFERP', @args);
  return bless $obj, $class;
}

sub blocksize      { Crypt::Cipher::blocksize('SAFERP')      }
sub keysize        { Crypt::Cipher::keysize('SAFERP')        }
sub max_keysize    { Crypt::Cipher::max_keysize('SAFERP')    }
sub min_keysize    { Crypt::Cipher::min_keysize('SAFERP')    }
sub default_rounds { Crypt::Cipher::default_rounds('SAFERP') }

1;

=pod

=head1 NAME

Crypt::Cipher::SAFERP - Symmetric cipher SAFER+, key size: 128/192/256 bits

=head1 SYNOPSIS

  ### example 1
  use Crypt::Mode::CBC;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::Mode::CBC->new('SAFERP');
  my $ciphertext = $cbc->encrypt("secret data", $key, $iv);

  ### example 2 (slower)
  use Crypt::CBC;
  use Crypt::Cipher::SAFERP;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::CBC->new( -cipher=>'Cipher::SAFERP', -key=>$key, -iv=>$iv );
  my $ciphertext = $cbc->encrypt("secret data");

=head1 DESCRIPTION

This module implements the SAFERP cipher. Provided interface is compliant with L<Crypt::CBC|Crypt::CBC> module.

B<BEWARE:> This module implements just elementary "one-block-(en|de)cryption" operation - if you want to
encrypt/decrypt generic data you have to use some of the cipher block modes - check for example
L<Crypt::Mode::CBC|Crypt::Mode::CBC>, L<Crypt::Mode::CTR|Crypt::Mode::CTR> or L<Crypt::CBC|Crypt::CBC> (which will be slower).

=head1 METHODS

Unless noted otherwise, assume C<$c> is an existing cipher object created via
C<new>, for example:

 my $c = Crypt::Cipher::SAFERP->new($key);

=head2 new

 my $c = Crypt::Cipher::SAFERP->new($key);
 #or
 my $c = Crypt::Cipher::SAFERP->new($key, $rounds);

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
  Crypt::Cipher::SAFERP->keysize;
  #or
  Crypt::Cipher::SAFERP::keysize;

=head2 blocksize

Returns the cipher block size (in bytes).

  $c->blocksize;
  #or
  Crypt::Cipher::SAFERP->blocksize;
  #or
  Crypt::Cipher::SAFERP::blocksize;

=head2 max_keysize

Returns the maximum key size (in bytes).

  $c->max_keysize;
  #or
  Crypt::Cipher::SAFERP->max_keysize;
  #or
  Crypt::Cipher::SAFERP::max_keysize;

=head2 min_keysize

Returns the minimum key size (in bytes).

  $c->min_keysize;
  #or
  Crypt::Cipher::SAFERP->min_keysize;
  #or
  Crypt::Cipher::SAFERP::min_keysize;

=head2 default_rounds

Returns the cipher's default round count.

  $c->default_rounds;
  #or
  Crypt::Cipher::SAFERP->default_rounds;
  #or
  Crypt::Cipher::SAFERP::default_rounds;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher>

=item * L<https://en.wikipedia.org/wiki/SAFER>

=back

=cut
