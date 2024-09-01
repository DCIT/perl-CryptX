package Crypt::Cipher::SAFER_SK128;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.080_008';

use base qw(Crypt::Cipher);

sub blocksize      { Crypt::Cipher::blocksize('SAFER_SK128')      }
sub keysize        { Crypt::Cipher::keysize('SAFER_SK128')        }
sub max_keysize    { Crypt::Cipher::max_keysize('SAFER_SK128')    }
sub min_keysize    { Crypt::Cipher::min_keysize('SAFER_SK128')    }
sub default_rounds { Crypt::Cipher::default_rounds('SAFER_SK128') }

1;

=pod

=head1 NAME

Crypt::Cipher::SAFER_SK128 - Symmetric cipher SAFER_SK128, key size: 128 bits

=head1 SYNOPSIS

  ### example 1
  use Crypt::Mode::CBC;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::Mode::CBC->new('SAFER_SK128');
  my $ciphertext = $cbc->encrypt("secret data", $key, $iv);

  ### example 2 (slower)
  use Crypt::CBC;
  use Crypt::Cipher::SAFER_SK128;

  my $key = '...'; # length has to be valid key size for this cipher
  my $iv = '...';  # 16 bytes
  my $cbc = Crypt::CBC->new( -cipher=>'Cipher::SAFER_SK128', -key=>$key, -iv=>$iv );
  my $ciphertext = $cbc->encrypt("secret data");

=head1 DESCRIPTION

This module implements the SAFER_SK128 cipher. Provided interface is compliant with L<Crypt::CBC|Crypt::CBC> module.

B<BEWARE:> This module implements just elementary "one-block-(en|de)cryption" operation - if you want to
encrypt/decrypt generic data you have to use some of the cipher block modes - check for example
L<Crypt::Mode::CBC|Crypt::Mode::CBC>, L<Crypt::Mode::CTR|Crypt::Mode::CTR> or L<Crypt::CBC|Crypt::CBC> (which will be slower).

=head1 METHODS

=head2 new

 $c = Crypt::Cipher::SAFER_SK128->new($key);
 #or
 $c = Crypt::Cipher::SAFER_SK128->new($key, $rounds);

=head2 encrypt

 $ciphertext = $c->encrypt($plaintext);

=head2 decrypt

 $plaintext = $c->decrypt($ciphertext);

=head2 keysize

  $c->keysize;
  #or
  Crypt::Cipher::SAFER_SK128->keysize;
  #or
  Crypt::Cipher::SAFER_SK128::keysize;

=head2 blocksize

  $c->blocksize;
  #or
  Crypt::Cipher::SAFER_SK128->blocksize;
  #or
  Crypt::Cipher::SAFER_SK128::blocksize;

=head2 max_keysize

  $c->max_keysize;
  #or
  Crypt::Cipher::SAFER_SK128->max_keysize;
  #or
  Crypt::Cipher::SAFER_SK128::max_keysize;

=head2 min_keysize

  $c->min_keysize;
  #or
  Crypt::Cipher::SAFER_SK128->min_keysize;
  #or
  Crypt::Cipher::SAFER_SK128::min_keysize;

=head2 default_rounds

  $c->default_rounds;
  #or
  Crypt::Cipher::SAFER_SK128->default_rounds;
  #or
  Crypt::Cipher::SAFER_SK128::default_rounds;

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Cipher>

=item * L<https://en.wikipedia.org/wiki/SAFER>

=back

=cut
