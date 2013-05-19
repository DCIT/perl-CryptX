package Crypt::Mac::PMAC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( pmac pmac_hex pmac_b64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::Mac';

use Crypt::Cipher;

sub new { my $class = shift; _new(Crypt::Cipher::_trans_cipher_name(shift), @_) }
sub pmac { Crypt::Mac::PMAC->new(shift, shift)->add(@_)->mac }
sub pmac_hex { Crypt::Mac::PMAC->new(shift, shift)->add(@_)->hexmac }
sub pmac_b64 { Crypt::Mac::PMAC->new(shift, shift)->add(@_)->b64mac }

1;

=pod

=head1 NAME

Crypt::Mac::PMAC - Message authentication code PMAC

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::PMAC qw( pmac pmac_hex );

   # calculate MAC from string/buffer
   $pmac_raw = pmac($cipher_name, $key, 'data buffer');
   $pmac_hex = pmac_hex($cipher_name, $key, 'data buffer');
   $pmac_b64 = pmac_b64($cipher_name, $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::PMAC;

   $d = Crypt::Mac::PMAC->new($cipher_name, $key);
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->mac;    # raw bytes
   $result_hex = $d->hexmac; # hexadecimal form
   $result_b64 = $d->b64mac; # Base64 form

=head1 DESCRIPTION

Provides an interface to the PMAC message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::PMAC qw(pmac pmac_hex );

Or all of them at once:

  use Crypt::Mac::PMAC ':all';

=head1 FUNCTIONS

=head2 pmac

Logically joins all arguments into a single string, and returns its PMAC message authentication code encoded as a binary string.

 $pmac_raw = pmac($cipher_name, $key, 'data buffer');
 #or
 $pmac_raw = pmac($cipher_name, $key, 'any data', 'more data', 'even more data');

=head2 pmac_hex

Logically joins all arguments into a single string, and returns its PMAC message authentication code encoded as a hexadecimal string.

 $pmac_hex = pmac_hex($cipher_name, $key, 'data buffer');
 #or
 $pmac_hex = pmac_hex($cipher_name, $key, 'any data', 'more data', 'even more data');

=head2 pmac_b64

Logically joins all arguments into a single string, and returns its PMAC message authentication code encoded as a BASE64 string.

 $pmac_b64 = pmac_b64($cipher_name, $key, 'data buffer');
 #or
 $pmac_b64 = pmac_b64($cipher_name, $key, 'any data', 'more data', 'even more data');

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Mac>.

=head2 new

 $d = Crypt::Mac::PMAC->new($cipher_name, $key);

=head2 clone

 $d->clone();

=head2 reset

 $d->reset();

=head2 add

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

=head2 mac

 $result_raw = $d->mac();

=head2 hexmac

 $result_hex = $d->hexmac();

=head2 b64mac

 $result_base64 = $d->b64mac();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Mac|Crypt::Mac>

=back

=cut

__END__