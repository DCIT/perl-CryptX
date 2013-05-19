package Crypt::Mac::Pelican;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( pelican pelican_hex pelican_b64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::Mac';

sub new { my $class = shift; _new(@_) }
sub pelican { Crypt::Mac::Pelican->new(shift)->add(@_)->mac }
sub pelican_hex { Crypt::Mac::Pelican->new(shift)->add(@_)->hexmac }
sub pelican_b64 { Crypt::Mac::Pelican->new(shift)->add(@_)->b64mac }

1;

=pod

=head1 NAME

Crypt::Mac::Pelican - Message authentication code Pelican (AES based MAC)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::Pelican qw( pelican pelican_hex );

   # calculate MAC from string/buffer
   $pelican_raw = pelican($key, 'data buffer');
   $pelican_hex = pelican_hex($key, 'data buffer');
   $pelican_b64 = pelican_b64($key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::Pelican;

   $d = Crypt::Mac::Pelican->new($key);
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->mac;    # raw bytes
   $result_hex = $d->hexmac; # hexadecimal form
   $result_b64 = $d->b64mac; # Base64 form

=head1 DESCRIPTION

Provides an interface to the Pelican message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::Pelican qw(pelican pelican_hex );

Or all of them at once:

  use Crypt::Mac::Pelican ':all';

=head1 FUNCTIONS

=head2 pelican

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a binary string.

 $pelican_raw = pelican($key, 'data buffer');
 #or
 $pelican_raw = pelican($key, 'any data', 'more data', 'even more data');

=head2 pelican_hex

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a hexadecimal string.

 $pelican_hex = pelican_hex($key, 'data buffer');
 #or
 $pelican_hex = pelican_hex($key, 'any data', 'more data', 'even more data');

=head2 pelican_b64

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a BASE64 string.

 $pelican_b64 = pelican_b64($key, 'data buffer');
 #or
 $pelican_b64 = pelican_b64($key, 'any data', 'more data', 'even more data');

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Mac>.

=head2 new

 $d = Crypt::Mac::Pelican->new($key);

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

 $result_b64 = $d->b64mac();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Mac|Crypt::Mac>

=back

=cut

__END__