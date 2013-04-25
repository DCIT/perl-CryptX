package Crypt::Digest::RIPEMD160;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( ripemd160 ripemd160_hex ripemd160_base64 ripemd160_file ripemd160_file_hex ripemd160_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub ripemd160             { Crypt::Digest::digest_data(__PACKAGE__, @_) }
sub ripemd160_hex         { Crypt::Digest::digest_data_hex(__PACKAGE__, @_) }
sub ripemd160_base64      { Crypt::Digest::digest_data_base64(__PACKAGE__, @_) }

sub ripemd160_file        { Crypt::Digest::digest_file(__PACKAGE__, @_) }
sub ripemd160_file_hex    { Crypt::Digest::digest_file_hex(__PACKAGE__, @_) }
sub ripemd160_file_base64 { Crypt::Digest::digest_file_base64(__PACKAGE__, @_) }

1;

=pod

=head1 NAME

Crypt::Digest::RIPEMD160 - Hash function RIPEMD-160 [size: 160 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::RIPEMD160 qw( ripemd160 ripemd160_hex ripemd160_base64 ripemd160_file ripemd160_file_hex ripemd160_file_base64 );

   # calculate digest from string/buffer
   $ripemd160_raw = ripemd160('data string');
   $ripemd160_hex = ripemd160_hex('data string');
   $ripemd160_b64 = ripemd160_base64('data string');
   # calculate digest from file
   $ripemd160_raw = ripemd160_file('filename.dat');
   $ripemd160_hex = ripemd160_file_hex('filename.dat');
   $ripemd160_b64 = ripemd160_file_base64('filename.dat');
   # calculate digest from filehandle
   $ripemd160_raw = ripemd160_file(*FILEHANDLE);
   $ripemd160_hex = ripemd160_file_hex(*FILEHANDLE);
   $ripemd160_b64 = ripemd160_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::RIPEMD160;

   $d = Crypt::Digest::RIPEMD160->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the RIPEMD160 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::RIPEMD160 qw(ripemd160 ripemd160_hex ripemd160_base64 ripemd160_file ripemd160_file_hex ripemd160_file_base64);

Or all of them at once:

  use Crypt::Digest::RIPEMD160 ':all';

=head1 FUNCTIONS

=head2 ripemd160

Logically joins all arguments into a single string, and returns its RIPEMD160 digest encoded as a binary string.

 $ripemd160_raw = ripemd160('data string');
 #or
 $ripemd160_raw = ripemd160('any data', 'more data', 'even more data');

=head2 ripemd160_hex

Logically joins all arguments into a single string, and returns its RIPEMD160 digest encoded as a hexadecimal string.

 $ripemd160_hex = ripemd160_hex('data string');
 #or
 $ripemd160_hex = ripemd160('any data', 'more data', 'even more data');

=head2 ripemd160_base64

Logically joins all arguments into a single string, and returns its RIPEMD160 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $ripemd160_base64 = ripemd160_base64('data string');
 #or
 $ripemd160_base64 = ripemd160('any data', 'more data', 'even more data');

=head2 ripemd160_file

Reads file (defined by filename or filehandle) content, and returns its RIPEMD160 digest encoded as a binary string.

 $ripemd160_raw = ripemd160_file('filename.dat');
 #or
 $ripemd160_raw = ripemd160_file(*FILEHANDLE);

=head2 ripemd160_file_hex

Reads file (defined by filename or filehandle) content, and returns its RIPEMD160 digest encoded as a hexadecimal string.

 $ripemd160_hex = ripemd160_file_hex('filename.dat');
 #or
 $ripemd160_hex = ripemd160_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 ripemd160_file_base64

Reads file (defined by filename or filehandle) content, and returns its RIPEMD160 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $ripemd160_base64 = ripemd160_file_base64('filename.dat');
 #or
 $ripemd160_base64 = ripemd160_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::RIPEMD160->new();

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

=head2 add_bits

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

=head2 hashsize

 $d->hashsize;
 #or
 Crypt::Digest::RIPEMD160->hashsize();
 #or
 Crypt::Digest::RIPEMD160::hashsize();

=head2 digest

 $result_raw = $d->digest();

=head2 hexdigest

 $result_hex = $d->hexdigest();

=head2 b64digest

 $result_base64 = $d->b64digest();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Digest|Crypt::Digest>

=item L<http://en.wikipedia.org/wiki/RIPEMD|http://en.wikipedia.org/wiki/RIPEMD>

=back

=cut

__END__