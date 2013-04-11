package Crypt::Digest::RIPEMD320;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( ripemd320 ripemd320_hex ripemd320_base64 ripemd320_file ripemd320_file_hex ripemd320_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub ripemd320             { __PACKAGE__->new->add(@_)->digest }
sub ripemd320_hex         { __PACKAGE__->new->add(@_)->hexdigest }
sub ripemd320_base64      { __PACKAGE__->new->add(@_)->b64digest }

sub ripemd320_file        { __PACKAGE__->new->addfile(@_)->digest }
sub ripemd320_file_hex    { __PACKAGE__->new->addfile(@_)->hexdigest }
sub ripemd320_file_base64 { __PACKAGE__->new->addfile(@_)->b64digest }

1;

=pod

=head1 NAME

Crypt::Digest::RIPEMD320 - Hash function RIPEMD-320 [size: 320 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::RIPEMD320 qw( ripemd320 ripemd320_hex ripemd320_base64 ripemd320_file ripemd320_file_hex ripemd320_file_base64 );

   # calculate digest from string/buffer
   $ripemd320_raw = ripemd320('data string');
   $ripemd320_hex = ripemd320_hex('data string');
   $ripemd320_b64 = ripemd320_base64('data string');
   # calculate digest from file
   $ripemd320_raw = ripemd320_file('filename.dat');
   $ripemd320_hex = ripemd320_file_hex('filename.dat');
   $ripemd320_b64 = ripemd320_file_base64('filename.dat');
   # calculate digest from filehandle
   $ripemd320_raw = ripemd320_file(*FILEHANDLE);
   $ripemd320_hex = ripemd320_file_hex(*FILEHANDLE);
   $ripemd320_b64 = ripemd320_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::RIPEMD320;

   $d = Crypt::Digest::RIPEMD320->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the RIPEMD320 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::RIPEMD320 qw(ripemd320 ripemd320_hex ripemd320_base64 ripemd320_file ripemd320_file_hex ripemd320_file_base64);

Or all of them at once:

  use Crypt::Digest::RIPEMD320 ':all';

=head1 FUNCTIONS

=head2 ripemd320

Logically joins all arguments into a single string, and returns its RIPEMD320 digest encoded as a binary string.

 $ripemd320_raw = ripemd320('data string');
 #or
 $ripemd320_raw = ripemd320('any data', 'more data', 'even more data');

=head2 ripemd320_hex

Logically joins all arguments into a single string, and returns its RIPEMD320 digest encoded as a hexadecimal string.

 $ripemd320_hex = ripemd320_hex('data string');
 #or
 $ripemd320_hex = ripemd320('any data', 'more data', 'even more data');

=head2 ripemd320_base64

Logically joins all arguments into a single string, and returns its RIPEMD320 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $ripemd320_base64 = ripemd320_base64('data string');
 #or
 $ripemd320_base64 = ripemd320('any data', 'more data', 'even more data');

=head2 ripemd320_file

Reads file (defined by filename or filehandle) content, and returns its RIPEMD320 digest encoded as a binary string.

 $ripemd320_raw = ripemd320_file('filename.dat');
 #or
 $ripemd320_raw = ripemd320_file(*FILEHANDLE);

=head2 ripemd320_file_hex

Reads file (defined by filename or filehandle) content, and returns its RIPEMD320 digest encoded as a hexadecimal string.

 $ripemd320_hex = ripemd320_file_hex('filename.dat');
 #or
 $ripemd320_hex = ripemd320_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 ripemd320_file_base64

Reads file (defined by filename or filehandle) content, and returns its RIPEMD320 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $ripemd320_base64 = ripemd320_file_base64('filename.dat');
 #or
 $ripemd320_base64 = ripemd320_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::RIPEMD320->new();

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
 Crypt::Digest::RIPEMD320->hashsize();
 #or
 Crypt::Digest::RIPEMD320::hashsize();

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