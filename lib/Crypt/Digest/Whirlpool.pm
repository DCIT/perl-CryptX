package Crypt::Digest::Whirlpool;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( whirlpool whirlpool_hex whirlpool_base64 whirlpool_file whirlpool_file_hex whirlpool_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub whirlpool             { Crypt::Digest::digest_data(__PACKAGE__, @_) }
sub whirlpool_hex         { Crypt::Digest::digest_data_hex(__PACKAGE__, @_) }
sub whirlpool_base64      { Crypt::Digest::digest_data_base64(__PACKAGE__, @_) }

sub whirlpool_file        { Crypt::Digest::digest_file(__PACKAGE__, @_) }
sub whirlpool_file_hex    { Crypt::Digest::digest_file_hex(__PACKAGE__, @_) }
sub whirlpool_file_base64 { Crypt::Digest::digest_file_base64(__PACKAGE__, @_) }

1;

=pod

=head1 NAME

Crypt::Digest::Whirlpool - Hash function Whirlpool [size: 512 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::Whirlpool qw( whirlpool whirlpool_hex whirlpool_base64 whirlpool_file whirlpool_file_hex whirlpool_file_base64 );

   # calculate digest from string/buffer
   $whirlpool_raw = whirlpool('data string');
   $whirlpool_hex = whirlpool_hex('data string');
   $whirlpool_b64 = whirlpool_base64('data string');
   # calculate digest from file
   $whirlpool_raw = whirlpool_file('filename.dat');
   $whirlpool_hex = whirlpool_file_hex('filename.dat');
   $whirlpool_b64 = whirlpool_file_base64('filename.dat');
   # calculate digest from filehandle
   $whirlpool_raw = whirlpool_file(*FILEHANDLE);
   $whirlpool_hex = whirlpool_file_hex(*FILEHANDLE);
   $whirlpool_b64 = whirlpool_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::Whirlpool;

   $d = Crypt::Digest::Whirlpool->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the Whirlpool digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::Whirlpool qw(whirlpool whirlpool_hex whirlpool_base64 whirlpool_file whirlpool_file_hex whirlpool_file_base64);

Or all of them at once:

  use Crypt::Digest::Whirlpool ':all';

=head1 FUNCTIONS

=head2 whirlpool

Logically joins all arguments into a single string, and returns its Whirlpool digest encoded as a binary string.

 $whirlpool_raw = whirlpool('data string');
 #or
 $whirlpool_raw = whirlpool('any data', 'more data', 'even more data');

=head2 whirlpool_hex

Logically joins all arguments into a single string, and returns its Whirlpool digest encoded as a hexadecimal string.

 $whirlpool_hex = whirlpool_hex('data string');
 #or
 $whirlpool_hex = whirlpool_hex('any data', 'more data', 'even more data');

=head2 whirlpool_base64

Logically joins all arguments into a single string, and returns its Whirlpool digest encoded as a Base64 string, B<with> trailing '=' padding.

 $whirlpool_base64 = whirlpool_base64('data string');
 #or
 $whirlpool_base64 = whirlpool_base64('any data', 'more data', 'even more data');

=head2 whirlpool_file

Reads file (defined by filename or filehandle) content, and returns its Whirlpool digest encoded as a binary string.

 $whirlpool_raw = whirlpool_file('filename.dat');
 #or
 $whirlpool_raw = whirlpool_file(*FILEHANDLE);

=head2 whirlpool_file_hex

Reads file (defined by filename or filehandle) content, and returns its Whirlpool digest encoded as a hexadecimal string.

 $whirlpool_hex = whirlpool_file_hex('filename.dat');
 #or
 $whirlpool_hex = whirlpool_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 whirlpool_file_base64

Reads file (defined by filename or filehandle) content, and returns its Whirlpool digest encoded as a Base64 string, B<with> trailing '=' padding.

 $whirlpool_base64 = whirlpool_file_base64('filename.dat');
 #or
 $whirlpool_base64 = whirlpool_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::Whirlpool->new();

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
 Crypt::Digest::Whirlpool->hashsize();
 #or
 Crypt::Digest::Whirlpool::hashsize();

=head2 digest

 $result_raw = $d->digest();

=head2 hexdigest

 $result_hex = $d->hexdigest();

=head2 b64digest

 $result_base64 = $d->b64digest();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Digest|Crypt::Digest>

=item L<http://en.wikipedia.org/wiki/Whirlpool_(cryptography)|http://en.wikipedia.org/wiki/Whirlpool_(cryptography)>

=back

=cut

__END__