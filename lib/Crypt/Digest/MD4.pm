package Crypt::Digest::MD4;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( md4 md4_hex md4_base64 md4_file md4_file_hex md4_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub md4             { Crypt::Digest::digest_data(__PACKAGE__, @_) }
sub md4_hex         { Crypt::Digest::digest_data_hex(__PACKAGE__, @_) }
sub md4_base64      { Crypt::Digest::digest_data_base64(__PACKAGE__, @_) }

sub md4_file        { Crypt::Digest::digest_file(__PACKAGE__, @_) }
sub md4_file_hex    { Crypt::Digest::digest_file_hex(__PACKAGE__, @_) }
sub md4_file_base64 { Crypt::Digest::digest_file_base64(__PACKAGE__, @_) }

1;

=pod

=head1 NAME

Crypt::Digest::MD4 - Hash function MD4 [size: 128 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::MD4 qw( md4 md4_hex md4_base64 md4_file md4_file_hex md4_file_base64 );

   # calculate digest from string/buffer
   $md4_raw = md4('data string');
   $md4_hex = md4_hex('data string');
   $md4_b64 = md4_base64('data string');
   # calculate digest from file
   $md4_raw = md4_file('filename.dat');
   $md4_hex = md4_file_hex('filename.dat');
   $md4_b64 = md4_file_base64('filename.dat');
   # calculate digest from filehandle
   $md4_raw = md4_file(*FILEHANDLE);
   $md4_hex = md4_file_hex(*FILEHANDLE);
   $md4_b64 = md4_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::MD4;

   $d = Crypt::Digest::MD4->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the MD4 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::MD4 qw(md4 md4_hex md4_base64 md4_file md4_file_hex md4_file_base64);

Or all of them at once:

  use Crypt::Digest::MD4 ':all';

=head1 FUNCTIONS

=head2 md4

Logically joins all arguments into a single string, and returns its MD4 digest encoded as a binary string.

 $md4_raw = md4('data string');
 #or
 $md4_raw = md4('any data', 'more data', 'even more data');

=head2 md4_hex

Logically joins all arguments into a single string, and returns its MD4 digest encoded as a hexadecimal string.

 $md4_hex = md4_hex('data string');
 #or
 $md4_hex = md4('any data', 'more data', 'even more data');

=head2 md4_base64

Logically joins all arguments into a single string, and returns its MD4 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $md4_base64 = md4_base64('data string');
 #or
 $md4_base64 = md4('any data', 'more data', 'even more data');

=head2 md4_file

Reads file (defined by filename or filehandle) content, and returns its MD4 digest encoded as a binary string.

 $md4_raw = md4_file('filename.dat');
 #or
 $md4_raw = md4_file(*FILEHANDLE);

=head2 md4_file_hex

Reads file (defined by filename or filehandle) content, and returns its MD4 digest encoded as a hexadecimal string.

 $md4_hex = md4_file_hex('filename.dat');
 #or
 $md4_hex = md4_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 md4_file_base64

Reads file (defined by filename or filehandle) content, and returns its MD4 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $md4_base64 = md4_file_base64('filename.dat');
 #or
 $md4_base64 = md4_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::MD4->new();

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
 Crypt::Digest::MD4->hashsize();
 #or
 Crypt::Digest::MD4::hashsize();

=head2 digest

 $result_raw = $d->digest();

=head2 hexdigest

 $result_hex = $d->hexdigest();

=head2 b64digest

 $result_base64 = $d->b64digest();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Digest|Crypt::Digest>

=item L<http://en.wikipedia.org/wiki/MD4|http://en.wikipedia.org/wiki/MD4>

=back

=cut

__END__