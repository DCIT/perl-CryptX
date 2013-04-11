package Crypt::Digest::SHA224;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( sha224 sha224_hex sha224_base64 sha224_file sha224_file_hex sha224_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub sha224             { __PACKAGE__->new->add(@_)->digest }
sub sha224_hex         { __PACKAGE__->new->add(@_)->hexdigest }
sub sha224_base64      { __PACKAGE__->new->add(@_)->b64digest }

sub sha224_file        { __PACKAGE__->new->addfile(@_)->digest }
sub sha224_file_hex    { __PACKAGE__->new->addfile(@_)->hexdigest }
sub sha224_file_base64 { __PACKAGE__->new->addfile(@_)->b64digest }

1;

=pod

=head1 NAME

Crypt::Digest::SHA224 - Hash function SHA-224 [size: 224 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::SHA224 qw( sha224 sha224_hex sha224_base64 sha224_file sha224_file_hex sha224_file_base64 );

   # calculate digest from string/buffer
   $sha224_raw = sha224('data string');
   $sha224_hex = sha224_hex('data string');
   $sha224_b64 = sha224_base64('data string');
   # calculate digest from file
   $sha224_raw = sha224_file('filename.dat');
   $sha224_hex = sha224_file_hex('filename.dat');
   $sha224_b64 = sha224_file_base64('filename.dat');
   # calculate digest from filehandle
   $sha224_raw = sha224_file(*FILEHANDLE);
   $sha224_hex = sha224_file_hex(*FILEHANDLE);
   $sha224_b64 = sha224_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::SHA224;

   $d = Crypt::Digest::SHA224->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the SHA224 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::SHA224 qw(sha224 sha224_hex sha224_base64 sha224_file sha224_file_hex sha224_file_base64);

Or all of them at once:

  use Crypt::Digest::SHA224 ':all';

=head1 FUNCTIONS

=head2 sha224

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a binary string.

 $sha224_raw = sha224('data string');
 #or
 $sha224_raw = sha224('any data', 'more data', 'even more data');

=head2 sha224_hex

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a hexadecimal string.

 $sha224_hex = sha224_hex('data string');
 #or
 $sha224_hex = sha224('any data', 'more data', 'even more data');

=head2 sha224_base64

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $sha224_base64 = sha224_base64('data string');
 #or
 $sha224_base64 = sha224('any data', 'more data', 'even more data');

=head2 sha224_file

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a binary string.

 $sha224_raw = sha224_file('filename.dat');
 #or
 $sha224_raw = sha224_file(*FILEHANDLE);

=head2 sha224_file_hex

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a hexadecimal string.

 $sha224_hex = sha224_file_hex('filename.dat');
 #or
 $sha224_hex = sha224_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 sha224_file_base64

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $sha224_base64 = sha224_file_base64('filename.dat');
 #or
 $sha224_base64 = sha224_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::SHA224->new();

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
 Crypt::Digest::SHA224->hashsize();
 #or
 Crypt::Digest::SHA224::hashsize();

=head2 digest

 $result_raw = $d->digest();

=head2 hexdigest

 $result_hex = $d->hexdigest();

=head2 b64digest

 $result_base64 = $d->b64digest();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Digest|Crypt::Digest>

=item L<http://en.wikipedia.org/wiki/SHA-2|http://en.wikipedia.org/wiki/SHA-2>

=back

=cut

__END__