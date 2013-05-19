package Crypt::Digest::SHA256;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( sha256 sha256_hex sha256_base64 sha256_file sha256_file_hex sha256_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub sha256             { Crypt::Digest::digest_data(__PACKAGE__, @_) }
sub sha256_hex         { Crypt::Digest::digest_data_hex(__PACKAGE__, @_) }
sub sha256_base64      { Crypt::Digest::digest_data_base64(__PACKAGE__, @_) }

sub sha256_file        { Crypt::Digest::digest_file(__PACKAGE__, @_) }
sub sha256_file_hex    { Crypt::Digest::digest_file_hex(__PACKAGE__, @_) }
sub sha256_file_base64 { Crypt::Digest::digest_file_base64(__PACKAGE__, @_) }

1;

=pod

=head1 NAME

Crypt::Digest::SHA256 - Hash function SHA-256 [size: 256 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::SHA256 qw( sha256 sha256_hex sha256_base64 sha256_file sha256_file_hex sha256_file_base64 );

   # calculate digest from string/buffer
   $sha256_raw = sha256('data string');
   $sha256_hex = sha256_hex('data string');
   $sha256_b64 = sha256_base64('data string');
   # calculate digest from file
   $sha256_raw = sha256_file('filename.dat');
   $sha256_hex = sha256_file_hex('filename.dat');
   $sha256_b64 = sha256_file_base64('filename.dat');
   # calculate digest from filehandle
   $sha256_raw = sha256_file(*FILEHANDLE);
   $sha256_hex = sha256_file_hex(*FILEHANDLE);
   $sha256_b64 = sha256_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::SHA256;

   $d = Crypt::Digest::SHA256->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the SHA256 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::SHA256 qw(sha256 sha256_hex sha256_base64 sha256_file sha256_file_hex sha256_file_base64);

Or all of them at once:

  use Crypt::Digest::SHA256 ':all';

=head1 FUNCTIONS

=head2 sha256

Logically joins all arguments into a single string, and returns its SHA256 digest encoded as a binary string.

 $sha256_raw = sha256('data string');
 #or
 $sha256_raw = sha256('any data', 'more data', 'even more data');

=head2 sha256_hex

Logically joins all arguments into a single string, and returns its SHA256 digest encoded as a hexadecimal string.

 $sha256_hex = sha256_hex('data string');
 #or
 $sha256_hex = sha256_hex('any data', 'more data', 'even more data');

=head2 sha256_base64

Logically joins all arguments into a single string, and returns its SHA256 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $sha256_base64 = sha256_base64('data string');
 #or
 $sha256_base64 = sha256_base64('any data', 'more data', 'even more data');

=head2 sha256_file

Reads file (defined by filename or filehandle) content, and returns its SHA256 digest encoded as a binary string.

 $sha256_raw = sha256_file('filename.dat');
 #or
 $sha256_raw = sha256_file(*FILEHANDLE);

=head2 sha256_file_hex

Reads file (defined by filename or filehandle) content, and returns its SHA256 digest encoded as a hexadecimal string.

 $sha256_hex = sha256_file_hex('filename.dat');
 #or
 $sha256_hex = sha256_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 sha256_file_base64

Reads file (defined by filename or filehandle) content, and returns its SHA256 digest encoded as a Base64 string, B<with> trailing '=' padding.

 $sha256_base64 = sha256_file_base64('filename.dat');
 #or
 $sha256_base64 = sha256_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::SHA256->new();

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
 Crypt::Digest::SHA256->hashsize();
 #or
 Crypt::Digest::SHA256::hashsize();

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