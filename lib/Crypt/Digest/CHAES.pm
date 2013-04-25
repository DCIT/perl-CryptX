package Crypt::Digest::CHAES;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( chaes chaes_hex chaes_base64 chaes_file chaes_file_hex chaes_file_base64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;
use base 'Crypt::Digest';

sub hashsize { Crypt::Digest::hashsize(__PACKAGE__) }

sub chaes             { Crypt::Digest::digest_data(__PACKAGE__, @_) }
sub chaes_hex         { Crypt::Digest::digest_data_hex(__PACKAGE__, @_) }
sub chaes_base64      { Crypt::Digest::digest_data_base64(__PACKAGE__, @_) }

sub chaes_file        { Crypt::Digest::digest_file(__PACKAGE__, @_) }
sub chaes_file_hex    { Crypt::Digest::digest_file_hex(__PACKAGE__, @_) }
sub chaes_file_base64 { Crypt::Digest::digest_file_base64(__PACKAGE__, @_) }

1;

=pod

=head1 NAME

Crypt::Digest::CHAES - Hash function - CipherHash based on AES [size: 128 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::CHAES qw( chaes chaes_hex chaes_base64 chaes_file chaes_file_hex chaes_file_base64 );

   # calculate digest from string/buffer
   $chaes_raw = chaes('data string');
   $chaes_hex = chaes_hex('data string');
   $chaes_b64 = chaes_base64('data string');
   # calculate digest from file
   $chaes_raw = chaes_file('filename.dat');
   $chaes_hex = chaes_file_hex('filename.dat');
   $chaes_b64 = chaes_file_base64('filename.dat');
   # calculate digest from filehandle
   $chaes_raw = chaes_file(*FILEHANDLE);
   $chaes_hex = chaes_file_hex(*FILEHANDLE);
   $chaes_b64 = chaes_file_base64(*FILEHANDLE);

   ### OO interface:
   use Crypt::Digest::CHAES;

   $d = Crypt::Digest::CHAES->new;
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->digest;    # raw bytes
   $result_hex = $d->hexdigest; # hexadecimal form
   $result_b64 = $d->b64digest; # Base64 form

=head1 DESCRIPTION

Provides an interface to the CHAES digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::CHAES qw(chaes chaes_hex chaes_base64 chaes_file chaes_file_hex chaes_file_base64);

Or all of them at once:

  use Crypt::Digest::CHAES ':all';

=head1 FUNCTIONS

=head2 chaes

Logically joins all arguments into a single string, and returns its CHAES digest encoded as a binary string.

 $chaes_raw = chaes('data string');
 #or
 $chaes_raw = chaes('any data', 'more data', 'even more data');

=head2 chaes_hex

Logically joins all arguments into a single string, and returns its CHAES digest encoded as a hexadecimal string.

 $chaes_hex = chaes_hex('data string');
 #or
 $chaes_hex = chaes('any data', 'more data', 'even more data');

=head2 chaes_base64

Logically joins all arguments into a single string, and returns its CHAES digest encoded as a Base64 string, B<with> trailing '=' padding.

 $chaes_base64 = chaes_base64('data string');
 #or
 $chaes_base64 = chaes('any data', 'more data', 'even more data');

=head2 chaes_file

Reads file (defined by filename or filehandle) content, and returns its CHAES digest encoded as a binary string.

 $chaes_raw = chaes_file('filename.dat');
 #or
 $chaes_raw = chaes_file(*FILEHANDLE);

=head2 chaes_file_hex

Reads file (defined by filename or filehandle) content, and returns its CHAES digest encoded as a hexadecimal string.

 $chaes_hex = chaes_file_hex('filename.dat');
 #or
 $chaes_hex = chaes_file_hex(*FILEHANDLE);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 chaes_file_base64

Reads file (defined by filename or filehandle) content, and returns its CHAES digest encoded as a Base64 string, B<with> trailing '=' padding.

 $chaes_base64 = chaes_file_base64('filename.dat');
 #or
 $chaes_base64 = chaes_file_base64(*FILEHANDLE);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.

=head2 new

 $d = Crypt::Digest::CHAES->new();

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
 Crypt::Digest::CHAES->hashsize();
 #or
 Crypt::Digest::CHAES::hashsize();

=head2 digest

 $result_raw = $d->digest();

=head2 hexdigest

 $result_hex = $d->hexdigest();

=head2 b64digest

 $result_base64 = $d->b64digest();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Digest|Crypt::Digest>

=item L<http://en.wikipedia.org/wiki/Cryptographic_hash_function#Hash_functions_based_on_block_ciphers|http://en.wikipedia.org/wiki/Cryptographic_hash_function#Hash_functions_based_on_block_ciphers>

=back

=cut

__END__