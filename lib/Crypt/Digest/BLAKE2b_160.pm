package Crypt::Digest::BLAKE2b_160;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( blake2b_160 blake2b_160_hex blake2b_160_b64 blake2b_160_b64u blake2b_160_file blake2b_160_file_hex blake2b_160_file_b64 blake2b_160_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub hashsize                { Crypt::Digest::hashsize('BLAKE2b_160')             }
sub blake2b_160             { Crypt::Digest::digest_data('BLAKE2b_160', @_)      }
sub blake2b_160_hex         { Crypt::Digest::digest_data_hex('BLAKE2b_160', @_)  }
sub blake2b_160_b64         { Crypt::Digest::digest_data_b64('BLAKE2b_160', @_)  }
sub blake2b_160_b64u        { Crypt::Digest::digest_data_b64u('BLAKE2b_160', @_) }
sub blake2b_160_file        { Crypt::Digest::digest_file('BLAKE2b_160', @_)      }
sub blake2b_160_file_hex    { Crypt::Digest::digest_file_hex('BLAKE2b_160', @_)  }
sub blake2b_160_file_b64    { Crypt::Digest::digest_file_b64('BLAKE2b_160', @_)  }
sub blake2b_160_file_b64u   { Crypt::Digest::digest_file_b64u('BLAKE2b_160', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::BLAKE2b_160 - Hash function BLAKE2b [size: 160 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::BLAKE2b_160 qw( blake2b_160 blake2b_160_hex blake2b_160_b64 blake2b_160_b64u
                                blake2b_160_file blake2b_160_file_hex blake2b_160_file_b64 blake2b_160_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $blake2b_160_raw  = blake2b_160($data);
   my $blake2b_160_hex  = blake2b_160_hex($data);
   my $blake2b_160_b64  = blake2b_160_b64($data);
   my $blake2b_160_b64u = blake2b_160_b64u($data);
   # or from file
   my $blake2b_160_file_raw  = blake2b_160_file('filename.dat');
   my $blake2b_160_file_hex  = blake2b_160_file_hex('filename.dat');
   my $blake2b_160_file_b64  = blake2b_160_file_b64('filename.dat');
   my $blake2b_160_file_b64u = blake2b_160_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $blake2b_160_fh_raw  = blake2b_160_file($filehandle);
   my $blake2b_160_fh_hex  = blake2b_160_file_hex($filehandle);
   my $blake2b_160_fh_b64  = blake2b_160_file_b64($filehandle);
   my $blake2b_160_fh_b64u = blake2b_160_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::BLAKE2b_160;

   my $d = Crypt::Digest::BLAKE2b_160->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::BLAKE2b_160->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Provides an interface to the BLAKE2b_160 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::BLAKE2b_160 qw(blake2b_160 blake2b_160_hex blake2b_160_b64 blake2b_160_b64u
                                      blake2b_160_file blake2b_160_file_hex blake2b_160_file_b64 blake2b_160_file_b64u);

Or all of them at once:

  use Crypt::Digest::BLAKE2b_160 ':all';

=head1 FUNCTIONS

=head2 blake2b_160

Logically joins all arguments into a single string, and returns its BLAKE2b_160 digest encoded as a binary string.

 my $blake2b_160_raw = blake2b_160('data string');
 #or
 my $blake2b_160_raw = blake2b_160('any data', 'more data', 'even more data');

=head2 blake2b_160_hex

Logically joins all arguments into a single string, and returns its BLAKE2b_160 digest encoded as a hexadecimal string.

 my $blake2b_160_hex = blake2b_160_hex('data string');
 #or
 my $blake2b_160_hex = blake2b_160_hex('any data', 'more data', 'even more data');

=head2 blake2b_160_b64

Logically joins all arguments into a single string, and returns its BLAKE2b_160 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $blake2b_160_b64 = blake2b_160_b64('data string');
 #or
 my $blake2b_160_b64 = blake2b_160_b64('any data', 'more data', 'even more data');

=head2 blake2b_160_b64u

Logically joins all arguments into a single string, and returns its BLAKE2b_160 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $blake2b_160_b64url = blake2b_160_b64u('data string');
 #or
 my $blake2b_160_b64url = blake2b_160_b64u('any data', 'more data', 'even more data');

=head2 blake2b_160_file

Reads file (defined by filename or filehandle) content, and returns its BLAKE2b_160 digest encoded as a binary string.

 my $blake2b_160_raw = blake2b_160_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $blake2b_160_raw = blake2b_160_file($filehandle);

=head2 blake2b_160_file_hex

Reads file (defined by filename or filehandle) content, and returns its BLAKE2b_160 digest encoded as a hexadecimal string.

 my $blake2b_160_hex = blake2b_160_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $blake2b_160_hex = blake2b_160_file_hex($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 blake2b_160_file_b64

Reads file (defined by filename or filehandle) content, and returns its BLAKE2b_160 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $blake2b_160_b64 = blake2b_160_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $blake2b_160_b64 = blake2b_160_file_b64($filehandle);

=head2 blake2b_160_file_b64u

Reads file (defined by filename or filehandle) content, and returns its BLAKE2b_160 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $blake2b_160_b64url = blake2b_160_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $blake2b_160_b64url = blake2b_160_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::BLAKE2b_160->new();

=head2 new

 my $d = Crypt::Digest::BLAKE2b_160->new();

=head2 clone

 $d->clone();

=head2 reset

 $d->reset();

=head2 add

Appends data to the message. Returns the object itself (for chaining).

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 add_bits

 $d->add_bits($bit_string);   # e.g. $d->add_bits("111100001010");
 #or
 $d->add_bits($data, $nbits); # e.g. $d->add_bits("\xF0\xA0", 16);

=head2 hashsize

 $d->hashsize;
 #or
 Crypt::Digest::BLAKE2b_160->hashsize();
 #or
 Crypt::Digest::BLAKE2b_160::hashsize();

=head2 digest

Returns the binary digest (raw bytes).

 my $result_raw = $d->digest();

=head2 hexdigest

Returns the digest encoded as a lowercase hexadecimal string.

 my $result_hex = $d->hexdigest();

=head2 b64digest

Returns the digest encoded as a Base64 string with trailing C<=> padding.

 my $result_b64 = $d->b64digest();

=head2 b64udigest

Returns the digest encoded as a Base64 URL Safe string (no trailing C<=>).

 my $result_b64url = $d->b64udigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest>

=item * L<https://blake2.net/>

=item * L<https://www.rfc-editor.org/rfc/rfc7693>

=back

=cut
