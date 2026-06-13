package Crypt::Digest::SM3;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.090';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( sm3 sm3_hex sm3_b64 sm3_b64u sm3_file sm3_file_hex sm3_file_b64 sm3_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub new {
  my ($class) = @_;
  my $obj = Crypt::Digest->new('SM3');
  return bless $obj, $class;
}

sub clone {
  my ($self) = @_;
  my $obj = Crypt::Digest::clone($self);
  return bless $obj, ref($self) || $self;
}

sub hashsize                { Crypt::Digest::hashsize('SM3')             }
sub sm3             { Crypt::Digest::digest_data('SM3', @_)      }
sub sm3_hex         { Crypt::Digest::digest_data_hex('SM3', @_)  }
sub sm3_b64         { Crypt::Digest::digest_data_b64('SM3', @_)  }
sub sm3_b64u        { Crypt::Digest::digest_data_b64u('SM3', @_) }
sub sm3_file        { Crypt::Digest::digest_file('SM3', @_)      }
sub sm3_file_hex    { Crypt::Digest::digest_file_hex('SM3', @_)  }
sub sm3_file_b64    { Crypt::Digest::digest_file_b64('SM3', @_)  }
sub sm3_file_b64u   { Crypt::Digest::digest_file_b64u('SM3', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::SM3 - Hash function SM3 [size: 256 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::SM3 qw( sm3 sm3_hex sm3_b64 sm3_b64u
                                sm3_file sm3_file_hex sm3_file_b64 sm3_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $sm3_raw  = sm3($data);
   my $sm3_hex  = sm3_hex($data);
   my $sm3_b64  = sm3_b64($data);
   my $sm3_b64u = sm3_b64u($data);
   # or from file
   my $sm3_file_raw  = sm3_file('filename.dat');
   my $sm3_file_hex  = sm3_file_hex('filename.dat');
   my $sm3_file_b64  = sm3_file_b64('filename.dat');
   my $sm3_file_b64u = sm3_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $sm3_fh_raw  = sm3_file($filehandle);
   my $sm3_fh_hex  = sm3_file_hex($filehandle);
   my $sm3_fh_b64  = sm3_file_b64($filehandle);
   my $sm3_fh_b64u = sm3_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::SM3;

   my $d = Crypt::Digest::SM3->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL-safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::SM3->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

I<Since: CryptX-0.090>

Provides an interface to the SM3 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::SM3 qw(sm3 sm3_hex sm3_b64 sm3_b64u
                                      sm3_file sm3_file_hex sm3_file_b64 sm3_file_b64u);

Or all of them at once:

  use Crypt::Digest::SM3 ':all';

=head1 FUNCTIONS

=head2 sm3

Joins all arguments into a single string and returns its SM3 digest encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<sm3_hex>, C<sm3_b64>, and
C<sm3_b64u>.

 my $sm3_raw = sm3('data string');
 #or
 my $sm3_raw = sm3('any data', 'more data', 'even more data');

=head2 sm3_hex

Joins all arguments into a single string and returns its SM3 digest encoded as a hexadecimal string.

 my $sm3_hex = sm3_hex('data string');
 #or
 my $sm3_hex = sm3_hex('any data', 'more data', 'even more data');

=head2 sm3_b64

Joins all arguments into a single string and returns its SM3 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $sm3_b64 = sm3_b64('data string');
 #or
 my $sm3_b64 = sm3_b64('any data', 'more data', 'even more data');

=head2 sm3_b64u

Joins all arguments into a single string and returns its SM3 digest encoded as a Base64 URL-safe string (see RFC 4648 section 5).

 my $sm3_b64url = sm3_b64u('data string');
 #or
 my $sm3_b64url = sm3_b64u('any data', 'more data', 'even more data');

=head2 sm3_file

Reads a file given by a filename or filehandle and returns its SM3 digest encoded as a binary string.

 my $sm3_raw = sm3_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sm3_raw = sm3_file($filehandle);

=head2 sm3_file_hex

Reads a file given by a filename or filehandle and returns its SM3 digest encoded as a hexadecimal string.

 my $sm3_hex = sm3_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sm3_hex = sm3_file_hex($filehandle);

B<Note:> The filehandle must be in binary mode before you pass it to C<addfile()>.

=head2 sm3_file_b64

Reads a file given by a filename or filehandle and returns its SM3 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $sm3_b64 = sm3_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sm3_b64 = sm3_file_b64($filehandle);

=head2 sm3_file_b64u

Reads a file given by a filename or filehandle and returns its SM3 digest encoded as a Base64 URL-safe string (see RFC 4648 section 5).

 my $sm3_b64url = sm3_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sm3_b64url = sm3_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::SM3->new();

=head2 new

 my $d = Crypt::Digest::SM3->new();

=head2 clone

 $d->clone();

=head2 reset

 $d->reset();

=head2 add

Appends data to the message. Returns the object itself (for chaining).

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 hashsize

 $d->hashsize;
 #or
 Crypt::Digest::SM3->hashsize();
 #or
 Crypt::Digest::SM3::hashsize();

=head2 digest

Returns the binary digest (raw bytes).
The first call finalizes the digest object. Any later C<add()>,
C<addfile()>, C<digest()>, C<hexdigest()>, C<b64digest()>, or
C<b64udigest()> call will fail until you call C<reset()>.

 my $result_raw = $d->digest();

=head2 hexdigest

Returns the digest encoded as a lowercase hexadecimal string.
Like C<digest()>, the first call finalizes the digest object.

 my $result_hex = $d->hexdigest();

=head2 b64digest

Returns the digest encoded as a Base64 string with trailing C<=> padding.
Like C<digest()>, the first call finalizes the digest object.

 my $result_b64 = $d->b64digest();

=head2 b64udigest

Returns the digest encoded as a Base64 URL-safe string (no trailing C<=>).
Like C<digest()>, the first call finalizes the digest object.

 my $result_b64url = $d->b64udigest();

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Digest>

=item * L<https://en.wikipedia.org/wiki/SM3_(hash_function)>

=item * L<https://datatracker.ietf.org/doc/html/draft-shen-sm3-hash>

=back

=cut
