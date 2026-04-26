package Crypt::Digest::SHA224;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( sha224 sha224_hex sha224_b64 sha224_b64u sha224_file sha224_file_hex sha224_file_b64 sha224_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub new {
  my ($class) = @_;
  my $obj = Crypt::Digest->new('SHA224');
  return bless $obj, $class;
}

sub clone {
  my ($self) = @_;
  my $obj = Crypt::Digest::clone($self);
  return bless $obj, ref($self) || $self;
}

sub hashsize                { Crypt::Digest::hashsize('SHA224')             }
sub sha224             { Crypt::Digest::digest_data('SHA224', @_)      }
sub sha224_hex         { Crypt::Digest::digest_data_hex('SHA224', @_)  }
sub sha224_b64         { Crypt::Digest::digest_data_b64('SHA224', @_)  }
sub sha224_b64u        { Crypt::Digest::digest_data_b64u('SHA224', @_) }
sub sha224_file        { Crypt::Digest::digest_file('SHA224', @_)      }
sub sha224_file_hex    { Crypt::Digest::digest_file_hex('SHA224', @_)  }
sub sha224_file_b64    { Crypt::Digest::digest_file_b64('SHA224', @_)  }
sub sha224_file_b64u   { Crypt::Digest::digest_file_b64u('SHA224', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::SHA224 - Hash function SHA-224 [size: 224 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::SHA224 qw( sha224 sha224_hex sha224_b64 sha224_b64u
                                sha224_file sha224_file_hex sha224_file_b64 sha224_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $sha224_raw  = sha224($data);
   my $sha224_hex  = sha224_hex($data);
   my $sha224_b64  = sha224_b64($data);
   my $sha224_b64u = sha224_b64u($data);
   # or from file
   my $sha224_file_raw  = sha224_file('filename.dat');
   my $sha224_file_hex  = sha224_file_hex('filename.dat');
   my $sha224_file_b64  = sha224_file_b64('filename.dat');
   my $sha224_file_b64u = sha224_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $sha224_fh_raw  = sha224_file($filehandle);
   my $sha224_fh_hex  = sha224_file_hex($filehandle);
   my $sha224_fh_b64  = sha224_file_b64($filehandle);
   my $sha224_fh_b64u = sha224_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::SHA224;

   my $d = Crypt::Digest::SHA224->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::SHA224->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Provides an interface to the SHA224 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::SHA224 qw(sha224 sha224_hex sha224_b64 sha224_b64u
                                      sha224_file sha224_file_hex sha224_file_b64 sha224_file_b64u);

Or all of them at once:

  use Crypt::Digest::SHA224 ':all';

=head1 FUNCTIONS

=head2 sha224

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<sha224_hex>, C<sha224_b64>, and
C<sha224_b64u>.

 my $sha224_raw = sha224('data string');
 #or
 my $sha224_raw = sha224('any data', 'more data', 'even more data');

=head2 sha224_hex

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a hexadecimal string.

 my $sha224_hex = sha224_hex('data string');
 #or
 my $sha224_hex = sha224_hex('any data', 'more data', 'even more data');

=head2 sha224_b64

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $sha224_b64 = sha224_b64('data string');
 #or
 my $sha224_b64 = sha224_b64('any data', 'more data', 'even more data');

=head2 sha224_b64u

Logically joins all arguments into a single string, and returns its SHA224 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $sha224_b64url = sha224_b64u('data string');
 #or
 my $sha224_b64url = sha224_b64u('any data', 'more data', 'even more data');

=head2 sha224_file

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a binary string.

 my $sha224_raw = sha224_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sha224_raw = sha224_file($filehandle);

=head2 sha224_file_hex

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a hexadecimal string.

 my $sha224_hex = sha224_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sha224_hex = sha224_file_hex($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 sha224_file_b64

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $sha224_b64 = sha224_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sha224_b64 = sha224_file_b64($filehandle);

=head2 sha224_file_b64u

Reads file (defined by filename or filehandle) content, and returns its SHA224 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $sha224_b64url = sha224_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $sha224_b64url = sha224_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::SHA224->new();

=head2 new

 my $d = Crypt::Digest::SHA224->new();

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
 Crypt::Digest::SHA224->hashsize();
 #or
 Crypt::Digest::SHA224::hashsize();

=head2 digest

Returns the binary digest (raw bytes).
This method does not alter the digest object state, so you can call it
repeatedly and continue with C<add()> or C<addfile()> afterwards.

 my $result_raw = $d->digest();

=head2 hexdigest

Returns the digest encoded as a lowercase hexadecimal string.
Like C<digest()>, this method does not alter the digest object state.

 my $result_hex = $d->hexdigest();

=head2 b64digest

Returns the digest encoded as a Base64 string with trailing C<=> padding.
Like C<digest()>, this method does not alter the digest object state.

 my $result_b64 = $d->b64digest();

=head2 b64udigest

Returns the digest encoded as a Base64 URL Safe string (no trailing C<=>).
Like C<digest()>, this method does not alter the digest object state.

 my $result_b64url = $d->b64udigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest>

=item * L<https://en.wikipedia.org/wiki/SHA-2>

=back

=cut
