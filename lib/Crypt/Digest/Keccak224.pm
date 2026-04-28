package Crypt::Digest::Keccak224;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_003';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( keccak224 keccak224_hex keccak224_b64 keccak224_b64u keccak224_file keccak224_file_hex keccak224_file_b64 keccak224_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub new {
  my ($class) = @_;
  my $obj = Crypt::Digest->new('Keccak224');
  return bless $obj, $class;
}

sub clone {
  my ($self) = @_;
  my $obj = Crypt::Digest::clone($self);
  return bless $obj, ref($self) || $self;
}

sub hashsize                { Crypt::Digest::hashsize('Keccak224')             }
sub keccak224             { Crypt::Digest::digest_data('Keccak224', @_)      }
sub keccak224_hex         { Crypt::Digest::digest_data_hex('Keccak224', @_)  }
sub keccak224_b64         { Crypt::Digest::digest_data_b64('Keccak224', @_)  }
sub keccak224_b64u        { Crypt::Digest::digest_data_b64u('Keccak224', @_) }
sub keccak224_file        { Crypt::Digest::digest_file('Keccak224', @_)      }
sub keccak224_file_hex    { Crypt::Digest::digest_file_hex('Keccak224', @_)  }
sub keccak224_file_b64    { Crypt::Digest::digest_file_b64('Keccak224', @_)  }
sub keccak224_file_b64u   { Crypt::Digest::digest_file_b64u('Keccak224', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::Keccak224 - Hash function Keccak-224 [size: 224 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::Keccak224 qw( keccak224 keccak224_hex keccak224_b64 keccak224_b64u
                                keccak224_file keccak224_file_hex keccak224_file_b64 keccak224_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $keccak224_raw  = keccak224($data);
   my $keccak224_hex  = keccak224_hex($data);
   my $keccak224_b64  = keccak224_b64($data);
   my $keccak224_b64u = keccak224_b64u($data);
   # or from file
   my $keccak224_file_raw  = keccak224_file('filename.dat');
   my $keccak224_file_hex  = keccak224_file_hex('filename.dat');
   my $keccak224_file_b64  = keccak224_file_b64('filename.dat');
   my $keccak224_file_b64u = keccak224_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $keccak224_fh_raw  = keccak224_file($filehandle);
   my $keccak224_fh_hex  = keccak224_file_hex($filehandle);
   my $keccak224_fh_b64  = keccak224_file_b64($filehandle);
   my $keccak224_fh_b64u = keccak224_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::Keccak224;

   my $d = Crypt::Digest::Keccak224->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::Keccak224->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Provides an interface to the Keccak224 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::Keccak224 qw(keccak224 keccak224_hex keccak224_b64 keccak224_b64u
                                      keccak224_file keccak224_file_hex keccak224_file_b64 keccak224_file_b64u);

Or all of them at once:

  use Crypt::Digest::Keccak224 ':all';

=head1 FUNCTIONS

=head2 keccak224

Logically joins all arguments into a single string, and returns its Keccak224 digest encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<keccak224_hex>, C<keccak224_b64>, and
C<keccak224_b64u>.

 my $keccak224_raw = keccak224('data string');
 #or
 my $keccak224_raw = keccak224('any data', 'more data', 'even more data');

=head2 keccak224_hex

Logically joins all arguments into a single string, and returns its Keccak224 digest encoded as a hexadecimal string.

 my $keccak224_hex = keccak224_hex('data string');
 #or
 my $keccak224_hex = keccak224_hex('any data', 'more data', 'even more data');

=head2 keccak224_b64

Logically joins all arguments into a single string, and returns its Keccak224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $keccak224_b64 = keccak224_b64('data string');
 #or
 my $keccak224_b64 = keccak224_b64('any data', 'more data', 'even more data');

=head2 keccak224_b64u

Logically joins all arguments into a single string, and returns its Keccak224 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $keccak224_b64url = keccak224_b64u('data string');
 #or
 my $keccak224_b64url = keccak224_b64u('any data', 'more data', 'even more data');

=head2 keccak224_file

Reads file (defined by filename or filehandle) content, and returns its Keccak224 digest encoded as a binary string.

 my $keccak224_raw = keccak224_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $keccak224_raw = keccak224_file($filehandle);

=head2 keccak224_file_hex

Reads file (defined by filename or filehandle) content, and returns its Keccak224 digest encoded as a hexadecimal string.

 my $keccak224_hex = keccak224_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $keccak224_hex = keccak224_file_hex($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 keccak224_file_b64

Reads file (defined by filename or filehandle) content, and returns its Keccak224 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $keccak224_b64 = keccak224_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $keccak224_b64 = keccak224_file_b64($filehandle);

=head2 keccak224_file_b64u

Reads file (defined by filename or filehandle) content, and returns its Keccak224 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $keccak224_b64url = keccak224_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $keccak224_b64url = keccak224_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::Keccak224->new();

=head2 new

 my $d = Crypt::Digest::Keccak224->new();

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
 Crypt::Digest::Keccak224->hashsize();
 #or
 Crypt::Digest::Keccak224::hashsize();

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

Returns the digest encoded as a Base64 URL Safe string (no trailing C<=>).
Like C<digest()>, the first call finalizes the digest object.

 my $result_b64url = $d->b64udigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest>

=item * L<https://keccak.team/index.html>

=back

=cut
