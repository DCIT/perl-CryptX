package Crypt::Digest::RIPEMD256;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( ripemd256 ripemd256_hex ripemd256_b64 ripemd256_b64u ripemd256_file ripemd256_file_hex ripemd256_file_b64 ripemd256_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub new {
  my ($class) = @_;
  my $obj = Crypt::Digest->new('RIPEMD256');
  return bless $obj, $class;
}

sub clone {
  my ($self) = @_;
  my $obj = Crypt::Digest::clone($self);
  return bless $obj, ref($self) || $self;
}

sub hashsize                { Crypt::Digest::hashsize('RIPEMD256')             }
sub ripemd256             { Crypt::Digest::digest_data('RIPEMD256', @_)      }
sub ripemd256_hex         { Crypt::Digest::digest_data_hex('RIPEMD256', @_)  }
sub ripemd256_b64         { Crypt::Digest::digest_data_b64('RIPEMD256', @_)  }
sub ripemd256_b64u        { Crypt::Digest::digest_data_b64u('RIPEMD256', @_) }
sub ripemd256_file        { Crypt::Digest::digest_file('RIPEMD256', @_)      }
sub ripemd256_file_hex    { Crypt::Digest::digest_file_hex('RIPEMD256', @_)  }
sub ripemd256_file_b64    { Crypt::Digest::digest_file_b64('RIPEMD256', @_)  }
sub ripemd256_file_b64u   { Crypt::Digest::digest_file_b64u('RIPEMD256', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::RIPEMD256 - Hash function RIPEMD-256 [size: 256 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::RIPEMD256 qw( ripemd256 ripemd256_hex ripemd256_b64 ripemd256_b64u
                                ripemd256_file ripemd256_file_hex ripemd256_file_b64 ripemd256_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $ripemd256_raw  = ripemd256($data);
   my $ripemd256_hex  = ripemd256_hex($data);
   my $ripemd256_b64  = ripemd256_b64($data);
   my $ripemd256_b64u = ripemd256_b64u($data);
   # or from file
   my $ripemd256_file_raw  = ripemd256_file('filename.dat');
   my $ripemd256_file_hex  = ripemd256_file_hex('filename.dat');
   my $ripemd256_file_b64  = ripemd256_file_b64('filename.dat');
   my $ripemd256_file_b64u = ripemd256_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $ripemd256_fh_raw  = ripemd256_file($filehandle);
   my $ripemd256_fh_hex  = ripemd256_file_hex($filehandle);
   my $ripemd256_fh_b64  = ripemd256_file_b64($filehandle);
   my $ripemd256_fh_b64u = ripemd256_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::RIPEMD256;

   my $d = Crypt::Digest::RIPEMD256->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::RIPEMD256->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Provides an interface to the RIPEMD256 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::RIPEMD256 qw(ripemd256 ripemd256_hex ripemd256_b64 ripemd256_b64u
                                      ripemd256_file ripemd256_file_hex ripemd256_file_b64 ripemd256_file_b64u);

Or all of them at once:

  use Crypt::Digest::RIPEMD256 ':all';

=head1 FUNCTIONS

=head2 ripemd256

Logically joins all arguments into a single string, and returns its RIPEMD256 digest encoded as a binary string.

 my $ripemd256_raw = ripemd256('data string');
 #or
 my $ripemd256_raw = ripemd256('any data', 'more data', 'even more data');

=head2 ripemd256_hex

Logically joins all arguments into a single string, and returns its RIPEMD256 digest encoded as a hexadecimal string.

 my $ripemd256_hex = ripemd256_hex('data string');
 #or
 my $ripemd256_hex = ripemd256_hex('any data', 'more data', 'even more data');

=head2 ripemd256_b64

Logically joins all arguments into a single string, and returns its RIPEMD256 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $ripemd256_b64 = ripemd256_b64('data string');
 #or
 my $ripemd256_b64 = ripemd256_b64('any data', 'more data', 'even more data');

=head2 ripemd256_b64u

Logically joins all arguments into a single string, and returns its RIPEMD256 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $ripemd256_b64url = ripemd256_b64u('data string');
 #or
 my $ripemd256_b64url = ripemd256_b64u('any data', 'more data', 'even more data');

=head2 ripemd256_file

Reads file (defined by filename or filehandle) content, and returns its RIPEMD256 digest encoded as a binary string.

 my $ripemd256_raw = ripemd256_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $ripemd256_raw = ripemd256_file($filehandle);

=head2 ripemd256_file_hex

Reads file (defined by filename or filehandle) content, and returns its RIPEMD256 digest encoded as a hexadecimal string.

 my $ripemd256_hex = ripemd256_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $ripemd256_hex = ripemd256_file_hex($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 ripemd256_file_b64

Reads file (defined by filename or filehandle) content, and returns its RIPEMD256 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $ripemd256_b64 = ripemd256_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $ripemd256_b64 = ripemd256_file_b64($filehandle);

=head2 ripemd256_file_b64u

Reads file (defined by filename or filehandle) content, and returns its RIPEMD256 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $ripemd256_b64url = ripemd256_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $ripemd256_b64url = ripemd256_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::RIPEMD256->new();

=head2 new

 my $d = Crypt::Digest::RIPEMD256->new();

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

=head2 hashsize

 $d->hashsize;
 #or
 Crypt::Digest::RIPEMD256->hashsize();
 #or
 Crypt::Digest::RIPEMD256::hashsize();

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

=item * L<https://en.wikipedia.org/wiki/RIPEMD>

=back

=cut
