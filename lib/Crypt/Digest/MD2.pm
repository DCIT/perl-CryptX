package Crypt::Digest::MD2;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Digest Exporter);
our %EXPORT_TAGS = ( all => [qw( md2 md2_hex md2_b64 md2_b64u md2_file md2_file_hex md2_file_b64 md2_file_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use Crypt::Digest;

sub new {
  my ($class) = @_;
  my $obj = Crypt::Digest->new('MD2');
  return bless $obj, $class;
}

sub clone {
  my ($self) = @_;
  my $obj = Crypt::Digest::clone($self);
  return bless $obj, ref($self) || $self;
}

sub hashsize                { Crypt::Digest::hashsize('MD2')             }
sub md2             { Crypt::Digest::digest_data('MD2', @_)      }
sub md2_hex         { Crypt::Digest::digest_data_hex('MD2', @_)  }
sub md2_b64         { Crypt::Digest::digest_data_b64('MD2', @_)  }
sub md2_b64u        { Crypt::Digest::digest_data_b64u('MD2', @_) }
sub md2_file        { Crypt::Digest::digest_file('MD2', @_)      }
sub md2_file_hex    { Crypt::Digest::digest_file_hex('MD2', @_)  }
sub md2_file_b64    { Crypt::Digest::digest_file_b64('MD2', @_)  }
sub md2_file_b64u   { Crypt::Digest::digest_file_b64u('MD2', @_) }

1;

=pod

=head1 NAME

Crypt::Digest::MD2 - Hash function MD2 [size: 128 bits]

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Digest::MD2 qw( md2 md2_hex md2_b64 md2_b64u
                                md2_file md2_file_hex md2_file_b64 md2_file_b64u );

   # calculate digest from string/buffer
   my $data = 'data string';
   my $md2_raw  = md2($data);
   my $md2_hex  = md2_hex($data);
   my $md2_b64  = md2_b64($data);
   my $md2_b64u = md2_b64u($data);
   # or from file
   my $md2_file_raw  = md2_file('filename.dat');
   my $md2_file_hex  = md2_file_hex('filename.dat');
   my $md2_file_b64  = md2_file_b64('filename.dat');
   my $md2_file_b64u = md2_file_b64u('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $md2_fh_raw  = md2_file($filehandle);
   my $md2_fh_hex  = md2_file_hex($filehandle);
   my $md2_fh_b64  = md2_file_b64($filehandle);
   my $md2_fh_b64u = md2_file_b64u($filehandle);

   ### OO interface:
   use Crypt::Digest::MD2;

   my $d = Crypt::Digest::MD2->new;
   $d->add('any data');
   my $result_raw  = $d->digest;     # raw bytes
   my $result_hex  = $d->hexdigest;  # hexadecimal form
   my $result_b64  = $d->b64digest;  # Base64 form
   my $result_b64u = $d->b64udigest; # Base64 URL Safe form

   # or hash a file instead
   my $file_result_raw = Crypt::Digest::MD2->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Provides an interface to the MD2 digest algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Digest::MD2 qw(md2 md2_hex md2_b64 md2_b64u
                                      md2_file md2_file_hex md2_file_b64 md2_file_b64u);

Or all of them at once:

  use Crypt::Digest::MD2 ':all';

=head1 FUNCTIONS

=head2 md2

Logically joins all arguments into a single string, and returns its MD2 digest encoded as a binary string.

 my $md2_raw = md2('data string');
 #or
 my $md2_raw = md2('any data', 'more data', 'even more data');

=head2 md2_hex

Logically joins all arguments into a single string, and returns its MD2 digest encoded as a hexadecimal string.

 my $md2_hex = md2_hex('data string');
 #or
 my $md2_hex = md2_hex('any data', 'more data', 'even more data');

=head2 md2_b64

Logically joins all arguments into a single string, and returns its MD2 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $md2_b64 = md2_b64('data string');
 #or
 my $md2_b64 = md2_b64('any data', 'more data', 'even more data');

=head2 md2_b64u

Logically joins all arguments into a single string, and returns its MD2 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $md2_b64url = md2_b64u('data string');
 #or
 my $md2_b64url = md2_b64u('any data', 'more data', 'even more data');

=head2 md2_file

Reads file (defined by filename or filehandle) content, and returns its MD2 digest encoded as a binary string.

 my $md2_raw = md2_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $md2_raw = md2_file($filehandle);

=head2 md2_file_hex

Reads file (defined by filename or filehandle) content, and returns its MD2 digest encoded as a hexadecimal string.

 my $md2_hex = md2_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $md2_hex = md2_file_hex($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 md2_file_b64

Reads file (defined by filename or filehandle) content, and returns its MD2 digest encoded as a Base64 string, B<with> trailing '=' padding.

 my $md2_b64 = md2_file_b64('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $md2_b64 = md2_file_b64($filehandle);

=head2 md2_file_b64u

Reads file (defined by filename or filehandle) content, and returns its MD2 digest encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $md2_b64url = md2_file_b64u('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $md2_b64url = md2_file_b64u($filehandle);

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Digest>.
Unless noted otherwise, assume C<$d> is an existing digest object created via
C<new>, for example:

 my $d = Crypt::Digest::MD2->new();

=head2 new

 my $d = Crypt::Digest::MD2->new();

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
 Crypt::Digest::MD2->hashsize();
 #or
 Crypt::Digest::MD2::hashsize();

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

=item * L<https://en.wikipedia.org/wiki/MD2_(cryptography)>

=back

=cut
