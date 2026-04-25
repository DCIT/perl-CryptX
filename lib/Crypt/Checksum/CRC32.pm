package Crypt::Checksum::CRC32;

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Checksum Exporter);
our %EXPORT_TAGS = ( all => [qw( crc32_data crc32_data_hex crc32_data_int crc32_file crc32_file_hex crc32_file_int )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub crc32_file     { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Checksum::CRC32->new->addfile(@_)->digest    }
sub crc32_file_hex { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Checksum::CRC32->new->addfile(@_)->hexdigest }
sub crc32_file_int { local $SIG{__DIE__} = \&CryptX::_croak; Crypt::Checksum::CRC32->new->addfile(@_)->intdigest }

1;

=pod

=head1 NAME

Crypt::Checksum::CRC32 - Compute CRC32 checksum

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Checksum::CRC32 ':all';

   # calculate CRC32 checksum from string/buffer
   my $data = 'data string';
   my $checksum_raw  = crc32_data($data);
   my $checksum_hex  = crc32_data_hex($data);
   my $checksum_int  = crc32_data_int($data);
   # or from file
   my $checksum_file_raw  = crc32_file('filename.dat');
   my $checksum_file_hex  = crc32_file_hex('filename.dat');
   my $checksum_file_int  = crc32_file_int('filename.dat');
   # or from filehandle
   my $filehandle = ...; # existing binary-mode filehandle
   my $checksum_fh_raw  = crc32_file($filehandle);
   my $checksum_fh_hex  = crc32_file_hex($filehandle);
   my $checksum_fh_int  = crc32_file_int($filehandle);

   ### OO interface:
   use Crypt::Checksum::CRC32;

   my $d = Crypt::Checksum::CRC32->new;
   $d->add('any data');
   $d->add('another data');
   my $checksum_raw = $d->digest;     # raw 4 bytes
   my $checksum_hex = $d->hexdigest;  # hexadecimal form
   my $checksum_int = $d->intdigest;  # 32bit unsigned integer

   # or checksum a file instead
   my $checksum_file_raw = Crypt::Checksum::CRC32->new->addfile('filename.dat')->digest;

=head1 DESCRIPTION

Computes CRC-32 checksums using the ISO 3309 / ITU-T V.42 polynomial
(C<0xEDB88320>, also known as CRC-32/ISO-HDLC). This is the same variant
used by Ethernet (IEEE 802.3), PKZIP, gzip, and PNG.

I<Updated: v0.057>

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

 use Crypt::Checksum::CRC32 qw(crc32_data crc32_data_hex crc32_data_int crc32_file crc32_file_hex crc32_file_int);

Or all of them at once:

 use Crypt::Checksum::CRC32 ':all';

=head1 FUNCTIONS

=head2 crc32_data

Returns the checksum as raw octets.

 my $checksum_raw = crc32_data('data string');
 #or
 my $checksum_raw = crc32_data('any data', 'more data', 'even more data');

=head2 crc32_data_hex

Returns checksum as a hexadecimal string.

 my $checksum_hex = crc32_data_hex('data string');
 #or
 my $checksum_hex = crc32_data_hex('any data', 'more data', 'even more data');

=head2 crc32_data_int

Returns checksum as unsigned 32bit integer.

 my $checksum_int = crc32_data_int('data string');
 #or
 my $checksum_int = crc32_data_int('any data', 'more data', 'even more data');

=head2 crc32_file

Returns the checksum as raw octets.

 my $checksum_raw = crc32_file('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $checksum_raw = crc32_file($filehandle);

=head2 crc32_file_hex

Returns checksum as a hexadecimal string.

 my $checksum_hex = crc32_file_hex('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $checksum_hex = crc32_file_hex($filehandle);

=head2 crc32_file_int

Returns checksum as unsigned 32bit integer.

 my $checksum_int = crc32_file_int('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 my $checksum_int = crc32_file_int($filehandle);

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing checksum object created via
C<new>.

=head2 new

Constructor, returns a reference to the checksum object.

 my $d = Crypt::Checksum::CRC32->new;

=head2 clone

Creates a copy of the checksum object state and returns a reference to the copy.

 $d->clone();

=head2 reset

Reinitialize the checksum object state and returns a reference to the checksum object.

 $d->reset();

=head2 add

All arguments are appended to the message we calculate checksum for.
The return value is the checksum object itself.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

The content of the file (or filehandle) is appended to the message we calculate checksum for.
The return value is the checksum object itself.

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

B<BEWARE:> You have to make sure that the filehandle is in binary mode before you pass it as argument to the addfile() method.

=head2 digest

Returns the binary checksum (raw bytes).

 my $result_raw = $d->digest();

=head2 hexdigest

Returns the checksum encoded as a hexadecimal string.

 my $result_hex = $d->hexdigest();

=head2 intdigest

Returns the checksum encoded as unsigned 32bit integer.

 my $result_int = $d->intdigest();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=item * L<https://en.wikipedia.org/wiki/Cyclic_redundancy_check>

=back

=cut
