package Crypt::Mac::Pelican;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_001';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( pelican pelican_hex pelican_b64 pelican_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::Pelican - Message authentication code Pelican (AES based MAC)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::Pelican qw( pelican pelican_hex );

   # calculate MAC from string/buffer
   my $pelican_raw  = pelican($key, 'data buffer');
   my $pelican_hex  = pelican_hex($key, 'data buffer');
   my $pelican_b64  = pelican_b64($key, 'data buffer');
   my $pelican_b64u = pelican_b64u($key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::Pelican;

   my $d = Crypt::Mac::Pelican->new($key);
   $d->add('any data');
   my $result_raw  = $d->mac;     # raw bytes
   my $result_hex  = $d->hexmac;  # hexadecimal form
   my $result_b64  = $d->b64mac;  # Base64 form
   my $result_b64u = $d->b64umac; # Base64 URL Safe form

   # or MAC a file instead
   my $file_result_raw = Crypt::Mac::Pelican->new($key)->addfile('filename.dat')->mac;

=head1 DESCRIPTION

Provides an interface to the Pelican message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::Pelican qw(pelican pelican_hex );

Or all of them at once:

  use Crypt::Mac::Pelican ':all';

=head1 FUNCTIONS

=head2 pelican

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a binary string.

 my $pelican_raw = pelican($key, 'data buffer');
 #or
 my $pelican_raw = pelican($key, 'any data', 'more data', 'even more data');

=head2 pelican_hex

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a hexadecimal string.

 my $pelican_hex = pelican_hex($key, 'data buffer');
 #or
 my $pelican_hex = pelican_hex($key, 'any data', 'more data', 'even more data');

=head2 pelican_b64

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a Base64 string.

 my $pelican_b64 = pelican_b64($key, 'data buffer');
 #or
 my $pelican_b64 = pelican_b64($key, 'any data', 'more data', 'even more data');

=head2 pelican_b64u

Logically joins all arguments into a single string, and returns its Pelican message authentication code encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $pelican_b64url = pelican_b64u($key, 'data buffer');
 #or
 my $pelican_b64url = pelican_b64u($key, 'any data', 'more data', 'even more data');

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::Pelican->new($key);

=head2 new

 my $d = Crypt::Mac::Pelican->new($key);

 # $key .. [binary string] exactly 16 bytes (AES-128 key; Pelican is AES-based)

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

=head2 mac

Returns the binary MAC (raw bytes).

 my $result_raw = $d->mac();

=head2 hexmac

Returns the MAC encoded as a lowercase hexadecimal string.

 my $result_hex = $d->hexmac();

=head2 b64mac

Returns the MAC encoded as a Base64 string with trailing C<=> padding.

 my $result_b64 = $d->b64mac();

=head2 b64umac

Returns the MAC encoded as a Base64 URL Safe string (no trailing C<=>).

 my $result_b64url = $d->b64umac();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=item * L<https://eprint.iacr.org/2005/088.pdf>

=back

=cut
