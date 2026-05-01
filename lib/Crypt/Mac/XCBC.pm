package Crypt::Mac::XCBC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_005';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( xcbc xcbc_hex xcbc_b64 xcbc_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::XCBC - Message authentication code XCBC (RFC 3566)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::XCBC qw( xcbc xcbc_hex xcbc_b64 xcbc_b64u );

   # calculate MAC from string/buffer
   my $xcbc_raw  = xcbc($cipher_name, $key, 'data buffer');
   my $xcbc_hex  = xcbc_hex($cipher_name, $key, 'data buffer');
   my $xcbc_b64  = xcbc_b64($cipher_name, $key, 'data buffer');
   my $xcbc_b64u = xcbc_b64u($cipher_name, $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::XCBC;

   my $d = Crypt::Mac::XCBC->new($cipher_name, $key);
   $d->add('any data');
   my $result_hex = $d->hexmac;   # finalizes the object

   # for another output encoding use a fresh object (or clone before finalizing)
   my $result_b64u = Crypt::Mac::XCBC->new($cipher_name, $key)->add('any data')->b64umac;

   # or MAC a file instead
   my $file_result_raw = Crypt::Mac::XCBC->new($cipher_name, $key)->addfile('filename.dat')->mac;

=head1 DESCRIPTION

Provides an interface to the XCBC message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::XCBC qw( xcbc xcbc_hex xcbc_b64 xcbc_b64u );

Or all of them at once:

  use Crypt::Mac::XCBC ':all';

=head1 FUNCTIONS

=head2 xcbc

Joins all arguments into a single string and returns its XCBC message authentication code encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<xcbc_hex>, C<xcbc_b64>, and
C<xcbc_b64u>.

 my $xcbc_raw = xcbc($cipher_name, $key, 'data buffer');
 #or
 my $xcbc_raw = xcbc($cipher_name, $key, 'any data', 'more data', 'even more data');

=head2 xcbc_hex

Joins all arguments into a single string and returns its XCBC message authentication code encoded as a hexadecimal string.

 my $xcbc_hex = xcbc_hex($cipher_name, $key, 'data buffer');
 #or
 my $xcbc_hex = xcbc_hex($cipher_name, $key, 'any data', 'more data', 'even more data');

=head2 xcbc_b64

Joins all arguments into a single string and returns its XCBC message authentication code encoded as a Base64 string.

 my $xcbc_b64 = xcbc_b64($cipher_name, $key, 'data buffer');
 #or
 my $xcbc_b64 = xcbc_b64($cipher_name, $key, 'any data', 'more data', 'even more data');

=head2 xcbc_b64u

Joins all arguments into a single string and returns its XCBC message authentication code encoded as a Base64 URL-safe string (see RFC 4648 section 5).

 my $xcbc_b64url = xcbc_b64u($cipher_name, $key, 'data buffer');
 #or
 my $xcbc_b64url = xcbc_b64u($cipher_name, $key, 'any data', 'more data', 'even more data');

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::XCBC->new($cipher_name, $key);

=head2 new

 my $d = Crypt::Mac::XCBC->new($cipher_name, $key);

 # $cipher_name .. [string] one of 'AES', 'Camellia', 'Twofish', 'Serpent', etc.
 #                 any <NAME> for which there is a Crypt::Cipher::<NAME> module
 # $key .......... [binary string] key of valid length for the chosen cipher (e.g. 16/24/32 bytes for AES)

=head2 clone

 $d->clone();

=head2 add

Appends data to the message. Returns the object itself (for chaining).
Croaks if the object has already been finalized by C<mac>, C<hexmac>,
C<b64mac>, or C<b64umac>.

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself
(for chaining). Croaks if the object has already been finalized by C<mac>,
C<hexmac>, C<b64mac>, or C<b64umac>.

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 mac

Returns the binary MAC (raw bytes) and finalizes the object. After the first
call to C<mac>, C<hexmac>, C<b64mac>, or C<b64umac>, later calls to C<add>,
C<addfile>, or any MAC getter croak.

 my $result_raw = $d->mac();

=head2 hexmac

Returns the MAC encoded as a lowercase hexadecimal string and finalizes the
object. After the first call to C<mac>, C<hexmac>, C<b64mac>, or C<b64umac>,
later calls to C<add>, C<addfile>, or any MAC getter croak.

 my $result_hex = $d->hexmac();

=head2 b64mac

Returns the MAC encoded as a Base64 string with trailing C<=> padding and
finalizes the object. After the first call to C<mac>, C<hexmac>, C<b64mac>, or
C<b64umac>, later calls to C<add>, C<addfile>, or any MAC getter croak.

 my $result_b64 = $d->b64mac();

=head2 b64umac

Returns the MAC encoded as a Base64 URL-safe string (no trailing C<=>) and
finalizes the object. After the first call to C<mac>, C<hexmac>, C<b64mac>, or
C<b64umac>, later calls to C<add>, C<addfile>, or any MAC getter croak.

 my $result_b64url = $d->b64umac();

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * L<https://www.rfc-editor.org/rfc/rfc3566>

=back

=cut
