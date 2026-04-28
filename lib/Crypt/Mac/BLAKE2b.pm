package Crypt::Mac::BLAKE2b;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_004';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( blake2b blake2b_hex blake2b_b64 blake2b_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::BLAKE2b - Message authentication code BLAKE2b MAC (RFC 7693)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::BLAKE2b qw( blake2b blake2b_hex );

   # calculate MAC from string/buffer
   my $blake2b_raw  = blake2b($size, $key, 'data buffer');
   my $blake2b_hex  = blake2b_hex($size, $key, 'data buffer');
   my $blake2b_b64  = blake2b_b64($size, $key, 'data buffer');
   my $blake2b_b64u = blake2b_b64u($size, $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::BLAKE2b;

   my $d = Crypt::Mac::BLAKE2b->new($size, $key);
   $d->add('any data');
   my $result_hex = $d->hexmac;   # finalizes the object

   # for another output encoding use a fresh object (or clone before finalizing)
   my $result_b64u = Crypt::Mac::BLAKE2b->new($size, $key)->add('any data')->b64umac;

   # or MAC a file instead
   my $file_result_raw = Crypt::Mac::BLAKE2b->new($size, $key)->addfile('filename.dat')->mac;

=head1 DESCRIPTION

Provides an interface to the BLAKE2b message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::BLAKE2b qw(blake2b blake2b_hex );

Or all of them at once:

  use Crypt::Mac::BLAKE2b ':all';

=head1 FUNCTIONS

=head2 blake2b

Logically joins all arguments into a single string, and returns its BLAKE2b message authentication code encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<blake2b_hex>, C<blake2b_b64>, and
C<blake2b_b64u>.

 my $blake2b_raw = blake2b($size, $key, 'data buffer');
 #or
 my $blake2b_raw = blake2b($size, $key, 'any data', 'more data', 'even more data');

=head2 blake2b_hex

Logically joins all arguments into a single string, and returns its BLAKE2b message authentication code encoded as a hexadecimal string.

 my $blake2b_hex = blake2b_hex($size, $key, 'data buffer');
 #or
 my $blake2b_hex = blake2b_hex($size, $key, 'any data', 'more data', 'even more data');

=head2 blake2b_b64

Logically joins all arguments into a single string, and returns its BLAKE2b message authentication code encoded as a Base64 string.

 my $blake2b_b64 = blake2b_b64($size, $key, 'data buffer');
 #or
 my $blake2b_b64 = blake2b_b64($size, $key, 'any data', 'more data', 'even more data');

=head2 blake2b_b64u

Logically joins all arguments into a single string, and returns its BLAKE2b message authentication code encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $blake2b_b64url = blake2b_b64u($size, $key, 'data buffer');
 #or
 my $blake2b_b64url = blake2b_b64u($size, $key, 'any data', 'more data', 'even more data');

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::BLAKE2b->new($size, $key);

=head2 new

 my $d = Crypt::Mac::BLAKE2b->new($size, $key);

 # $size .. [integer] desired MAC output size in bytes (1 - 64)
 # $key ... [binary string] the key (1 - 64 bytes)

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

Returns the MAC encoded as a Base64 URL Safe string (no trailing C<=>) and
finalizes the object. After the first call to C<mac>, C<hexmac>, C<b64mac>, or
C<b64umac>, later calls to C<add>, C<addfile>, or any MAC getter croak.

 my $result_b64url = $d->b64umac();

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>

=item * L<https://www.rfc-editor.org/rfc/rfc7693>

=back

=cut
