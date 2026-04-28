package Crypt::Mac::Poly1305;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_002';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( poly1305 poly1305_hex poly1305_b64 poly1305_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::Poly1305 - Message authentication code Poly1305 (RFC 7539)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::Poly1305 qw( poly1305 poly1305_hex );

   # calculate MAC from string/buffer
   my $poly1305_raw  = poly1305($key, 'data buffer');
   my $poly1305_hex  = poly1305_hex($key, 'data buffer');
   my $poly1305_b64  = poly1305_b64($key, 'data buffer');
   my $poly1305_b64u = poly1305_b64u($key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::Poly1305;

   my $d = Crypt::Mac::Poly1305->new($key);
   $d->add('any data');
   my $result_hex = $d->hexmac;   # finalizes the object

   # for another output encoding use a fresh object (or clone before finalizing)
   my $result_b64u = Crypt::Mac::Poly1305->new($key)->add('any data')->b64umac;

   # or MAC a file instead
   my $file_result_raw = Crypt::Mac::Poly1305->new($key)->addfile('filename.dat')->mac;

=head1 DESCRIPTION

Provides an interface to the Poly1305 message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::Poly1305 qw(poly1305 poly1305_hex );

Or all of them at once:

  use Crypt::Mac::Poly1305 ':all';

=head1 FUNCTIONS

=head2 poly1305

Logically joins all arguments into a single string, and returns its Poly1305 message authentication code encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<poly1305_hex>, C<poly1305_b64>, and
C<poly1305_b64u>.

 my $poly1305_raw = poly1305($key, 'data buffer');
 #or
 my $poly1305_raw = poly1305($key, 'any data', 'more data', 'even more data');

=head2 poly1305_hex

Logically joins all arguments into a single string, and returns its Poly1305 message authentication code encoded as a hexadecimal string.

 my $poly1305_hex = poly1305_hex($key, 'data buffer');
 #or
 my $poly1305_hex = poly1305_hex($key, 'any data', 'more data', 'even more data');

=head2 poly1305_b64

Logically joins all arguments into a single string, and returns its Poly1305 message authentication code encoded as a Base64 string.

 my $poly1305_b64 = poly1305_b64($key, 'data buffer');
 #or
 my $poly1305_b64 = poly1305_b64($key, 'any data', 'more data', 'even more data');

=head2 poly1305_b64u

Logically joins all arguments into a single string, and returns its Poly1305 message authentication code encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $poly1305_b64url = poly1305_b64u($key, 'data buffer');
 #or
 my $poly1305_b64url = poly1305_b64u($key, 'any data', 'more data', 'even more data');

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::Poly1305->new($key);

=head2 new

 my $d = Crypt::Mac::Poly1305->new($key);

 # $key .. [binary string] exactly 32 bytes (256 bits); a fresh one-time key per message

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

=item * L<https://www.rfc-editor.org/rfc/rfc7539>

=back

=cut
