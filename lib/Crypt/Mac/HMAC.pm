package Crypt::Mac::HMAC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;
our $VERSION = '0.088_002';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( hmac hmac_hex hmac_b64 hmac_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::HMAC - Message authentication code HMAC

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::HMAC qw( hmac hmac_hex );

   # calculate MAC from string/buffer
   my $hmac_raw  = hmac('SHA256', $key, 'data buffer');
   my $hmac_hex  = hmac_hex('SHA256', $key, 'data buffer');
   my $hmac_b64  = hmac_b64('SHA256', $key, 'data buffer');
   my $hmac_b64u = hmac_b64u('SHA256', $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::HMAC;

   my $d = Crypt::Mac::HMAC->new('SHA256', $key);
   $d->add('any data');
   my $result_hex = $d->hexmac;   # finalizes the object

   # for another output encoding use a fresh object (or clone before finalizing)
   my $result_b64u = Crypt::Mac::HMAC->new('SHA256', $key)->add('any data')->b64umac;

   # or MAC a file instead
   my $file_result_raw = Crypt::Mac::HMAC->new('SHA256', $key)->addfile('filename.dat')->mac;

=head1 DESCRIPTION

Provides an interface to the HMAC message authentication code (MAC) algorithm.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::HMAC qw(hmac hmac_hex );

Or all of them at once:

  use Crypt::Mac::HMAC ':all';

=head1 FUNCTIONS

=head2 hmac

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a binary string.

Data arguments for the functional helpers are converted to byte strings using
Perl's usual scalar stringification. Defined scalars, including numbers and
string-overloaded objects, are accepted. C<undef> is treated as an empty
string and may emit Perl's usual "uninitialized value" warning. The same
rules apply to C<hmac_hex>, C<hmac_b64>, and
C<hmac_b64u>.

 my $hmac_raw = hmac($hash_name, $key, 'data buffer');
 #or
 my $hmac_raw = hmac($hash_name, $key, 'any data', 'more data', 'even more data');

 # $hash_name ... [string] any <NAME> for which there exists Crypt::Digest::<NAME>
 # $key ......... [binary string] the key (octets/bytes)

=head2 hmac_hex

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a hexadecimal string.

 my $hmac_hex = hmac_hex($hash_name, $key, 'data buffer');
 #or
 my $hmac_hex = hmac_hex($hash_name, $key, 'any data', 'more data', 'even more data');

 # $hash_name ... [string] any <NAME> for which there exists Crypt::Digest::<NAME>
 # $key ......... [binary string] the key (not hex!)

=head2 hmac_b64

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a Base64 string.

 my $hmac_b64 = hmac_b64($hash_name, $key, 'data buffer');
 #or
 my $hmac_b64 = hmac_b64($hash_name, $key, 'any data', 'more data', 'even more data');

 # $hash_name ... [string] any <NAME> for which there exists Crypt::Digest::<NAME>
 # $key ......... [binary string] the key (not Base64!)

=head2 hmac_b64u

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a Base64 URL Safe string (see RFC 4648 section 5).

 my $hmac_b64url = hmac_b64u($hash_name, $key, 'data buffer');
 #or
 my $hmac_b64url = hmac_b64u($hash_name, $key, 'any data', 'more data', 'even more data');

 # $hash_name ... [string] any <NAME> for which there exists Crypt::Digest::<NAME>
 # $key ......... [binary string] the key (not Base64url!)

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::HMAC->new('SHA256', $key);

=head2 new

 my $d = Crypt::Mac::HMAC->new($hash_name, $key);

 # $hash_name ... [string] one of 'SHA256', 'SHA384', 'SHA512', 'SHA1', 'SHA3_256', 'BLAKE2b_256',
 #                'RIPEMD160', etc. - any <NAME> for which there exists Crypt::Digest::<NAME>
 # $key ......... [binary string] the key (any length - internally padded/hashed as per RFC 2104)

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

=item * L<https://en.wikipedia.org/wiki/Hmac>

=item * L<https://www.rfc-editor.org/rfc/rfc2104>

=back

=cut
