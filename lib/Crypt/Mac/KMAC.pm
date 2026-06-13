package Crypt::Mac::KMAC;

use strict;
use warnings;
our $VERSION = '0.090';

use base qw(Crypt::Mac Exporter);
our %EXPORT_TAGS = ( all => [qw( kmac kmac_hex kmac_b64 kmac_b64u )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

1;

=pod

=head1 NAME

Crypt::Mac::KMAC - Message authentication code KMAC (NIST SP 800-185)

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::KMAC qw( kmac kmac_hex kmac_b64 kmac_b64u );

   # KMAC128 / KMAC256 - fixed-length output committed in advance
   my $mac_raw  = kmac('KMAC128', 32, $key, '', 'data buffer');
   my $mac_hex  = kmac_hex('KMAC256', 64, $key, $custom, 'data buffer');

   # KMACXOF128 / KMACXOF256 - extendable-output variant
   my $bytes    = kmac('KMACXOF128', 100, $key, '', 'data buffer');

   ### OO interface:
   use Crypt::Mac::KMAC;

   my $d = Crypt::Mac::KMAC->new('KMAC256', $key, $custom);
   $d->add('any data');
   my $result_hex = $d->hexmac(64);   # finalizes the object

   # XOF mode - same API, just a different variant
   my $d = Crypt::Mac::KMAC->new('KMACXOF128', $key);
   $d->add('any data');
   my $result_b64 = $d->b64mac(100);

=head1 DESCRIPTION

I<Since: CryptX-0.090>

Provides an interface to KMAC, the keyed message authentication code based on
cSHAKE (NIST SP 800-185 section4). Four variants are exposed:

=over

=item * C<KMAC128> / C<KMAC256> - fixed-output KMAC. The requested output
length C<L> is encoded into the input, so re-running KMAC with a different
output length produces an unrelated MAC, even with identical key, customization,
and message.

=item * C<KMACXOF128> / C<KMACXOF256> - extendable-output KMAC (KMACXOF in
SP 800-185). The encoded length is set to C<0>, so any prefix of the squeezed
output is a valid KMAC of the same key/customization/message; you can request
arbitrarily many bytes.

=back

The customization string C<S> is optional and is used for domain separation.
When unused it is encoded as an empty string.

=head1 EXPORT

Nothing is exported by default.

You can export selected functions:

  use Crypt::Mac::KMAC qw( kmac kmac_hex kmac_b64 kmac_b64u );

Or all of them at once:

  use Crypt::Mac::KMAC ':all';

=head1 FUNCTIONS

=head2 kmac

Joins all data arguments into a single string and returns its KMAC encoded as a
binary string.

 my $mac = kmac($variant, $size, $key, $cust, 'data buffer');
 #or
 my $mac = kmac($variant, $size, $key, $cust, 'data', 'more data', 'even more');

 # $variant .. [string] 'KMAC128', 'KMAC256', 'KMACXOF128' or 'KMACXOF256'
 # $size .... [integer] requested output length in bytes (>0)
 # $key ..... [binary string] secret key (any length, including empty)
 # $cust .... [binary string] customization string (may be empty); undef is treated as empty

=head2 kmac_hex

Like L</kmac> but returns the MAC encoded as a lowercase hexadecimal string.

 my $mac_hex = kmac_hex($variant, $size, $key, $cust, 'data buffer');

=head2 kmac_b64

Like L</kmac> but returns the MAC encoded as a Base64 string.

 my $mac_b64 = kmac_b64($variant, $size, $key, $cust, 'data buffer');

=head2 kmac_b64u

Like L</kmac> but returns the MAC encoded as a Base64 URL-safe string
(see RFC 4648 section 5).

 my $mac_b64u = kmac_b64u($variant, $size, $key, $cust, 'data buffer');

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing MAC object created via
C<new>, for example:

 my $d = Crypt::Mac::KMAC->new('KMAC256', $key, $cust);

=head2 new

 my $d = Crypt::Mac::KMAC->new($variant, $key);
 #or
 my $d = Crypt::Mac::KMAC->new($variant, $key, $cust);

 # $variant .. [string] 'KMAC128', 'KMAC256', 'KMACXOF128' or 'KMACXOF256'
 # $key ..... [binary string] secret key (any length, including empty)
 # $cust .... [binary string] customization string (optional, defaults to empty)

=head2 clone

 $d->clone();

=head2 add

Appends data to the message. Returns the object itself (for chaining).
Croaks if the object has already been finalized by C<mac>, C<hexmac>,
C<b64mac>, or C<b64umac>.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself
(for chaining). Croaks if the object has already been finalized.

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 mac

Returns the binary MAC (raw bytes) and finalizes the object. After the first
call to C<mac>, C<hexmac>, C<b64mac>, or C<b64umac>, later calls to C<add>,
C<addfile>, or any MAC getter croak.

 my $result_raw = $d->mac($size);

 # $size .. [integer] requested output length in bytes (>0)

For C<KMAC128> / C<KMAC256> the requested length is committed via right_encode
into the cSHAKE input as defined in SP 800-185 section4.3.1; for C<KMACXOF128> /
C<KMACXOF256> the encoded length is C<0> and the same C<$size> bytes are
squeezed from the XOF (section4.3.2).

=head2 hexmac

Like L</mac> but returns the MAC encoded as a lowercase hexadecimal string.

 my $result_hex = $d->hexmac($size);

=head2 b64mac

Like L</mac> but returns the MAC encoded as a Base64 string with trailing
C<=> padding.

 my $result_b64 = $d->b64mac($size);

=head2 b64umac

Like L</mac> but returns the MAC encoded as a Base64 URL-safe string (no
trailing C<=>).

 my $result_b64url = $d->b64umac($size);

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * L<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf> - NIST SP 800-185 (KMAC, cSHAKE, TupleHash, ParallelHash)

=back

=cut
