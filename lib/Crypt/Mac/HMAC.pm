package Crypt::Mac::HMAC;

### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( hmac hmac_hex hmac_b64 )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use CryptX;
use base 'Crypt::Mac';

use Crypt::Digest;

sub new { my $class = shift; _new(Crypt::Digest::_trans_digest_name(shift), @_) }
sub hmac { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->mac }
sub hmac_hex { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->hexmac }
sub hmac_b64 { Crypt::Mac::HMAC->new(shift, shift)->add(@_)->b64mac }

1;

=pod

=head1 NAME

Crypt::Mac::HMAC - Message authentication code HMAC

=head1 SYNOPSIS

   ### Functional interface:
   use Crypt::Mac::HMAC qw( hmac hmac_hex );

   # calculate MAC from string/buffer
   $hmac_raw = hmac('SHA256', $key, 'data buffer');
   $hmac_hex = hmac_hex('SHA256', $key, 'data buffer');
   $hmac_b64 = hmac_b64('SHA256', $key, 'data buffer');

   ### OO interface:
   use Crypt::Mac::HMAC;

   $d = Crypt::Mac::HMAC->new('SHA256', $key);
   $d->add('any data');
   $d->addfile('filename.dat');
   $d->addfile(*FILEHANDLE);
   $result_raw = $d->mac;    # raw bytes
   $result_hex = $d->hexmac; # hexadecimal form
   $result_b64 = $d->b64mac; # Base64 form

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

 $hmac_raw = hmac($hash_name, $key, 'data buffer');
 #or
 $hmac_raw = hmac($hash_name, $key, 'any data', 'more data', 'even more data');

=head2 hmac_hex

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a hexadecimal string.

 $hmac_hex = hmac_hex($hash_name, $key, 'data buffer');
 #or
 $hmac_hex = hmac_hex($hash_name, $key, 'any data', 'more data', 'even more data');

=head2 hmac_b64

Logically joins all arguments into a single string, and returns its HMAC message authentication code encoded as a BASE64 string.

 $hmac_b64 = hmac_b64($hash_name, $key, 'data buffer');
 #or
 $hmac_b64 = hmac_b64($hash_name, $key, 'any data', 'more data', 'even more data');

=head1 METHODS

The OO interface provides the same set of functions as L<Crypt::Mac>.

=head2 new

 $d = Crypt::Mac::HMAC->new($hash_name, $key);

=head2 clone

 $d->clone();

=head2 reset

 $d->reset();

=head2 add

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

=head2 mac

 $result_raw = $d->mac();

=head2 hexmac

 $result_hex = $d->hexmac();

=head2 b64mac

 $result_b64 = $d->b64mac();

=head1 SEE ALSO

=over 4

=item L<CryptX|CryptX>, L<Crypt::Mac|Crypt::Mac>

=back

=cut

__END__