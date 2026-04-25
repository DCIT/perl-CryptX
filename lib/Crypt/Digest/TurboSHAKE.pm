package Crypt::Digest::TurboSHAKE;

use strict;
use warnings;
our $VERSION = '0.088_001';

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub addfile {
  my ($self, $file) = @_;

  my $handle;
  if (ref(\$file) eq 'SCALAR') {        #filename
    open($handle, "<", $file) || croak "FATAL: cannot open '$file': $!";
    binmode($handle);
  }
  else {                                #handle
    $handle = $file
  }
  croak "FATAL: invalid handle" unless defined $handle;

  my $n;
  my $buf = "";
  while (($n = read($handle, $buf, 32*1024))) {
    $self->add($buf)
  }
  croak "FATAL: read failed: $!" unless defined $n;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Digest::TurboSHAKE - XOF (extendable output) hash functions TurboSHAKE128 and TurboSHAKE256

=head1 SYNOPSIS

   use Crypt::Digest::TurboSHAKE;

   my $d = Crypt::Digest::TurboSHAKE->new(128); # TurboSHAKE128
   $d->add('any data');
   my $result = $d->done(32);                   # 32 bytes of output

   # or absorb input from a file instead
   my $file_d = Crypt::Digest::TurboSHAKE->new(128);
   $file_d->addfile('filename.dat');
   my $file_result = $file_d->done(32);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to TurboSHAKE128 and TurboSHAKE256 as defined in
L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>.

TurboSHAKE is a faster variant of SHAKE based on the reduced-round KeccakP-1600
permutation. Like SHAKE, it is an XOF (extendable output function): C<done()>
can be called multiple times to stream arbitrary amounts of output.

After the first C<done()>, treat the object as being in output mode:
do not call C<add()> again on that state. Use C<reset()> or a new object
to start hashing a new message.

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing TurboSHAKE object created
via C<new>, for example:

 my $d = Crypt::Digest::TurboSHAKE->new(128);

=head2 new

I<Since: CryptX-0.100>

 my $d = Crypt::Digest::TurboSHAKE->new($num);
 # $num ... [integer] 128 or 256 (selects TurboSHAKE128 or TurboSHAKE256)

=head2 clone

I<Since: CryptX-0.100>

 my $d2 = $d->clone;

=head2 reset

I<Since: CryptX-0.100>

 $d->reset;

=head2 add

I<Since: CryptX-0.100>

Appends data to the message. Returns the object itself (for chaining).

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

I<Since: CryptX-0.100>

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 done

I<Since: CryptX-0.100>

Returns C<$len> bytes of output as a binary string. Can be called repeatedly
to stream an unlimited amount of output from the same absorbed input. The
C<$len> argument is required and must be a positive integer.

After the first C<done()> call the object is in output mode. Calling
C<add()> in this state is not permitted; use C<reset()> or create a new
object to hash a different message.

 my $result_raw = $d->done($len);
 # can be called multiple times for streaming output
 # after the first done(), call reset() before hashing a new message

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest::SHAKE|Crypt::Digest::SHAKE>, L<Crypt::Digest::KangarooTwelve|Crypt::Digest::KangarooTwelve>

=item * L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>

=back

=cut
