package Crypt::Digest::KangarooTwelve;

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

Crypt::Digest::KangarooTwelve - XOF (extendable output) hash function KangarooTwelve

=head1 SYNOPSIS

   use Crypt::Digest::KangarooTwelve;

   my $d = Crypt::Digest::KangarooTwelve->new(128); # 128-bit security
   $d->add('any data');
   $d->customization('optional context string');
   my $result = $d->done(32);                      # 32 bytes of output

   # or absorb input from a file instead
   my $file_d = Crypt::Digest::KangarooTwelve->new(128);
   $file_d->addfile('filename.dat');
   $file_d->customization('optional context string');
   my $file_result = $file_d->done(32);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to KangarooTwelve (K12) as defined in
L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>.

KangarooTwelve is a fast cryptographic hash and XOF based on a reduced-round
(12-round) Keccak-p permutation. It supports an optional B<customization string>
that binds the output to a specific context. C<done()> can be called multiple
times to stream arbitrary amounts of output.

B<Order of operations>: C<add()> must be called before C<customization()>;
C<customization()> must be called before C<done()>.
After the first C<done()>, treat the object as being in output mode:
do not call C<add()> or C<customization()> again on that state. Use C<reset()>
or a new object to start hashing a new message.

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing KangarooTwelve object
created via C<new>, for example:

 my $d = Crypt::Digest::KangarooTwelve->new(128);

=head2 new

I<Since: CryptX-0.100>

 my $d = Crypt::Digest::KangarooTwelve->new($num);
 # $num ... [integer] 128 or 256 (security level in bits)

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
 $d->add('chunk1', 'chunk2', ...);

=head2 addfile

I<Since: CryptX-0.100>

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 customization

I<Since: CryptX-0.100>

 $d->customization('context string');  # optional; call after add(), before done()

=head2 done

I<Since: CryptX-0.100>

Returns C<$len> bytes of output as a binary string. Can be called repeatedly
to stream an unlimited amount of output from the same absorbed input. The
C<$len> argument is required and must be a positive integer.

After the first C<done()> call the object is in output mode. Calling
C<add()> or C<customization()> in this state is not permitted; use
C<reset()> or create a new object to hash a different message.

 my $result_raw = $d->done($len);
 # can be called multiple times for streaming output
 # after the first done(), call reset() before hashing a new message

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest::SHAKE|Crypt::Digest::SHAKE>, L<Crypt::Digest::TurboSHAKE|Crypt::Digest::TurboSHAKE>

=item * L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>

=back

=cut
