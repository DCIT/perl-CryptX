package Crypt::Digest::KangarooTwelve;

use strict;
use warnings;
our $VERSION = '0.088_005';

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub addfile {
  my ($self, $file) = @_;

  my ($handle, $close_handle);
  if (ref($file) && eval { defined fileno($file) }) {
    $handle = $file;
  }
  elsif (defined($file) && !ref($file)) {
    open($handle, "<", $file) || croak "FATAL: cannot open '$file': $!";
    binmode($handle);
    $close_handle = 1;
  }
  else {
    croak "FATAL: invalid handle";
  }

  my $n;
  my $buf = "";
  {
    local $SIG{__DIE__} = \&CryptX::_croak;
    while (($n = read($handle, $buf, 32*1024))) {
      $self->add($buf)
    }
    croak "FATAL: read failed: $!" unless defined $n;
  }
  close($handle) if $close_handle;

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

 my $d = Crypt::Digest::KangarooTwelve->new($num);
 # $num ... [integer] 128 or 256 (security level in bits)

=head2 clone

 my $d2 = $d->clone;

=head2 reset

 $d->reset;

=head2 add

Appends data to the message. Returns the object itself (for chaining).

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

 $d->add('any data');
 #or
 $d->add('chunk1', 'chunk2', ...);

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 customization

 $d->customization('context string');  # optional; call after add(), before done()

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

=head2 done

Returns C<$len> bytes of output as a binary string. Can be called repeatedly
to stream an unlimited amount of output from the same absorbed input. The
C<$len> argument is required and must be a positive integer. Single
C<done()> calls are limited to 1,000,000,000 bytes, but the recommended way
to read large output is to call C<done()> repeatedly in 10 MB chunks.

After the first C<done()> call the object is in output mode. Calling
C<add()> or C<customization()> in this state croaks; use
C<reset()> or create a new object to hash a different message.

 my $result_raw = $d->done($len);
 # can be called multiple times; $len is the number of output bytes to read
 # after the first done(), add() / customization() croak until you call reset()

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Digest::SHAKE>, L<Crypt::Digest::TurboSHAKE>

=item * L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>

=back

=cut
