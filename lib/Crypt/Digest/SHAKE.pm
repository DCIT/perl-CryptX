package Crypt::Digest::SHAKE;

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

Crypt::Digest::SHAKE - Hash functions SHAKE128, SHAKE256 from SHA3 family

=head1 SYNOPSIS

   use Crypt::Digest::SHAKE;

   my $d = Crypt::Digest::SHAKE->new(128);
   $d->add('any data');
   my $part1 = $d->done(100); # 100 raw bytes
   my $part2 = $d->done(100); # another 100 raw bytes
   #...

   # or absorb input from a file instead
   my $file_d = Crypt::Digest::SHAKE->new(128);
   $file_d->addfile('filename.dat');
   my $file_part1 = $file_d->done(100);

=head1 DESCRIPTION

Provides an interface to the SHA3's sponge function SHAKE.

This is an XOF (extendable output function). Feed input with C<add()> /
C<addfile()>, then read output with one or more C<done($len)> calls.
After the first C<done()>, treat the object as being in output mode:
do not call C<add()> again on that state. Use C<reset()> or a new object
to start hashing a new message.

=head1 METHODS

Unless noted otherwise, assume C<$d> is an existing SHAKE object created via
C<new>, for example:

 my $d = Crypt::Digest::SHAKE->new(128);

=head2 new

 my $d = Crypt::Digest::SHAKE->new($num);
 # $num ... [integer] 128 or 256 (selects SHAKE128 or SHAKE256)

=head2 clone

 my $d2 = $d->clone();

=head2 reset

 $d->reset();

=head2 add

Appends data to the message. Returns the object itself (for chaining).

Each argument is converted to bytes using Perl's usual scalar stringification.
Defined scalars, including numbers and string-overloaded objects, are
accepted. C<undef> is treated as an empty string and may emit Perl's usual
"uninitialized value" warning.

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

Reads the file content and appends it to the message. Returns the object itself (for chaining).

 $d->addfile('filename.dat');
 #or
 my $filehandle = ...; # existing binary-mode filehandle
 $d->addfile($filehandle);

=head2 done

Returns C<$len> bytes of output as a binary string. Can be called repeatedly
to stream an unlimited amount of output from the same absorbed input. The
C<$len> argument is required and must be a positive integer. Single
C<done()> calls are limited to 1,000,000,000 bytes, but the recommended way
to read large output is to call C<done()> repeatedly in 10 MB chunks.

After the first C<done()> call the object is in output mode. Calling
C<add()> in this state croaks; use C<reset()> or create a new object to hash
a different message.

 my $result_raw = $d->done($len);
 # can be called multiple times; $len is the number of output bytes to read
 # after the first done(), add() croaks until you call reset()

=head1 SEE ALSO

=over

=item * L<CryptX>, L<Crypt::Digest>

=item * L<https://csrc.nist.gov/pubs/fips/202/final>

=back

=cut
