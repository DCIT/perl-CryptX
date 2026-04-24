package Crypt::Digest::TurboSHAKE;

use strict;
use warnings;
our $VERSION = '0.087_004';

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

   $d = Crypt::Digest::TurboSHAKE->new(128);    # TurboSHAKE128
   $d->add('any data');
   $d->addfile('filename.dat');
   $result = $d->done(32);                       # 32 bytes of output

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Provides an interface to TurboSHAKE128 and TurboSHAKE256 as defined in
L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>.

TurboSHAKE is a faster variant of SHAKE based on the reduced-round KeccakP-1600
permutation. Like SHAKE, it is an XOF (extendable output function): C<done()>
can be called multiple times to stream arbitrary amounts of output.

=head1 METHODS

=head2 new

I<Since: CryptX-0.100>

 $d = Crypt::Digest::TurboSHAKE->new($num);
 # $num ... 128 or 256

=head2 clone

I<Since: CryptX-0.100>

 $d2 = $d->clone;

=head2 reset

I<Since: CryptX-0.100>

 $d->reset;

=head2 add

I<Since: CryptX-0.100>

 $d->add('any data');
 #or
 $d->add('any data', 'more data', 'even more data');

=head2 addfile

I<Since: CryptX-0.100>

 $d->addfile('filename.dat');
 #or
 $d->addfile(*FILEHANDLE);

=head2 done

I<Since: CryptX-0.100>

 $result_raw = $d->done($len);
 # can be called multiple times for streaming output

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Digest::SHAKE|Crypt::Digest::SHAKE>, L<Crypt::Digest::KangarooTwelve|Crypt::Digest::KangarooTwelve>

=item * L<RFC 9861|https://www.rfc-editor.org/rfc/rfc9861>

=back

=cut
