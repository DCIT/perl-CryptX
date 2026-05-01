package Crypt::Mac;

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
      $self->add($buf);
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

Crypt::Mac - [internal only]

=head1 SYNOPSIS

Do not use this module directly.

Use a concrete MAC module instead.

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * L<Crypt::Mac::HMAC>, L<Crypt::Mac::Poly1305>, L<Crypt::Mac::BLAKE2b>, L<Crypt::Mac::BLAKE2s>

=item * L<Crypt::Mac::OMAC>, L<Crypt::Mac::PMAC>, L<Crypt::Mac::XCBC>, L<Crypt::Mac::F9>, L<Crypt::Mac::Pelican>

=back

=cut
