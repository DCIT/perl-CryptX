package Crypt::Mac;

use strict;
use warnings;
our $VERSION = '0.088_001';

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub addfile {
  my ($self, $file) = @_;

  my $handle;
  if (ref(\$file) eq 'SCALAR') {
    open($handle, "<", $file) || die "FATAL: cannot open '$file': $!";
    binmode($handle);
  }
  else {
    $handle = $file
  }
  die "FATAL: invalid handle" unless defined $handle;

  my $n;
  my $buf = "";
  local $SIG{__DIE__} = \&CryptX::_croak;
  while (($n = read($handle, $buf, 32*1024))) {
    $self->add($buf);
  }
  die "FATAL: read failed: $!" unless defined $n;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

=pod

=head1 NAME

Crypt::Mac - [internal only]

=head1 SYNOPSIS

Do not use this module directly.

Use a concrete MAC module such as L<Crypt::Mac::HMAC> or
L<Crypt::Mac::Poly1305>.

=head1 DESCRIPTION

Internal base class for MAC implementations.

Do not use this module directly. Use a concrete implementation such as
L<Crypt::Mac::HMAC>, L<Crypt::Mac::Poly1305>, L<Crypt::Mac::BLAKE2b>, or
another C<Crypt::Mac::*> module.

=cut
