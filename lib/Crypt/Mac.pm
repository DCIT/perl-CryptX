package Crypt::Mac;

use strict;
use warnings;
our $VERSION = '0.054_006';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 'import';
our %EXPORT_TAGS = ( all => [qw( mac mac_hex )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp;
$Carp::Internal{(__PACKAGE__)}++;
use CryptX;

sub add {
  my $self = shift;
  local $SIG{__DIE__} = \&CryptX::_croak;
  $self->_add_single($_) for (@_);
  return $self;
}

sub addfile {
  my ($self, $file) = @_;

  my $handle;
  if (ref(\$file) eq 'SCALAR') {
    #filename
    open($handle, "<", $file) || die "FATAL: cannot open '$file': $!";
    binmode($handle);
  }
  else {
    #handle
    $handle = $file
  }
  die "FATAL: invalid handle" unless defined $handle;

  my $n;
  my $buf = "";
  local $SIG{__DIE__} = \&CryptX::_croak;
  while (($n = read($handle, $buf, 32*1024))) {
    $self->_add_single($buf)
  }
  die "FATAL: read failed: $!" unless defined $n;

  return $self;
}

sub CLONE_SKIP { 1 } # prevent cloning

1;

__END__

=head1 NAME

Crypt::Mac - [internal only]

=cut