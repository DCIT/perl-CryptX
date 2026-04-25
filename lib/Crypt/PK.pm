package Crypt::PK;

use strict;
use warnings;
our $VERSION = '0.088_001';

use Carp;

sub _ssh_parse {
  my $raw = shift;
  return unless defined $raw;
  my $len = length($raw);
  my @parts = ();
  my $i = 0;
  while (1) {
    last unless $i + 4 <= $len;
    my $part_len = unpack("N4", substr($raw, $i, 4));
    last unless $i + 4 + $part_len <= $len;
    push @parts, substr($raw, $i + 4, $part_len);
    $i += $part_len + 4;
  }
  return @parts;
}

1;

=pod

=head1 NAME

Crypt::PK - [internal only]

=head1 SYNOPSIS

Do not use this module directly.

Use a concrete public-key module such as L<Crypt::PK::RSA>,
L<Crypt::PK::ECC>, or L<Crypt::PK::Ed25519>.

=head1 DESCRIPTION

Internal base/helper namespace for public-key modules.

Do not use this module directly. Use a concrete implementation such as
L<Crypt::PK::RSA>, L<Crypt::PK::ECC>, L<Crypt::PK::DSA>, L<Crypt::PK::DH>,
L<Crypt::PK::Ed25519>, L<Crypt::PK::X25519>, L<Crypt::PK::Ed448>, or
L<Crypt::PK::X448>.

=cut
