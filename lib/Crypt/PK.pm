package Crypt::PK;

use strict;
use warnings;
our $VERSION = '0.088_005';

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

Use a concrete public-key module instead.

=head1 SEE ALSO

=over

=item * L<CryptX>

=item * L<Crypt::PK::RSA>, L<Crypt::PK::ECC>, L<Crypt::PK::DSA>, L<Crypt::PK::DH>

=item * L<Crypt::PK::Ed25519>, L<Crypt::PK::Ed448>, L<Crypt::PK::X25519>, L<Crypt::PK::X448>

=back

=cut
