package Crypt::ASN1;

use strict;
use warnings;
our $VERSION = '0.087_004';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw( asn1_decode_der asn1_decode_pem asn1_decode_der_file asn1_decode_pem_file )] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp 'croak';
use CryptX;
use Crypt::Misc qw(pem_to_der read_rawfile);

sub asn1_decode_pem {
  my $pem = shift;
  my $der = pem_to_der($pem) or croak "FATAL: asn1_decode_pem: failed to decode PEM data";
  return asn1_decode_der($der, @_);
}

sub asn1_decode_der_file {
  my $file = shift;
  return asn1_decode_der(read_rawfile($file), @_);
}

sub asn1_decode_pem_file {
  my $file = shift;
  return asn1_decode_pem(read_rawfile($file), @_);
}

1;

=pod

=head1 NAME

Crypt::ASN1 - DER/BER ASN.1 parser based on libtomcrypt's flexi decoder

=head1 SYNOPSIS

  use Crypt::ASN1 qw(asn1_decode_der);
  use Crypt::Misc qw(pem_to_der);

  my $der  = pem_to_der(do { local $/; <STDIN> });
  my $tree = asn1_decode_der($der);
  my $tree2 = asn1_decode_der($der, {
    oidmap => {
      '1.2.840.113549.1.1.11' => 'sha256WithRSAEncryption',
    },
  });

  # $tree is an arrayref of nodes at the top level.
  # Each node is a hashref:
  #   { type => 'SEQUENCE', value => [...children...] }
  #   { type => 'INTEGER',  value => '12345678...' }
  #   { type => 'OID',      value => '1.2.840.113549.1.1.11' }
  #   { type => 'BIT_STRING', value => $bytes, bits => 256 }
  #   { type => 'CUSTOM', class => 'CONTEXT_SPECIFIC',
  #             constructed => 1, tag => 0, value => [...] }
  #   ...

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Parses arbitrary DER (or BER) encoded ASN.1 data into a Perl data structure
without requiring any schema. Uses libtomcrypt's C<der_decode_sequence_flexi>
under the hood.

The result is an B<arrayref> of node hashrefs. Each node always has:

=over

=item C<type>

One of: C<SEQUENCE>, C<SET>, C<INTEGER>, C<OID>, C<OCTET_STRING>,
C<BIT_STRING>, C<NULL>, C<BOOLEAN>, C<UTF8_STRING>, C<PRINTABLE_STRING>,
C<IA5_STRING>, C<TELETEX_STRING>, C<UTCTIME>, C<GENERALIZEDTIME>, C<CUSTOM>.

=item C<value>

=over

=item * C<SEQUENCE> / C<SET> -- arrayref of child nodes

=item * C<INTEGER> -- decimal string (arbitrary precision)

=item * C<OID> -- dotted notation string, e.g. C<"1.2.840.113549.1.1.11">

If C<oidmap> is supplied and contains the dotted OID, the node also gets a
C<name> key with the mapped value.

=item * C<OCTET_STRING> -- raw binary string

=item * C<BIT_STRING> -- binary string (bits packed MSB-first); also has C<bits> key with the bit count

=item * C<NULL> -- C<undef>

=item * C<BOOLEAN> -- C<1> or C<0>

=item * C<UTF8_STRING> -- Perl Unicode string (C<utf8> flag on)

=item * C<PRINTABLE_STRING> / C<IA5_STRING> / C<TELETEX_STRING> -- byte string

=item * C<UTCTIME> -- RFC 3339 string, e.g. C<"2024-01-15T10:30:00Z"> or C<"2024-01-15T10:30:00+05:30">; 2-digit year is expanded using the RFC 5280 pivot (YY >= 50: 19YY, else 20YY)

=item * C<GENERALIZEDTIME> -- RFC 3339 string, e.g. C<"2024-01-15T10:30:00Z">

=item * C<CUSTOM> -- raw bytes for primitive; arrayref of children for constructed

=back

=back

C<CUSTOM> nodes additionally have C<class> (C<"CONTEXT_SPECIFIC">,
C<"APPLICATION">, C<"UNIVERSAL">, or C<"PRIVATE">), C<constructed> (C<1> or
C<0>), and C<tag> (integer tag number).

=head1 FUNCTIONS

=head2 asn1_decode_der

I<Since: CryptX-0.100>

  my $tree = asn1_decode_der($der_bytes);
  my $tree = asn1_decode_der($der_bytes, \%opts);

Parses C<$der_bytes> and returns an arrayref of top-level node hashrefs.
Croaks on parse error.

The optional C<%opts> hashref controls value formatting:

=over

=item C<int =E<gt> 'hex' | 'bytes'>

How to represent C<INTEGER> values. Default is a decimal string.
C<'hex'> gives an uppercase hex string (e.g. C<"FF">).
C<'bytes'> gives a raw big-endian binary string -- natural for RSA moduli and
other large integers.

=item C<bin =E<gt> 'hex' | 'base64'>

How to represent C<OCTET_STRING> and C<BIT_STRING> values. Default is raw
binary bytes.
C<'hex'> gives a lowercase hex string.
C<'base64'> gives a Base64-encoded string.

=item C<dt =E<gt> 'epoch'>

How to represent C<UTCTIME> and C<GENERALIZEDTIME> values. Default is an
RFC 3339 string (e.g. C<"2024-01-15T10:30:00Z">).
C<'epoch'> gives a Unix timestamp integer.

=item C<oidmap =E<gt> \%map>

Optional mapping from dotted OID strings to friendly names.
If an C<OID> node's value exists in C<%map>, the node additionally gets a
C<name> key with the mapped value.

=back

=head2 asn1_decode_pem

I<Since: CryptX-0.100>

  my $tree = asn1_decode_pem($pem_string);

Convenience wrapper: decodes the PEM envelope first (via L<Crypt::Misc/pem_to_der>),
then parses the resulting DER bytes. Croaks if the PEM cannot be decoded or the
DER cannot be parsed.

=head2 asn1_decode_der_file

I<Since: CryptX-0.100>

  my $tree = asn1_decode_der_file($filename);

Reads C<$filename> as raw binary (via L<Crypt::Misc/read_rawfile>) and parses it as DER.

=head2 asn1_decode_pem_file

I<Since: CryptX-0.100>

  my $tree = asn1_decode_pem_file($filename);

Reads C<$filename> as raw binary (via L<Crypt::Misc/read_rawfile>), decodes the PEM
envelope, then parses the resulting DER bytes.

=head1 SEE ALSO

=over

=item * L<CryptX|CryptX>, L<Crypt::Misc|Crypt::Misc>

=back

=cut
