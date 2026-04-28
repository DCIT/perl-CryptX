package Crypt::ASN1;

use strict;
use warnings;
our $VERSION = '0.088_005';

require Exporter; our @ISA = qw(Exporter); ### use Exporter 5.57 'import';
our %EXPORT_TAGS = ( all => [qw(
  asn1_decode_der asn1_decode_pem asn1_decode_der_file asn1_decode_pem_file
  asn1_encode_der asn1_encode_pem asn1_encode_der_file asn1_encode_pem_file
  asn1_to_string
)] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

use Carp 'croak';
use Config ();
use CryptX;
use Crypt::Misc qw(pem_to_der der_to_pem read_rawfile write_rawfile decode_b64);

# --- decode (public) ---

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

# --- encode (public) ---

sub asn1_encode_der {
  my ($tree) = @_;
  croak "FATAL: asn1_encode_der: argument must be an arrayref" unless ref $tree eq 'ARRAY';
  my $normalized = [ map { _normalize_node($_) } @$tree ];
  return _asn1_encode_der($normalized);
}

sub asn1_encode_pem {
  my ($tree, $header) = @_;
  $header = 'DATA' unless defined $header;
  my $der = asn1_encode_der($tree);
  return der_to_pem($der, $header);
}

sub asn1_encode_der_file {
  my ($tree, $file) = @_;
  my $der = asn1_encode_der($tree);
  write_rawfile($file, $der);
  return $der;
}

sub asn1_encode_pem_file {
  my ($tree, $header, $file) = @_;
  my $pem = asn1_encode_pem($tree, $header);
  write_rawfile($file, $pem);
  return $pem;
}

# --- dump (public) ---

sub asn1_to_string {
  my ($tree) = @_;
  croak "FATAL: asn1_to_string: argument must be an arrayref" unless ref $tree eq 'ARRAY';
  my $out = '';
  _dump_nodes(\$out, $tree, 0);
  return $out;
}

my %_LABEL = (
  BOOLEAN => 'BOOLEAN', INTEGER => 'INTEGER', BIT_STRING => 'BIT STRING',
  OCTET_STRING => 'OCTET STRING', NULL => 'NULL', OID => 'OBJECT',
  UTF8_STRING => 'UTF8STRING', PRINTABLE_STRING => 'PRINTABLESTRING',
  TELETEX_STRING => 'TELETEXSTRING', IA5_STRING => 'IA5STRING',
  UTCTIME => 'UTCTIME', GENERALIZEDTIME => 'GENERALIZEDTIME',
  SEQUENCE => 'SEQUENCE', SET => 'SET',
);

sub _dump_nodes {
  my ($out, $nodes, $depth) = @_;
  for my $node (@$nodes) {
    _dump_node($out, $node, $depth);
  }
}

sub _dump_node {
  my ($out, $node, $depth) = @_;
  my $type   = defined $node->{type} ? $node->{type} : '?';
  my $val    = $node->{value};
  my $fmt    = defined $node->{format} ? $node->{format} : '';
  my $indent = '  ' x $depth;

  if ($type eq 'SEQUENCE' || $type eq 'SET') {
    my $n = ref $val eq 'ARRAY' ? scalar @$val : 0;
    $$out .= "${indent}$_LABEL{$type} ($n elem)\n";
    _dump_nodes($out, $val, $depth + 1) if $n;
    return;
  }

  if ($type eq 'CUSTOM') {
    my $cls   = defined $node->{class} ? $node->{class} : 'CONTEXT_SPECIFIC';
    my $tag   = defined $node->{tag} ? $node->{tag} : 0;
    my $cons  = $node->{constructed};
    my $label = lc($cls) . " [$tag]";
    if ($cons && ref $val eq 'ARRAY') {
      my $n = scalar @$val;
      $$out .= "${indent}$label cons ($n elem)\n";
      _dump_nodes($out, $val, $depth + 1);
    } else {
      $$out .= "${indent}$label prim:${\ _dump_value_short($val, $fmt)}\n";
    }
    return;
  }

  my $label = exists $_LABEL{$type} ? $_LABEL{$type} : $type;
  $$out .= "${indent}${label}:${\ _dump_value($type, $val, $fmt, $node)}\n";
}

sub _dump_value {
  my ($type, $val, $fmt, $node) = @_;

  return '' if $type eq 'NULL';

  if ($type eq 'BOOLEAN') {
    return $val ? 'TRUE' : 'FALSE';
  }
  if ($type eq 'INTEGER') {
    return _dump_value_short($val, $fmt) if $fmt eq 'bytes';
    my $s = defined $val ? "$val" : '';
    return length($s) > 64 ? substr($s, 0, 61) . '...' : $s;
  }
  if ($type eq 'OID') {
    my $s = defined $val ? $val : '';
    $s .= " ($node->{name})" if defined $node->{name};
    return $s;
  }
  if ($type eq 'UTF8_STRING' || $type eq 'PRINTABLE_STRING'
      || $type eq 'IA5_STRING' || $type eq 'TELETEX_STRING') {
    my $s = defined $val ? $val : '';
    return length($s) > 64 ? substr($s, 0, 61) . '...' : $s;
  }
  if ($type eq 'UTCTIME' || $type eq 'GENERALIZEDTIME') {
    return defined $val ? "$val" : '';
  }
  if ($type eq 'OCTET_STRING' || $type eq 'BIT_STRING') {
    my $extra = '';
    if ($type eq 'BIT_STRING' && defined $node->{bits}) {
      $extra = " ($node->{bits} bit)";
    }
    return _dump_value_short($val, $fmt) . $extra;
  }
  return defined $val ? "$val" : '';
}

sub _dump_value_short {
  my ($val, $fmt) = @_;
  return '' unless defined $val && length $val;
  my $hex;
  if ($fmt eq 'hex') {
    $hex = lc($val);
  } elsif ($fmt eq 'base64') {
    $hex = lc unpack("H*", decode_b64($val));
  } else {
    $hex = lc unpack("H*", $val);
  }
  return length($hex) > 64 ? substr($hex, 0, 61) . '...' : $hex;
}

# --- normalization (internal) ---

my %_CLASS_MAP = (UNIVERSAL => 0, APPLICATION => 1, CONTEXT_SPECIFIC => 2, PRIVATE => 3);
my $_MAX_ULONG_DEC = _max_ulong_dec();
my $_MAX_OID_SECOND_ARC_DEC = _max_oid_second_arc_dec();

sub _normalize_node {
  my ($node) = @_;
  croak "FATAL: asn1_encode: node must be a hashref" unless ref $node eq 'HASH';
  my $type = defined $node->{type} ? $node->{type} : croak "FATAL: asn1_encode: node missing 'type'";
  my $fmt  = defined $node->{format} ? $node->{format} : '';
  my $val  = $node->{value};

  # --- constructed types ---
  if ($type eq 'SEQUENCE' || $type eq 'SET') {
    croak "FATAL: asn1_encode: $type value must be arrayref" unless ref($val) eq 'ARRAY';
    return { type => $type, value => [ map { _normalize_node($_) } @$val ] };
  }
  # --- INTEGER: always normalize to decimal string ---
  if ($type eq 'INTEGER') {
    croak "FATAL: asn1_encode: INTEGER missing value" unless defined $val;
    if ($fmt eq 'hex') {
      require Math::BigInt;
      my $hex = $val;
      my $neg = ($hex =~ s/^-//);
      my $bi  = Math::BigInt->new("0x$hex");
      $bi->bneg() if $neg;
      $val = $bi->bstr();
    }
    elsif ($fmt eq 'bytes') {
      require Math::BigInt;
      $val = Math::BigInt->new("0x" . unpack("H*", $val))->bstr();
    }
    else {
      $val = "$val"; # stringify Perl number
    }
    return { type => 'INTEGER', value => $val };
  }
  # --- BOOLEAN ---
  if ($type eq 'BOOLEAN') {
    return { type => 'BOOLEAN', value => $val ? 1 : 0 };
  }
  # --- NULL ---
  if ($type eq 'NULL') {
    return { type => 'NULL' };
  }
  # --- OID ---
  if ($type eq 'OID') {
    croak "FATAL: asn1_encode: OID missing value" unless defined $val;
    return { type => 'OID', value => _normalize_oid($val) };
  }
  # --- OCTET_STRING: always normalize to raw bytes ---
  if ($type eq 'OCTET_STRING') {
    $val = _bin_to_raw($val, $fmt);
    return { type => 'OCTET_STRING', value => $val };
  }
  # --- BIT_STRING: raw bytes + bits ---
  if ($type eq 'BIT_STRING') {
    $val  = _bin_to_raw($val, $fmt);
    my $bits = exists $node->{bits}
      ? _normalize_bit_count($node->{bits}, length($val))
      : (length($val) * 8);
    return { type => 'BIT_STRING', value => $val, bits => $bits };
  }
  # --- string types ---
  if ($type eq 'UTF8_STRING') {
    return { type => 'UTF8_STRING', value => defined $val ? $val : '' };
  }
  if ($type eq 'IA5_STRING' || $type eq 'PRINTABLE_STRING' || $type eq 'TELETEX_STRING') {
    return { type => $type, value => defined $val ? $val : '' };
  }
  # --- time types ---
  if ($type eq 'UTCTIME') {
    return { type => 'UTCTIME', value => _normalize_time($val, $fmt, 'utc') };
  }
  if ($type eq 'GENERALIZEDTIME') {
    return { type => 'GENERALIZEDTIME', value => _normalize_time($val, $fmt, 'gen') };
  }
  # --- CUSTOM ---
  if ($type eq 'CUSTOM') {
    my $class_name = defined $node->{class} ? $node->{class} : 'CONTEXT_SPECIFIC';
    croak "FATAL: asn1_encode: invalid CUSTOM class '$class_name'"
      unless exists $_CLASS_MAP{$class_name};
    my $cls    = $_CLASS_MAP{$class_name};
    my $constr = $node->{constructed} ? 1 : 0;
    my $tag    = _normalize_custom_tag(defined $node->{tag} ? $node->{tag} : 0);
    my %n = (type => 'CUSTOM', class => $cls, constructed => $constr, tag => $tag);
    if ($constr) {
      croak "FATAL: asn1_encode: CUSTOM constructed value must be arrayref"
        unless ref($val) eq 'ARRAY';
      $n{value} = [ map { _normalize_node($_) } @$val ];
    }
    else {
      croak "FATAL: asn1_encode: CUSTOM primitive value must not be a reference"
        if ref($val);
      $n{value} = _bin_to_raw($val, $fmt);
    }
    return \%n;
  }
  croak "FATAL: asn1_encode: unsupported type '$type'";
}

# Convert binary value from hex/base64 to raw bytes
sub _bin_to_raw {
  my ($val, $fmt) = @_;
  $val = '' unless defined $val;
  $fmt = '' unless defined $fmt;
  if ($fmt eq 'hex') {
    croak "FATAL: asn1_encode: invalid hex value"
      unless $val =~ /\A(?:[0-9A-Fa-f]{2})*\z/;
    return pack("H*", $val);
  }
  if ($fmt eq 'base64') {
    croak "FATAL: asn1_encode: invalid base64 value"
      unless $val =~ /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/;
    return decode_b64($val);
  }
  return $val;
}

sub _normalize_oid {
  my ($val) = @_;
  my $oid = "$val";

  croak "FATAL: asn1_encode: invalid OID value '$oid'"
    unless $oid =~ /\A\d+(?:\.\d+)+\z/;

  my @arc = split /\./, $oid;
  croak "FATAL: asn1_encode: OID must have at least 2 arcs"
    unless @arc >= 2;
  croak "FATAL: asn1_encode: OID first arc must be 0, 1, or 2"
    unless $arc[0] >= 0 && $arc[0] <= 2;
  croak "FATAL: asn1_encode: OID second arc must be between 0 and 39 when first arc is 0 or 1"
    if $arc[0] < 2 && $arc[1] > 39;
  croak "FATAL: asn1_encode: OID has too many arcs (maximum 64)"
    if @arc > 64;

  for my $i (1 .. $#arc) {
    my $limit = ($i == 1 && $arc[0] == 2) ? $_MAX_OID_SECOND_ARC_DEC : $_MAX_ULONG_DEC;
    croak "FATAL: asn1_encode: OID arc '$arc[$i]' is too large for this encoder"
      unless _decimal_fits_limit($arc[$i], $limit);
  }

  return $oid;
}

sub _normalize_bit_count {
  my ($bits, $byte_len) = @_;
  my $max_bits = $byte_len * 8;

  croak "FATAL: asn1_encode: BIT_STRING bits missing"
    unless defined $bits;

  my $raw = "$bits";
  croak "FATAL: asn1_encode: BIT_STRING bits must be a non-negative integer"
    unless $raw =~ /\A\d+\z/;

  $bits = int($raw);
  croak "FATAL: asn1_encode: BIT_STRING bits exceeds available data ($bits > $max_bits)"
    if $bits > $max_bits;

  return $bits;
}

sub _normalize_custom_tag {
  my ($tag) = @_;
  my $raw = "$tag";

  croak "FATAL: asn1_encode: CUSTOM tag must be a non-negative integer"
    unless $raw =~ /\A\d+\z/;
  croak "FATAL: asn1_encode: CUSTOM tag '$raw' is too large for this encoder"
    unless _decimal_fits_limit($raw, $_MAX_ULONG_DEC);

  return int($raw);
}

sub _decimal_fits_limit {
  my ($value, $limit) = @_;
  $value = "$value";
  $value =~ s/\A0+(?=\d)//;
  return 1 if length($value) < length($limit);
  return 0 if length($value) > length($limit);
  return $value le $limit;
}

sub _max_ulong_dec {
  my $bytes = $Config::Config{longsize} || 0;
  return '4294967295' if $bytes == 4;
  return '18446744073709551615' if $bytes == 8;

  require Math::BigInt;
  return Math::BigInt->new(2)->bpow($bytes * 8)->bsub(1)->bstr();
}

sub _max_oid_second_arc_dec {
  my $bytes = $Config::Config{longsize} || 0;
  return '4294967215' if $bytes == 4;
  return '18446744073709551535' if $bytes == 8;

  require Math::BigInt;
  return Math::BigInt->new(_max_ulong_dec())->bsub(80)->bstr();
}

# Normalize timestamp to ASN.1 wire format
sub _normalize_time {
  my ($val, $fmt, $kind) = @_;
  croak "FATAL: asn1_encode: time value missing" unless defined $val;
  my $type = $kind eq 'utc' ? 'UTCTIME' : 'GENERALIZEDTIME';

  # epoch (all digits, possibly negative)
  if ($fmt eq 'epoch' || ($fmt eq '' && $val =~ /^-?\d+$/)) {
    my @t = gmtime($val);
    my $year = $t[5] + 1900;
    if ($kind eq 'utc') {
      croak "FATAL: asn1_encode: UTCTIME year out of range: $year (expected 1950..2049)"
        if $year < 1950 || $year > 2049;
    }
    return ($kind eq 'utc')
      ? sprintf("%02d%02d%02d%02d%02d%02dZ", $t[5] % 100, $t[4]+1, $t[3], $t[2], $t[1], $t[0])
      : sprintf("%04d%02d%02d%02d%02d%02dZ", $t[5]+1900,  $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
  }

  # RFC 3339  (e.g. "2024-01-15T10:30:00Z" or "2024-01-15T10:30:00.5+05:30")
  if ($fmt eq 'rfc3339' || $val =~ /^\d{4}-/) {
    $val =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/
      or croak "FATAL: asn1_encode: invalid RFC 3339 time for $type: $val";
    my ($YYYY,$MM,$DD,$hh,$mm,$ss,$fs,$tz,$sign,$oh,$om) = ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);
    my $r;
    if ($kind eq 'utc') {
      croak "FATAL: asn1_encode: UTCTIME does not allow fractional seconds: $val"
        if defined $fs && length $fs;
      croak "FATAL: asn1_encode: UTCTIME year out of range: $YYYY (expected 1950..2049)"
        if $YYYY < 1950 || $YYYY > 2049;
      my $YY = ($YYYY >= 2000) ? $YYYY - 2000 : $YYYY - 1900;
      $r = sprintf "%02d%02d%02d%02d%02d%02d", $YY, $MM, $DD, $hh, $mm, $ss;
    }
    else {
      $r = sprintf "%04d%02d%02d%02d%02d%02d", $YYYY, $MM, $DD, $hh, $mm, $ss;
      $r .= ".$fs" if defined $fs && $fs > 0;
    }
    $r .= ($tz eq 'Z') ? 'Z' : sprintf("%s%02d%02d", $sign, $oh, $om);
    return $r;
  }

  croak "FATAL: asn1_encode: invalid $type value '$val' (expected RFC 3339 string or epoch)";
}

1;

=pod

=head1 NAME

Crypt::ASN1 - DER ASN.1 parser and encoder based on libtomcrypt

=head1 SYNOPSIS

  use Crypt::ASN1 qw(asn1_decode_der asn1_encode_der asn1_to_string);

  # --- decode ---
  my $tree = asn1_decode_der($der_bytes);
  my $tree = asn1_decode_der($der_bytes, { int => 'hex', bin => 'hex' });

  # --- inspect ---
  print asn1_to_string($tree);

  # --- encode a decoded tree ---
  my $der2 = asn1_encode_der($tree);

  # --- build from scratch ---
  my $der = asn1_encode_der([{
    type  => 'SEQUENCE',
    value => [
      { type => 'INTEGER',      value => '42' },
      { type => 'BOOLEAN',      value => 1 },
      { type => 'OID',          value => '1.2.840.113549.1.1.11' },
      { type => 'UTF8_STRING',  value => 'hello' },
      { type => 'OCTET_STRING', value => "\x00\x01\x02" },
      { type => 'BIT_STRING',   value => "\x03\x02\x01", bits => 20 },
      { type => 'NULL' },
      { type => 'UTCTIME',      value => '2025-06-15T12:00:00Z' },
      { type => 'CUSTOM', class => 'CONTEXT_SPECIFIC',
        constructed => 1, tag => 0,
        value => [{ type => 'INTEGER', value => '2' }] },
    ],
  }]);

=head1 DESCRIPTION

I<Since: CryptX-0.100>

Parses DER-encoded ASN.1 data into a Perl data structure without requiring
any schema, and encodes Perl data structures back to DER.
Uses libtomcrypt's C<der_decode_sequence_flexi> for decoding.

Both the decoder output and the encoder input use the same B<node hash>
structure described below.  When given a tree produced by the decoder, the
encoder does its best to produce the same ASN.1 that was originally parsed,
regardless of what decode options were used.

=head1 NODE HASH STRUCTURE

Both the decoder and encoder operate on the same data structure: an B<arrayref
of node hashrefs>.  Each hashref represents one ASN.1 TLV (Tag-Length-Value)
element.

=head2 Common keys

Every node has three keys:

=over

=item C<type> (string, B<required>)

The ASN.1 type name.  Built-in values include:

  BOOLEAN  INTEGER  NULL  OID
  OCTET_STRING  BIT_STRING  UTF8_STRING
  PRINTABLE_STRING  IA5_STRING  TELETEX_STRING
  UTCTIME  GENERALIZEDTIME
  SEQUENCE  SET  CUSTOM

The list above is not exhaustive for decoded input.  If the decoder encounters
an ASN.1 tag that does not map to one of the built-in type names above, it is
returned as C<CUSTOM> with the appropriate C<class>, C<constructed>, and
C<tag> fields.  This includes unsupported universal tags such as
C<ENUMERATED>, which decode as C<CUSTOM> with C<< class => "UNIVERSAL" >>.

=item C<value> (varies, required for most types)

The decoded value.  Its Perl type depends on C<type> and sometimes on the
C<format> key -- see L</Per-type details> below.

=item C<format> (string, decoder sets it, encoder reads it)

Tells the encoder how the C<value> is represented so it can convert it back
to DER.  Set automatically by the decoder; when building nodes from scratch
you may omit it -- the encoder then assumes the default representation for
each type.

=back

=head2 Per-type details

Each subsection below documents one C<type>.  For types where the C<value>
representation depends on the decode option used, a B<format table> lists
every C<format>/C<value> combination.  B<The encoder accepts every
combination shown> -- it reads C<format> and converts C<value> back to DER
automatically.

=head3 BOOLEAN

B<Keys>: C<type>, C<format>, C<value>.

C<value> is C<1> (true) or C<0> (false).  C<format> is always C<"bool">.

  { type => "BOOLEAN", format => "bool", value => 1 }

=head3 INTEGER

B<Keys>: C<type>, C<format>, C<value>.

C<value> is an arbitrary-precision signed integer.  C<format> describes the
representation:

  format    value                        decode option     example
  --------  ---------------------------  ----------------  ---------------
  decimal   decimal string               (default)         "255"
  hex       lowercase hex string         int => 'hex'      "ff"
  bytes     big-endian binary string     int => 'bytes'    "\xff"

All three forms are accepted by the encoder.  When C<format> is absent the
encoder treats C<value> as a decimal string (a Perl integer is fine too).

Negative integers: C<decimal> and C<hex> carry a leading C<-> (e.g. C<"-5">).
C<bytes> stores the unsigned magnitude only and is intended for naturally
unsigned values such as RSA moduli.  When decoding with C<< int => 'bytes' >>,
negative ASN.1 INTEGER values are rejected.

=head3 NULL

B<Keys>: C<type>, C<format>, C<value>.

C<value> is always C<undef>.  C<format> is always C<"null">.  The encoder
ignores C<value>.

  { type => "NULL", format => "null", value => undef }

=head3 OID

B<Keys>: C<type>, C<format>, C<value>, and optionally C<name>.

C<value> is a dotted-decimal OID string (at least two arcs).  C<format> is
always C<"oid">.

  { type => "OID", format => "oid", value => "1.2.840.113549.1.1.11" }

As a convenience, the encoder accepts textual arcs with leading zeros and
lets DER encoding canonicalize them.  For example, C<"2.000.1"> encodes and
decodes back as C<"2.0.1">.

B<Optional key>: C<name> -- present only when the C<oidmap> decode option
is supplied and the OID is found in the map.  Ignored by the encoder.

  { ..., name => "sha256WithRSAEncryption" }   # when oidmap matches

=head3 OCTET_STRING

B<Keys>: C<type>, C<format>, C<value>.

C<value> is binary data.  C<format> describes the representation:

  format    value                        decode option      example
  --------  ---------------------------  -----------------  --------
  bytes     raw binary string            (default)          "\x04\x01"
  hex       lowercase hex string         bin => 'hex'       "0401"
  base64    Base64-encoded string        bin => 'base64'    "BAE="

All three forms are accepted by the encoder.  When C<format> is absent the
encoder treats C<value> as raw bytes.

=head3 BIT_STRING

B<Keys>: C<type>, C<format>, C<value>, C<bits>.

C<value> is the packed bit data (MSB-first).  C<format> follows the same
rules as C<OCTET_STRING> (C<"bytes">, C<"hex">, or C<"base64">).  All three
forms are accepted by the encoder.

C<bits> is the exact number of significant bits.  The quantity
C<< 8 * byte_length(value) - bits >> gives the number of unused trailing
bits in the last byte.

When C<format> is absent the encoder treats C<value> as raw bytes.  When
C<bits> is absent it defaults to C<< 8 * length(value) >> (no unused bits).

  # default format (raw bytes, 25 significant bits)
  { type => "BIT_STRING", format => "bytes",
    value => "\x03\x02\x01\x00", bits => 25 }

  # hex format
  { type => "BIT_STRING", format => "hex",
    value => "03020100", bits => 25 }

=head3 UTF8_STRING

B<Keys>: C<type>, C<format>, C<value>.

C<value> is a Perl Unicode string (C<utf8> flag on).  C<format> is always
C<"utf8">.

  { type => "UTF8_STRING", format => "utf8", value => "caf\x{e9}" }

=head3 PRINTABLE_STRING, IA5_STRING, TELETEX_STRING

B<Keys>: C<type>, C<format>, C<value>.

C<value> is a byte string.  C<format> is always C<"string"> for all three.

  { type => "PRINTABLE_STRING", format => "string", value => "abc" }
  { type => "IA5_STRING",       format => "string", value => "ia5" }
  { type => "TELETEX_STRING",   format => "string", value => "tele" }

=head3 UTCTIME

B<Keys>: C<type>, C<format>, C<value>.

C<value> is a timestamp.  C<format> describes the representation:

  format    value                          decode option    example
  --------  -----------------------------  ---------------  -----------------------
  rfc3339   RFC 3339 string                (default)        "2024-01-15T10:30:00Z"
  epoch     Unix timestamp (integer)       dt => 'epoch'    1705314600

Both forms are accepted by the encoder.  When C<format> is absent, the
encoder auto-detects: an all-digit value is treated as epoch, a value
matching C<YYYY-> is treated as RFC 3339.

For C<UTCTIME>, encoder input must fall within the UTCTime year window
C<1950..2049>; values outside that range are rejected.  Fractional seconds
are also rejected for C<UTCTIME>.

Time validation in the encoder is currently B<syntactic>, not full calendar
validation.  The encoder checks the accepted input shape and ASN.1-specific
constraints above, but it does not verify that every RFC 3339-looking date
and time is semantically valid.

The decoder expands the 2-digit UTCTime year using the RFC 5280 window
(YY E<gt>= 50 E<rarr> 19YY, else 20YY).  Timezone offsets are preserved
(e.g. C<"2024-01-15T10:30:00+05:30">).

=head3 GENERALIZEDTIME

B<Keys>: C<type>, C<format>, C<value>.

Same C<format> rules as C<UTCTIME>; both forms are accepted by the encoder.
Fractional seconds are preserved (e.g. C<"2024-01-15T10:30:00.125Z">).
Validation is likewise syntactic only; semantically invalid calendar values
that match the accepted timestamp syntax are not currently rejected.

=head3 SEQUENCE

B<Keys>: C<type>, C<format>, C<value>.

C<value> is an arrayref of child node hashrefs (in order).  C<format> is
always C<"array">.

  { type => "SEQUENCE", format => "array", value => [ ...children... ] }

=head3 SET

B<Keys>: C<type>, C<format>, C<value>.

Same structure as C<SEQUENCE>.  C<format> is always C<"array">.  Both
ASN.1 SET and SET OF are represented as C<type =E<gt> "SET"> (they share
the same DER tag C<0x31>).

=head3 CUSTOM

Represents any tag that does not map to one of the built-in type names above.
This is commonly used for context-specific implicit/explicit tags (C<[0]>,
C<[1]>, ...) found in X.509 certificates and other ASN.1 schemas, but it can
also be emitted by the decoder for unsupported universal tags.

B<Keys>: C<type>, C<format>, C<value>, C<class>, C<constructed>, C<tag>.

=over

=item C<class> (string) -- C<"CONTEXT_SPECIFIC">, C<"APPLICATION">, C<"UNIVERSAL">, or C<"PRIVATE">

=item C<constructed> (integer) -- C<1> if constructed, C<0> if primitive

=item C<tag> (integer) -- the tag number (e.g. C<0> for C<[0]>)

Must be a non-negative integer within the range supported by the current
encoder build.

=back

B<Constructed> (C<< constructed => 1 >>): C<value> is an arrayref of child
nodes.  C<format> is C<"array">.

  { type => "CUSTOM", format => "array",
    class => "CONTEXT_SPECIFIC", constructed => 1, tag => 0,
    value => [ { type => "INTEGER", ... } ] }

B<Primitive> (C<< constructed => 0 >>): C<value> is raw data.  C<format>
follows the same rules as C<OCTET_STRING> (C<"bytes">, C<"hex">, or
C<"base64"> depending on the C<bin> decode option).  All three forms are
accepted by the encoder.  Primitive C<CUSTOM> values must not be references.

  # default format
  { type => "CUSTOM", format => "bytes",
    class => "CONTEXT_SPECIFIC", constructed => 0, tag => 1,
    value => "\xAA\xBB" }

  # hex format (bin => 'hex')
  { type => "CUSTOM", format => "hex",
    class => "CONTEXT_SPECIFIC", constructed => 0, tag => 1,
    value => "aabb" }

=head2 Re-encoding Decoded Trees

The encoder reads C<format> and converts C<value> back to DER before
encoding.  When given a tree returned by C<asn1_decode_der>, it does its best
to produce the same ASN.1 that was originally parsed, regardless of the
decode options used:

  my $tree = asn1_decode_der($der, { int=>'hex', bin=>'base64', dt=>'epoch' });
  my $der2 = asn1_encode_der($tree);

=head2 Building nodes from scratch

When constructing nodes by hand you need C<type> and C<value> (plus the
extra keys noted above for C<CUSTOM> and C<BIT_STRING>).  You may omit
C<format>; the encoder assumes:

  Type              default value interpretation
  ----------------  ------------------------------------------
  INTEGER           decimal string or Perl integer
  OCTET_STRING      raw bytes
  BIT_STRING        raw packed bytes, bits = length(value) * 8
  UTCTIME           RFC 3339 string (or all-digit epoch)
  GENERALIZEDTIME   RFC 3339 string (or all-digit epoch)
  CUSTOM primitive  raw bytes

You may also supply C<format> explicitly if you prefer to work with hex
or base64 representations:

  # these two produce identical DER
  { type => "OCTET_STRING", value => "\x04\x01" }
  { type => "OCTET_STRING", format => "hex", value => "0401" }

=head1 FUNCTIONS

=head2 asn1_decode_der

  my $tree = asn1_decode_der($der_bytes);
  my $tree = asn1_decode_der($der_bytes, \%opts);

Parses C<$der_bytes> and returns an arrayref of top-level node hashrefs.
Croaks on parse error.

The optional C<%opts> hashref controls value formatting:

=over

=item C<int =E<gt> 'hex' | 'bytes'>

How to represent C<INTEGER> values.  Default is a decimal string
(C<< format=>"decimal" >>).
C<'hex'> gives a lowercase hex string (C<< format=>"hex" >>).
C<'bytes'> gives a raw big-endian binary string (C<< format=>"bytes" >>) for
non-negative INTEGER values only; decoding croaks if the DER INTEGER is
negative.

=item C<bin =E<gt> 'hex' | 'base64'>

How to represent C<OCTET_STRING>, C<BIT_STRING>, and primitive C<CUSTOM>
values.  Default is raw binary bytes (C<< format=>"bytes" >>).
C<'hex'> gives a lowercase hex string (C<< format=>"hex" >>).
C<'base64'> gives a Base64-encoded string (C<< format=>"base64" >>).

=item C<dt =E<gt> 'epoch'>

How to represent C<UTCTIME> and C<GENERALIZEDTIME> values.  Default is an
RFC 3339 string (C<< format=>"rfc3339" >>).
C<'epoch'> gives a Unix timestamp integer (C<< format=>"epoch" >>).
This works reliably only on Perls with 64-bit integers; on 32-bit integer
Perls, large timestamps may overflow or lose precision.

=item C<oidmap =E<gt> \%map>

A hashref mapping dotted OID strings to friendly names.  When a decoded
C<OID> node's value exists as a key in C<%map>, the node gets an additional
C<name> key with the mapped value.  Does not affect encoding.

=back

=head2 asn1_decode_pem

  my $tree = asn1_decode_pem($pem_string);
  my $tree = asn1_decode_pem($pem_string, \%opts);

Decodes the PEM envelope first (via L<Crypt::Misc/pem_to_der>), then parses
the resulting DER bytes.  Accepts the same C<%opts> as C<asn1_decode_der>.

=head2 asn1_decode_der_file

  my $tree = asn1_decode_der_file($filename);
  my $tree = asn1_decode_der_file($filename, \%opts);

Reads C<$filename> as raw binary and parses it as DER.

=head2 asn1_decode_pem_file

  my $tree = asn1_decode_pem_file($filename);
  my $tree = asn1_decode_pem_file($filename, \%opts);

Reads C<$filename>, decodes the PEM envelope, then parses the DER bytes.

=head2 asn1_encode_der

  my $der_bytes = asn1_encode_der($tree);

Encodes C<$tree> (an arrayref of node hashrefs) to DER bytes.  The input
may be a tree previously returned by C<asn1_decode_der> or one
built from scratch.  Croaks on invalid input.

The encoder normalizes every node before encoding: it reads C<format> (if
present) to determine how to interpret C<value>, converts it to the canonical
DER form, and encodes it.

The current low-level encoder supports element content lengths up to
C<0xffffffff> bytes; larger values are rejected.

=head2 asn1_encode_pem

  my $pem_string = asn1_encode_pem($tree, $header);

Encodes C<$tree> to DER, then wraps in a PEM envelope with the given
C<$header> (e.g. C<"CERTIFICATE">, C<"RSA PRIVATE KEY">).  Defaults to
C<"DATA"> if C<$header> is omitted.

=head2 asn1_encode_der_file

  asn1_encode_der_file($tree, $filename);

Encodes C<$tree> to DER and writes it to C<$filename>.

=head2 asn1_encode_pem_file

  asn1_encode_pem_file($tree, $header, $filename);

Encodes C<$tree> to PEM and writes it to C<$filename>.

=head2 asn1_to_string

  my $text = asn1_to_string($tree);

Returns a human-readable text representation of C<$tree> (an arrayref of
node hashrefs as returned by any C<asn1_decode_*> function).  Useful for
debugging and inspection, similar to C<openssl asn1parse> output.

  print asn1_to_string(asn1_decode_pem_file("cert.pem"));

produces output like:

  SEQUENCE (3 elem)
    SEQUENCE (8 elem)
      context_specific [0] cons (1 elem)
        INTEGER:2
      INTEGER:17923815188543234454
      SEQUENCE (2 elem)
        OBJECT:1.2.840.113549.1.1.11
        NULL:
      ...
    BIT STRING:3082010a0282010100c242299a49420c21dcf9b957afcdc49... (2160 bit)

Binary values (C<OCTET_STRING>, C<BIT_STRING>, primitive C<CUSTOM>) are
shown as lowercase hex, truncated to 64 characters with C<...> for longer
values.  C<BIT_STRING> additionally shows the bit count in parentheses.
C<OID> nodes that have a C<name> key (via C<oidmap>) show the name in
parentheses after the dotted value.

The function handles trees decoded with any combination of decode options
(C<int>, C<bin>, C<dt>).

=head1 SEE ALSO

L<CryptX>, L<Crypt::Misc>

=cut
