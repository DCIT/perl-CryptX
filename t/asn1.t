use strict;
use warnings;

use Test::More tests => 158;
use Crypt::ASN1 qw(asn1_decode_der asn1_decode_pem asn1_decode_der_file asn1_decode_pem_file
                    asn1_encode_der asn1_encode_pem asn1_encode_der_file asn1_encode_pem_file
                    asn1_to_string);
use Crypt::Misc qw(pem_to_der read_rawfile);

# Helper: build DER TLV
sub tlv { my ($tag, $val) = @_; pack("CC", $tag, length($val)) . $val }

{ ### basic types inside a SEQUENCE
  my $der = tlv(0x30,
                tlv(0x02, pack("C", 42))            # INTEGER 42
              . tlv(0x0C, "Hi")                      # UTF8String "Hi"
              . tlv(0x06, pack("CC", 0x2a, 0x03))    # OID 1.2.3
              . tlv(0x04, "bytes")                   # OCTET_STRING
              . tlv(0x05, "")                        # NULL
              . tlv(0x01, pack("C", 0xFF))           # BOOLEAN true
              . tlv(0x13, "abc")                     # PrintableString
              . tlv(0x16, "ia5")                     # IA5String
  );

  my $tree = asn1_decode_der($der);
  is(scalar @$tree, 1,          'top level has 1 node');
  my $seq = $tree->[0];
  is($seq->{type}, 'SEQUENCE',  'outer SEQUENCE');
  my $ch = $seq->{value};
  is(scalar @$ch, 8,            '8 children');

  is($ch->[0]{type},  'INTEGER',          'INTEGER type');
  is($ch->[0]{value}, '42',               'INTEGER value');

  is($ch->[1]{type},  'UTF8_STRING',      'UTF8_STRING type');
  is($ch->[1]{value}, 'Hi',              'UTF8_STRING value');

  is($ch->[2]{type},   'OID',    'OID type');
  is($ch->[2]{format}, 'oid',    'OID format');
  is($ch->[2]{value},  '1.2.3', 'OID value');

  is($ch->[3]{type},  'OCTET_STRING',    'OCTET_STRING type');
  is($ch->[3]{value}, 'bytes',          'OCTET_STRING value');

  is($ch->[4]{type},  'NULL',            'NULL type');
  ok(!defined $ch->[4]{value},          'NULL value is undef');

  is($ch->[5]{type},  'BOOLEAN',         'BOOLEAN type');
  is($ch->[5]{value}, 1,                'BOOLEAN true');

  is($ch->[6]{type},  'PRINTABLE_STRING', 'PRINTABLE_STRING type');
  is($ch->[7]{type},  'IA5_STRING',       'IA5_STRING type');

  # OID name lookup is opt-in via oidmap: Ed25519 = 1.3.101.112
  my $oid_der = tlv(0x06, pack("CCC", 0x2b, 0x65, 0x70));  # 1.3.101.112
  my $oid_node = asn1_decode_der($oid_der)->[0];
  is($oid_node->{value}, '1.3.101.112', 'OID value Ed25519');
  ok(!exists $oid_node->{name},         'OID name absent by default');

  $oid_node = asn1_decode_der($oid_der, { oidmap => { '1.3.101.112' => 'ed25519' } })->[0];
  is($oid_node->{name},  'ed25519',     'OID name via oidmap');
}

{ ### nested SEQUENCE
  my $inner = tlv(0x30, tlv(0x02, pack("C", 7)));  # SEQUENCE { INTEGER 7 }
  my $outer = tlv(0x30, $inner);
  my $tree  = asn1_decode_der($outer);
  my $ch    = $tree->[0]{value};
  is($ch->[0]{type}, 'SEQUENCE', 'nested SEQUENCE');
  is($ch->[0]{value}[0]{value}, '7', 'nested INTEGER');
}

{ ### empty constructed values decode as empty arrays and round-trip
  my $seq = asn1_decode_der(pack("H*", "3000"));
  is(ref $seq->[0]{value}, 'ARRAY', 'empty SEQUENCE decodes to arrayref');
  is(scalar @{$seq->[0]{value}}, 0, 'empty SEQUENCE has no phantom child');
  is(unpack("H*", asn1_encode_der($seq)), '3000', 'empty SEQUENCE round-trips');

  my $set = asn1_decode_der(pack("H*", "3100"));
  is(scalar @{$set->[0]{value}}, 0, 'empty SET has no phantom child');
  is(unpack("H*", asn1_encode_der($set)), '3100', 'empty SET round-trips');

  my $custom = asn1_decode_der(pack("H*", "a000"));
  is(scalar @{$custom->[0]{value}}, 0, 'empty constructed CUSTOM has no phantom child');
  is(unpack("H*", asn1_encode_der($custom)), 'a000', 'empty constructed CUSTOM round-trips');
}

{ ### multiple top-level elements
  my $der = tlv(0x02, pack("C", 1)) . tlv(0x02, pack("C", 2));
  my $tree = asn1_decode_der($der);
  is(scalar @$tree, 2,   '2 top-level elements');
  is($tree->[0]{value}, '1', 'first INTEGER');
  is($tree->[1]{value}, '2', 'second INTEGER');
}

{ ### unsupported universal tag decodes as CUSTOM/UNIVERSAL
  my $der = tlv(0x0A, pack("C", 5)); # ENUMERATED 5
  my $node = asn1_decode_der($der)->[0];
  is($node->{type}, 'CUSTOM', 'ENUMERATED decodes as CUSTOM');
  is($node->{class}, 'UNIVERSAL', 'ENUMERATED decodes with UNIVERSAL class');
  is($node->{tag}, 10, 'ENUMERATED universal tag number preserved');
  is($node->{value}, "\x05", 'ENUMERATED raw value preserved');
}

{ ### real EC private key via asn1_decode_pem
  my $pem  = do { local $/; open my $f, "<", "t/data/openssl_ec1.key.pem" or die $!; <$f> };
  my $tree = asn1_decode_pem($pem);
  is($tree->[0]{type}, 'SEQUENCE', 'EC key: outer SEQUENCE');
  is($tree->[0]{value}[0]{value}, '1', 'EC key: version = 1');
}

{ ### format options: int, bin, dt
  my $der = tlv(0x30, tlv(0x02, "\x00\xff") . tlv(0x04, "hi"));

  my $t = asn1_decode_der($der);
  is($t->[0]{value}[0]{value},  '255',     'int default: decimal');
  is($t->[0]{value}[0]{format}, 'decimal', 'int default: format=decimal');
  is($t->[0]{value}[1]{value},  'hi',      'bin default: raw bytes');
  is($t->[0]{value}[1]{format}, 'bytes',   'bin default: format=bytes');

  $t = asn1_decode_der($der, { int => 'hex' });
  is($t->[0]{value}[0]{value},  'ff',  'int hex');
  is($t->[0]{value}[0]{format}, 'hex', 'int hex: format=hex');

  $t = asn1_decode_der($der, { int => 'bytes' });
  is(unpack('H*', $t->[0]{value}[0]{value}), 'ff', 'int bytes');

  $t = asn1_decode_der(pack("H*", "020100"), { int => 'bytes' });
  is(unpack('H*', $t->[0]{value}), '00', 'int bytes zero stays explicit');
  is(unpack('H*', asn1_encode_der($t)), '020100', 'int bytes zero round-trips');

  eval { asn1_decode_der(pack("H*", "020180"), { int => 'bytes' }) };
  like($@, qr/negative INTEGER cannot be represented with int=>'bytes'/, 'int bytes rejects negative INTEGER');

  $t = asn1_decode_der($der, { bin => 'hex' });
  is($t->[0]{value}[1]{value}, '6869', 'bin hex');

  $t = asn1_decode_der($der, { bin => 'base64' });
  is($t->[0]{value}[1]{value}, 'aGk=', 'bin base64');

  # dt=>epoch on real cert (two UTCTIME nodes: notBefore, notAfter)
  sub find_times { my $n=shift; map { $_ -> {type} =~ /TIME/ ? ($_) : (ref $_->{value} eq 'ARRAY' ? find_times($_->{value}) : ()) } @$n }
  my @times = find_times(asn1_decode_pem_file('t/data/openssl_rsa-x509.pem', { dt => 'epoch' }));
  ok($times[0]{value} =~ /^\d+$/, 'dt epoch: is integer');
  ok($times[0]{value} > 0,        'dt epoch: positive');
  ok($times[1]{value} > $times[0]{value}, 'dt epoch: notAfter > notBefore');
}

{ ### GENERALIZEDTIME with fractional seconds
  # GeneralizedTime encoding: tag 0x18, then length, then "YYYYMMDDhhmmss.fsZ"
  my $gt_str = "20240115103000.125Z";
  my $der = pack("CC", 0x18, length($gt_str)) . $gt_str;
  my $tree = asn1_decode_der($der);
  is($tree->[0]{type}, 'GENERALIZEDTIME', 'GENERALIZEDTIME type');
  is($tree->[0]{value}, '2024-01-15T10:30:00.125Z', 'GENERALIZEDTIME with fractional seconds');

  # without fractional seconds
  my $gt_str2 = "20240115103000Z";
  my $der2 = pack("CC", 0x18, length($gt_str2)) . $gt_str2;
  my $tree2 = asn1_decode_der($der2);
  is($tree2->[0]{value}, '2024-01-15T10:30:00Z', 'GENERALIZEDTIME without fractional seconds');

  # with fractional seconds and timezone offset
  my $gt_str3 = "20240115103000.5+0530";
  my $der3 = pack("CC", 0x18, length($gt_str3)) . $gt_str3;
  my $tree3 = asn1_decode_der($der3);
  is($tree3->[0]{value}, '2024-01-15T10:30:00.5+05:30', 'GENERALIZEDTIME with fs and tz offset');

  # epoch mode should still work (ignores sub-second)
  my $tree4 = asn1_decode_der($der, { dt => 'epoch' });
  ok($tree4->[0]{value} =~ /^\d+$/, 'GENERALIZEDTIME epoch: is integer');
  ok($tree4->[0]{value} > 0,        'GENERALIZEDTIME epoch: positive');
}

{ ### asn1_decode_pem_file
  my $tree = asn1_decode_pem_file("t/data/openssl_ec1.key.pem");
  is($tree->[0]{type}, 'SEQUENCE',  'asn1_decode_pem_file: outer SEQUENCE');
  is($tree->[0]{value}[0]{value}, '1', 'asn1_decode_pem_file: version = 1');
}

{ ### asn1_decode_der_file
  my $tree = asn1_decode_der_file("t/data/openssl_rsa-x509.der");
  is($tree->[0]{type}, 'SEQUENCE',  'asn1_decode_der_file: outer SEQUENCE');
  is($tree->[0]{value}[0]{type},  'SEQUENCE', 'asn1_decode_der_file: tbsCertificate');
}

### ===== ENCODER TESTS =====

{ ### round-trip: hand-built SEQUENCE with all basic types
  my $der = tlv(0x30,
                tlv(0x02, pack("C", 42))            # INTEGER 42
              . tlv(0x0C, "Hi")                      # UTF8String
              . tlv(0x06, pack("CC", 0x2a, 0x03))    # OID 1.2.3
              . tlv(0x04, "bytes")                   # OCTET_STRING
              . tlv(0x05, "")                        # NULL
              . tlv(0x01, pack("C", 0xFF))           # BOOLEAN true
              . tlv(0x13, "abc")                     # PrintableString
              . tlv(0x16, "ia5")                     # IA5String
  );
  my $tree = asn1_decode_der($der);
  my $enc  = asn1_encode_der($tree);
  is($enc, $der, 'round-trip: basic SEQUENCE');
}

{ ### round-trip: real EC key via PEM

  my $pem_data = read_rawfile("t/data/openssl_ec1.key.pem");
  my $orig_der = pem_to_der($pem_data);
  my $tree     = asn1_decode_der($orig_der);
  my $enc      = asn1_encode_der($tree);
  is($enc, $orig_der, 'round-trip: EC private key');
}

{ ### round-trip: real X.509 certificate (DER)

  my $orig = read_rawfile("t/data/openssl_rsa-x509.der");
  my $tree = asn1_decode_der($orig);
  my $enc  = asn1_encode_der($tree);
  is($enc, $orig, 'round-trip: X.509 certificate');
}

{ ### round-trip with non-default decode options

  my $orig = read_rawfile("t/data/openssl_rsa-x509.der");

  my $t1 = asn1_decode_der($orig, { int => 'hex', bin => 'base64', dt => 'epoch' });
  is(asn1_encode_der($t1), $orig, 'round-trip: hex/base64/epoch options');

  my $t2 = asn1_decode_der($orig, { int => 'bytes', bin => 'hex' });
  is(asn1_encode_der($t2), $orig, 'round-trip: bytes/hex options');
}

{ ### encode from scratch: all types
  # INTEGER
  my $der = asn1_encode_der([{ type => 'INTEGER', value => '42' }]);
  is(unpack("H*", $der), '02012a', 'encode: INTEGER 42');

  # INTEGER 0
  $der = asn1_encode_der([{ type => 'INTEGER', value => '0' }]);
  is(unpack("H*", $der), '020100', 'encode: INTEGER 0');

  # Negative INTEGER
  $der = asn1_encode_der([{ type => 'INTEGER', value => '-128' }]);
  is(unpack("H*", $der), '020180', 'encode: INTEGER -128');

  # Large INTEGER
  $der = asn1_encode_der([{ type => 'INTEGER', value => '255' }]);
  is(unpack("H*", $der), '020200ff', 'encode: INTEGER 255');

  # BOOLEAN true
  $der = asn1_encode_der([{ type => 'BOOLEAN', value => 1 }]);
  is(unpack("H*", $der), '0101ff', 'encode: BOOLEAN true');

  # BOOLEAN false
  $der = asn1_encode_der([{ type => 'BOOLEAN', value => 0 }]);
  is(unpack("H*", $der), '010100', 'encode: BOOLEAN false');

  # NULL
  $der = asn1_encode_der([{ type => 'NULL' }]);
  is(unpack("H*", $der), '0500', 'encode: NULL');

  # OID
  $der = asn1_encode_der([{ type => 'OID', value => '1.2.3' }]);
  is(unpack("H*", $der), '06022a03', 'encode: OID 1.2.3');

  $der = asn1_encode_der([{ type => 'OID', value => '2.000.1' }]);
  is(asn1_decode_der($der)->[0]{value}, '2.0.1', 'encode: OID leading-zero arcs canonicalize');

  # OCTET_STRING
  $der = asn1_encode_der([{ type => 'OCTET_STRING', value => "hi" }]);
  is(unpack("H*", $der), '04026869', 'encode: OCTET_STRING');

  # UTF8_STRING
  $der = asn1_encode_der([{ type => 'UTF8_STRING', value => "AB" }]);
  is(unpack("H*", $der), '0c024142', 'encode: UTF8_STRING');

  # IA5_STRING
  $der = asn1_encode_der([{ type => 'IA5_STRING', value => "xy" }]);
  is(unpack("H*", $der), '16027879', 'encode: IA5_STRING');

  # PRINTABLE_STRING
  $der = asn1_encode_der([{ type => 'PRINTABLE_STRING', value => "ab" }]);
  is(unpack("H*", $der), '13026162', 'encode: PRINTABLE_STRING');

  # TELETEX_STRING
  $der = asn1_encode_der([{ type => 'TELETEX_STRING', value => "tx" }]);
  is(unpack("H*", $der), '14027478', 'encode: TELETEX_STRING');
}

{ ### encode: BIT_STRING
  # 8 bits, no unused
  my $der = asn1_encode_der([{ type => 'BIT_STRING', value => "\xff", bits => 8 }]);
  is(unpack("H*", $der), '030200ff', 'encode: BIT_STRING 8 bits');

  # 1 bit (7 unused)
  $der = asn1_encode_der([{ type => 'BIT_STRING', value => "\x80", bits => 1 }]);
  is(unpack("H*", $der), '03020780', 'encode: BIT_STRING 1 bit');

  # default bits from value length
  $der = asn1_encode_der([{ type => 'BIT_STRING', value => "\xAB\xCD" }]);
  is(unpack("H*", $der), '030300abcd', 'encode: BIT_STRING default 16 bits');

  eval { asn1_encode_der([{ type => 'BIT_STRING', value => "\xff", bits => 20 }]) };
  like($@, qr/BIT_STRING bits exceeds available data/, 'encode: BIT_STRING rejects bits larger than value');

  eval { asn1_encode_der([{ type => 'BIT_STRING', value => "\xff", bits => -1 }]) };
  like($@, qr/BIT_STRING bits must be a non-negative integer/, 'encode: BIT_STRING rejects negative bits');

  eval { asn1_encode_der([{ type => 'BIT_STRING', value => "\xff", bits => '1.5' }]) };
  like($@, qr/BIT_STRING bits must be a non-negative integer/, 'encode: BIT_STRING rejects non-integer bits');
}

{ ### encode: UTCTIME
  my $der = asn1_encode_der([{ type => 'UTCTIME', value => '2024-01-15T10:30:00Z' }]);
  my $t = asn1_decode_der($der)->[0];
  is($t->{type}, 'UTCTIME', 'encode UTCTIME: type');
  is($t->{value}, '2024-01-15T10:30:00Z', 'encode UTCTIME: round-trip value');

  # epoch input
  $der = asn1_encode_der([{ type => 'UTCTIME', value => 1705311000, format => 'epoch' }]);
  $t = asn1_decode_der($der)->[0];
  is($t->{type}, 'UTCTIME', 'encode UTCTIME from epoch: type');
  like($t->{value}, qr/^20\d{2}-/, 'encode UTCTIME from epoch: RFC 3339');

  # boundary year is still accepted
  $der = asn1_encode_der([{ type => 'UTCTIME', value => '2049-12-31T23:59:59Z' }]);
  $t = asn1_decode_der($der)->[0];
  is($t->{value}, '2049-12-31T23:59:59Z', 'encode UTCTIME upper boundary');

  eval { asn1_encode_der([{ type => 'UTCTIME', value => '2050-01-01T00:00:00Z' }]) };
  like($@, qr/UTCTIME year out of range/, 'encode UTCTIME rejects RFC3339 year above 2049');

  eval { asn1_encode_der([{ type => 'UTCTIME', value => '1949-12-31T23:59:59Z' }]) };
  like($@, qr/UTCTIME year out of range/, 'encode UTCTIME rejects RFC3339 year below 1950');

  SKIP: {
    require Config;
    skip 'requires 64-bit Perl integers', 1 if ($Config::Config{ivsize} || 0) < 8;

    eval { asn1_encode_der([{ type => 'UTCTIME', format => 'epoch', value => 2524608000 }]) };
    like($@, qr/UTCTIME year out of range/, 'encode UTCTIME rejects epoch above 2049');
  }

  eval { asn1_encode_der([{ type => 'UTCTIME', value => 'junk' }]) };
  like($@, qr/invalid UTCTIME value/, 'encode UTCTIME rejects arbitrary raw string');

  eval { asn1_encode_der([{ type => 'UTCTIME', value => '500101000000Z' }]) };
  like($@, qr/invalid UTCTIME value/, 'encode UTCTIME rejects undocumented wire-format string');

  eval { asn1_encode_der([{ type => 'UTCTIME', value => '2024-01-15T10:30:00.5Z' }]) };
  like($@, qr/UTCTIME does not allow fractional seconds/, 'encode UTCTIME rejects fractional seconds');
}

{ ### encode: GENERALIZEDTIME with fractional seconds
  my $der = asn1_encode_der([{ type => 'GENERALIZEDTIME', value => '2024-01-15T10:30:00.125Z' }]);
  my $t = asn1_decode_der($der)->[0];
  is($t->{type}, 'GENERALIZEDTIME', 'encode GENERALIZEDTIME: type');
  is($t->{value}, '2024-01-15T10:30:00.125Z', 'encode GENERALIZEDTIME: round-trip with fs');

  eval { asn1_encode_der([{ type => 'GENERALIZEDTIME', value => 'junk' }]) };
  like($@, qr/invalid GENERALIZEDTIME value/, 'encode GENERALIZEDTIME rejects arbitrary raw string');

  eval { asn1_encode_der([{ type => 'GENERALIZEDTIME', value => '20240115103000Z' }]) };
  like($@, qr/invalid GENERALIZEDTIME value/, 'encode GENERALIZEDTIME rejects undocumented wire-format string');
}

{ ### encode: SEQUENCE and SET
  my $der = asn1_encode_der([{
    type  => 'SEQUENCE',
    value => [
      { type => 'INTEGER', value => '1' },
      { type => 'SET', value => [
        { type => 'BOOLEAN', value => 0 },
      ]},
    ],
  }]);
  my $t = asn1_decode_der($der);
  is($t->[0]{type}, 'SEQUENCE', 'encode SEQUENCE: type');
  is($t->[0]{value}[0]{value}, '1', 'encode SEQUENCE: child INTEGER');
  is($t->[0]{value}[1]{type}, 'SET', 'encode SEQUENCE: child SET');
  is($t->[0]{value}[1]{value}[0]{value}, 0, 'encode SET: child BOOLEAN');
}

{ ### encode: CUSTOM types
  # Constructed context-specific [0]
  my $der = asn1_encode_der([{
    type => 'CUSTOM', class => 'CONTEXT_SPECIFIC',
    constructed => 1, tag => 0,
    value => [{ type => 'INTEGER', value => '2' }],
  }]);
  my $t = asn1_decode_der($der)->[0];
  is($t->{type}, 'CUSTOM', 'encode CUSTOM constructed: type');
  is($t->{class}, 'CONTEXT_SPECIFIC', 'encode CUSTOM constructed: class');
  is($t->{tag}, 0, 'encode CUSTOM constructed: tag');
  is($t->{constructed}, 1, 'encode CUSTOM constructed: flag');
  is($t->{value}[0]{value}, '2', 'encode CUSTOM constructed: child');

  # Primitive context-specific [1]
  $der = asn1_encode_der([{
    type => 'CUSTOM', class => 'CONTEXT_SPECIFIC',
    constructed => 0, tag => 1,
    value => "\xAA\xBB",
  }]);
  is(unpack("H*", $der), '8102aabb', 'encode CUSTOM primitive');

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'application', constructed => 0, tag => 1, value => "\xAA" }]) };
  like($@, qr/invalid CUSTOM class/, 'encode CUSTOM rejects wrong-case class');

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'bogus', constructed => 0, tag => 1, value => "\xAA" }]) };
  like($@, qr/invalid CUSTOM class/, 'encode CUSTOM rejects unknown class');

  my $err;

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 0, tag => '1.5', value => "\xAA" }]) };
  $err = $@;
  like($err, qr/CUSTOM tag must be a non-negative integer/, 'encode CUSTOM rejects fractional tag');

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 0, tag => 'abc', value => "\xAA" }]) };
  $err = $@;
  like($err, qr/CUSTOM tag must be a non-negative integer/, 'encode CUSTOM rejects non-numeric tag');

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 0, tag => -1, value => "\xAA" }]) };
  $err = $@;
  like($err, qr/CUSTOM tag must be a non-negative integer/, 'encode CUSTOM rejects negative tag');

  {
    my $overflow = do {
      require Config;
      if (($Config::Config{longsize} || 0) == 4) {
        '4294967296';
      }
      elsif (($Config::Config{longsize} || 0) == 8) {
        '18446744073709551616';
      }
      else {
        require Math::BigInt;
        Math::BigInt->new(2)->bpow(($Config::Config{longsize} || 0) * 8)->bstr();
      }
    };
    eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 0, tag => $overflow, value => "\xAA" }]) };
    $err = $@;
    like($err, qr/CUSTOM tag '.*' is too large/, 'encode CUSTOM rejects overflowing tag');
  }

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 1, tag => 0, value => "\xAA" }]) };
  $err = $@;
  like($err, qr/CUSTOM constructed value must be arrayref/, 'encode CUSTOM rejects scalar value for constructed tag');

  eval { asn1_encode_der([{ type => 'CUSTOM', class => 'CONTEXT_SPECIFIC', constructed => 0, tag => 1, value => [] }]) };
  $err = $@;
  like($err, qr/CUSTOM primitive value must not be a reference/, 'encode CUSTOM rejects reference value for primitive tag');
}

{ ### encode: PEM output
  my $pem = asn1_encode_pem([{
    type  => 'SEQUENCE',
    value => [{ type => 'INTEGER', value => '42' }],
  }], 'TEST');
  like($pem, qr/-----BEGIN TEST-----/, 'encode PEM: header');
  like($pem, qr/-----END TEST-----/,   'encode PEM: footer');
  # decode PEM back
  my $tree = asn1_decode_pem($pem);
  is($tree->[0]{value}[0]{value}, '42', 'encode PEM: round-trip');
}

### ===== DUMP TESTS =====

{ ### asn1_to_string: all basic types
  my $tree = [{
    type  => 'SEQUENCE',
    format => 'array',
    value => [
      { type => 'INTEGER',          format => 'decimal', value => '42' },
      { type => 'BOOLEAN',          format => 'bool',    value => 1 },
      { type => 'BOOLEAN',          format => 'bool',    value => 0 },
      { type => 'NULL',             format => 'null',    value => undef },
      { type => 'OID',              format => 'oid',     value => '1.2.3' },
      { type => 'OCTET_STRING',     format => 'bytes',   value => "\xAB\xCD" },
      { type => 'BIT_STRING',       format => 'bytes',   value => "\x80", bits => 1 },
      { type => 'UTF8_STRING',      format => 'utf8',    value => 'hello' },
      { type => 'PRINTABLE_STRING', format => 'string',  value => 'abc' },
      { type => 'IA5_STRING',       format => 'string',  value => 'ia5' },
      { type => 'TELETEX_STRING',   format => 'string',  value => 'tx' },
      { type => 'UTCTIME',          format => 'rfc3339', value => '2024-01-15T10:30:00Z' },
      { type => 'GENERALIZEDTIME',  format => 'rfc3339', value => '2024-01-15T10:30:00.5Z' },
    ],
  }];
  my $out = asn1_to_string($tree);
  like($out, qr/^SEQUENCE \(13 elem\)/,      'dump: SEQUENCE header');
  like($out, qr/INTEGER:42/,                  'dump: INTEGER');
  like($out, qr/BOOLEAN:TRUE/,                'dump: BOOLEAN true');
  like($out, qr/BOOLEAN:FALSE/,               'dump: BOOLEAN false');
  like($out, qr/NULL:/,                        'dump: NULL');
  like($out, qr/OBJECT:1\.2\.3/,              'dump: OID');
  like($out, qr/OCTET STRING:abcd/,           'dump: OCTET_STRING hex');
  like($out, qr/BIT STRING:80 \(1 bit\)/i,    'dump: BIT_STRING with bits');
  like($out, qr/UTF8STRING:hello/,            'dump: UTF8_STRING');
  like($out, qr/UTCTIME:2024-01-15/,          'dump: UTCTIME');
  like($out, qr/GENERALIZEDTIME:.*\.5Z/,      'dump: GENERALIZEDTIME fs');
}

{ ### asn1_to_string: CUSTOM and OID name
  my $tree = [{
    type => 'CUSTOM', format => 'array',
    class => 'CONTEXT_SPECIFIC', constructed => 1, tag => 0,
    value => [{ type => 'INTEGER', format => 'decimal', value => '2' }],
  }];
  my $out = asn1_to_string($tree);
  like($out, qr/context_specific \[0\] cons/, 'dump: CUSTOM constructed');
  like($out, qr/INTEGER:2/,                   'dump: CUSTOM child');
}

{ ### asn1_to_string: works with non-default decode options

  my $der = read_rawfile("t/data/openssl_rsa-x509.der");
  my $tree = asn1_decode_der($der, { int => 'hex', bin => 'base64', dt => 'epoch' });
  my $out = asn1_to_string($tree);
  like($out, qr/^SEQUENCE/,                   'dump: hex/base64/epoch - starts with SEQUENCE');
}

{ ### asn1_to_string: OID with name
  my $tree = [{
    type => 'OID', format => 'oid', value => '1.2.840.113549.1.1.11',
    name => 'sha256WithRSAEncryption',
  }];
  my $out = asn1_to_string($tree);
  like($out, qr/OBJECT:1\.2\.840.*\(sha256WithRSAEncryption\)/, 'dump: OID with name');
}

{ ### encoder accepts explicit format on manually-built nodes
  # hex OCTET_STRING
  my $der = asn1_encode_der([{ type => 'OCTET_STRING', format => 'hex', value => '0401' }]);
  is($der, "\x04\x02\x04\x01", 'encode: OCTET_STRING with format=>hex');

  # hex INTEGER
  $der = asn1_encode_der([{ type => 'INTEGER', format => 'hex', value => 'ff' }]);
  is(unpack("H*", $der), '020200ff', 'encode: INTEGER with format=>hex');

  # negative hex INTEGER
  $der = asn1_encode_der([{ type => 'INTEGER', format => 'hex', value => '-5' }]);
  my $t = asn1_decode_der($der)->[0];
  is($t->{value}, '-5', 'encode: negative hex INTEGER round-trip');

  # base64 OCTET_STRING
  $der = asn1_encode_der([{ type => 'OCTET_STRING', format => 'base64', value => 'aGk=' }]);
  is($der, "\x04\x02hi", 'encode: OCTET_STRING with format=>base64');

  # epoch UTCTIME
  $der = asn1_encode_der([{ type => 'UTCTIME', format => 'epoch', value => 1705314600 }]);
  $t = asn1_decode_der($der)->[0];
  is($t->{type}, 'UTCTIME', 'encode: UTCTIME with format=>epoch');
}

{ ### encoder does not mutate input tree
  my $tree = [{ type => 'INTEGER', format => 'hex', value => '-FF' }];
  asn1_encode_der($tree);
  is($tree->[0]{value}, '-FF', 'encode: input not mutated');
}

{ ### encoder rejects malformed OID / hex / base64 input
  my $err;

  eval { asn1_encode_der([{ type => 'OID', value => 'abc' }]) };
  $err = $@;
  like($err, qr/invalid OID value/, 'encode: rejects non-numeric OID');

  eval { asn1_encode_der([{ type => 'OID', value => '1..2' }]) };
  $err = $@;
  like($err, qr/invalid OID value/, 'encode: rejects OID with empty arc');

  eval { asn1_encode_der([{ type => 'OID', value => '2.999999999999999999999999999999.1' }]) };
  $err = $@;
  like($err, qr/OID arc .* too large/, 'encode: rejects huge overflowing OID arc');

  {
    my $overflow = do {
      require Config;
      if (($Config::Config{longsize} || 0) == 4) {
        '4294967216';
      }
      elsif (($Config::Config{longsize} || 0) == 8) {
        '18446744073709551536';
      }
      else {
        require Math::BigInt;
        Math::BigInt->new(2)->bpow(($Config::Config{longsize} || 0) * 8)->bsub(80)->badd(1)->bstr();
      }
    };
    eval { asn1_encode_der([{ type => 'OID', value => "2.$overflow.1" }]) };
    $err = $@;
    like($err, qr/OID arc .* too large/, 'encode: rejects overflowing second arc for first arc 2');
  }

  eval { asn1_encode_der([{ type => 'OCTET_STRING', format => 'hex', value => 'zz' }]) };
  $err = $@;
  like($err, qr/invalid hex value/, 'encode: rejects invalid hex');

  eval { asn1_encode_der([{ type => 'OCTET_STRING', format => 'hex', value => 'abc' }]) };
  $err = $@;
  like($err, qr/invalid hex value/, 'encode: rejects odd-length hex');

  eval { asn1_encode_der([{ type => 'OCTET_STRING', format => 'base64', value => '!!!' }]) };
  $err = $@;
  like($err, qr/invalid base64 value/, 'encode: rejects invalid base64');

  eval { asn1_encode_der([{ type => 'OCTET_STRING', format => 'base64', value => 'aGk' }]) };
  $err = $@;
  like($err, qr/invalid base64 value/, 'encode: rejects unpadded base64');
}

{ ### asn1_encode_der_file / asn1_encode_pem_file
  my $tree = [{ type => 'SEQUENCE', value => [{ type => 'INTEGER', value => '99' }] }];
  my $tmpder = "t/tmp_asn1_test.$$.der";
  my $tmppem = "t/tmp_asn1_test.$$.pem";

  my $der = asn1_encode_der_file($tree, $tmpder);
  ok(-f $tmpder, 'encode_der_file: file created');
  my $rt = asn1_decode_der_file($tmpder);
  is($rt->[0]{value}[0]{value}, '99', 'encode_der_file: round-trip');

  my $pem = asn1_encode_pem_file($tree, 'TEST', $tmppem);
  ok(-f $tmppem, 'encode_pem_file: file created');
  like($pem, qr/-----BEGIN TEST-----/, 'encode_pem_file: PEM header');

  unlink $tmpder, $tmppem;
}
