use strict;
use warnings;

use Test::More tests => 44;
use Crypt::ASN1 qw(asn1_decode_der asn1_decode_pem asn1_decode_der_file asn1_decode_pem_file);

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

{ ### multiple top-level elements
  my $der = tlv(0x02, pack("C", 1)) . tlv(0x02, pack("C", 2));
  my $tree = asn1_decode_der($der);
  is(scalar @$tree, 2,   '2 top-level elements');
  is($tree->[0]{value}, '1', 'first INTEGER');
  is($tree->[1]{value}, '2', 'second INTEGER');
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
  is($t->[0]{value}[0]{value},  'FF',  'int hex');
  is($t->[0]{value}[0]{format}, 'hex', 'int hex: format=hex');

  $t = asn1_decode_der($der, { int => 'bytes' });
  is(unpack('H*', $t->[0]{value}[0]{value}), 'ff', 'int bytes');

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
