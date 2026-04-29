use strict;
use warnings;

use Test::More;
use File::Basename qw(basename);

my $TV_DIR = 't/wycheproof-repo/testvectors_v1';

plan skip_all => 'set AUTHOR_MODE=2 to run Project Wycheproof tests' unless $ENV{AUTHOR_MODE} && $ENV{AUTHOR_MODE} == 2;
plan skip_all => "Project Wycheproof checkout not found at $TV_DIR" unless -d $TV_DIR;
plan skip_all => 'JSON::PP module not installed' unless eval { require JSON::PP; JSON::PP->import(); 1 };

for my $module (
  qw(
    CryptX
    Crypt::AuthEnc::CCM
    Crypt::AuthEnc::ChaCha20Poly1305
    Crypt::AuthEnc::EAX
    Crypt::AuthEnc::GCM
    Crypt::AuthEnc::SIV
    Crypt::AuthEnc::XChaCha20Poly1305
    Crypt::Cipher
    Crypt::Digest
    Crypt::KeyDerivation
    Crypt::Mac::HMAC
    Crypt::Mac::OMAC
    Crypt::Mode::CBC
    Crypt::PK::DSA
    Crypt::PK::ECC
    Crypt::PK::Ed25519
    Crypt::PK::Ed448
    Crypt::PK::RSA
    Crypt::PK::X25519
    Crypt::PK::X448
  )
) {
  plan skip_all => "$module module not available" unless eval "require $module; 1";
}

my %STATS = (
  files_total       => 0,
  files_tested      => 0,
  files_unsupported => 0,
  tc_total          => 0,
  tc_run            => 0,
  tc_unsupported    => 0,
);
my %UNSUPPORTED;
my %HASH_OK;
my %CIPHER_OK;

my $SECP256K1_ORDER      = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
my $SECP256K1_HALF_ORDER = '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0';

my %HANDLER = (
  aead_test_schema_v1_json                         => \&handle_aead,
  daead_test_schema_v1_json                        => \&handle_daead,
  dsa_p1363_verify_schema_v1_json                  => \&handle_dsa_verify,
  dsa_verify_schema_v1_json                        => \&handle_dsa_verify,
  ec_curve_test_schema_json                        => \&handle_ec_curve_test,
  ecdsa_bitcoin_verify_schema_json                 => \&handle_ecdsa_bitcoin_verify,
  ecdsa_p1363_verify_schema_v1_json                => \&handle_ecdsa_verify,
  ecdsa_verify_schema_v1_json                      => \&handle_ecdsa_verify,
  eddsa_verify_schema_v1_json                      => \&handle_eddsa_verify,
  ecdh_ecpoint_test_schema_v1_json                 => \&handle_ecdh,
  ecdh_pem_test_schema_v1_json                     => \&handle_ecdh,
  ecdh_test_schema_v1_json                         => \&handle_ecdh,
  ecdh_webcrypto_test_schema_v1_json               => \&handle_ecdh,
  hkdf_test_schema_v1_json                         => \&handle_hkdf,
  ind_cpa_test_schema_v1_json                      => \&handle_ind_cpa,
  mac_test_schema_v1_json                          => \&handle_mac,
  mac_with_iv_test_schema_v1_json                  => \&handle_mac_with_iv,
  pbe_test_schema_json                             => \&handle_pbe,
  pbkdf_test_schema_json                           => \&handle_pbkdf,
  rsaes_oaep_decrypt_schema_v1_json                => \&handle_rsa_oaep_decrypt,
  rsaes_pkcs1_decrypt_schema_v1_json               => \&handle_rsa_pkcs1_decrypt,
  rsassa_pkcs1_generate_schema_v1_json             => \&handle_rsa_pkcs1_generate,
  rsassa_pkcs1_verify_schema_v1_json               => \&handle_rsa_pkcs1_verify,
  rsassa_pss_verify_schema_v1_json                 => \&handle_rsa_pss_verify,
  rsassa_pss_with_parameters_verify_schema_json    => \&handle_rsa_pss_verify,
  xdh_asn_comp_schema_v1_json                      => \&handle_xdh,
  xdh_comp_schema_v1_json                          => \&handle_xdh,
  xdh_jwk_comp_schema_v1_json                      => \&handle_xdh,
  xdh_pem_comp_schema_v1_json                      => \&handle_xdh,
);

my @files = sort glob("$TV_DIR/*_test.json");
if (defined $ENV{CRYPTX_WYCHEPROOF_FILE} && length $ENV{CRYPTX_WYCHEPROOF_FILE}) {
  my $re = $ENV{CRYPTX_WYCHEPROOF_FILE};
  @files = grep { basename($_) =~ /$re/ } @files;
}

plan skip_all => "no Wycheproof JSON files found in $TV_DIR" unless @files;

for my $path (@files) {
  my $file = basename($path);
  my $doc = eval { JSON::PP->new->decode(read_file($path)) };
  if (!$doc) {
    fail("$file JSON decode");
    diag($@) if $@;
    next;
  }

  $STATS{files_total}++;
  $STATS{tc_total} += doc_test_count($doc);

  my $schema = schema_key($doc->{schema});
  my $handler = $HANDLER{$schema};
  if (!$handler) {
    unsupported_file($file, $doc, "unsupported schema " . ($doc->{schema} || '(none)'));
    next;
  }

  my $before = $STATS{tc_run};
  eval { $handler->($file, $doc); 1 } or do {
    fail("$file fatal adapter error");
    diag($@);
  };
  $STATS{files_tested}++ if $STATS{tc_run} > $before;
}

diag sprintf(
  'wycheproof2 summary: files total=%d tested=%d unsupported=%d; testcases total=%d run=%d unsupported=%d',
  @STATS{qw(files_total files_tested files_unsupported tc_total tc_run tc_unsupported)}
);
for my $reason (sort keys %UNSUPPORTED) {
  diag sprintf('wycheproof2 unsupported: %6d  %s', $UNSUPPORTED{$reason}, $reason);
}

done_testing;

sub read_file {
  my ($path) = @_;
  open my $fh, '<', $path or die "cannot open $path: $!";
  binmode $fh;
  local $/;
  return <$fh>;
}

sub schema_key {
  my ($schema) = @_;
  $schema = '' unless defined $schema;
  $schema =~ s/[^A-Za-z0-9]+/_/g;
  $schema =~ s/^_+//;
  $schema =~ s/_+$//;
  return $schema;
}

sub doc_test_count {
  my ($doc) = @_;
  return $doc->{numberOfTests} if defined $doc->{numberOfTests};
  my $n = 0;
  for my $g (@{ $doc->{testGroups} || [] }) {
    $n += scalar @{ $g->{tests} || [] };
  }
  return $n;
}

sub unsupported_file {
  my ($file, $doc, $reason) = @_;
  my $n = doc_test_count($doc);
  $STATS{files_unsupported}++;
  $STATS{tc_unsupported} += $n;
  $UNSUPPORTED{$reason} += $n;
  return;
}

sub unsupported_group {
  my ($file, $doc, $group, $reason) = @_;
  my $n = scalar @{ $group->{tests} || [] };
  $STATS{tc_unsupported} += $n;
  $UNSUPPORTED{$reason} += $n;
  return;
}

sub mark_tc {
  $STATS{tc_run}++;
}

sub name_for {
  my ($file, $doc, $group, $test, $op) = @_;
  my $name = "$file tcId=" . (defined $test->{tcId} ? $test->{tcId} : '?');
  $name .= " alg=" . $doc->{algorithm} if defined $doc->{algorithm};
  $name .= " type=" . $group->{type} if defined $group->{type};
  $name .= " result=" . $test->{result} if defined $test->{result};
  $name .= " $op" if defined $op && length $op;
  return $name;
}

sub hex_to_bin {
  my ($hex) = @_;
  $hex = '' unless defined $hex;
  return pack 'H*', $hex;
}

sub bin_to_hex {
  my ($bin) = @_;
  return undef unless defined $bin;
  return lc unpack('H*', $bin);
}

sub lc_hex {
  my ($hex) = @_;
  return undef unless defined $hex;
  return lc $hex;
}

sub norm_unsigned_hex {
  my ($hex) = @_;
  return undef unless defined $hex;
  $hex = lc $hex;
  $hex =~ s/^0+//;
  return length($hex) ? $hex : '0';
}

sub hex_cmp_unsigned {
  my ($left, $right) = @_;
  $left  = norm_unsigned_hex($left);
  $right = norm_unsigned_hex($right);
  return length($left) <=> length($right) || $left cmp $right;
}

sub eval_scalar {
  my ($code) = @_;
  my ($value, $err);
  my $ok = eval { $value = $code->(); 1 };
  $err = $@ unless $ok;
  return ($ok ? 1 : 0, $value, $err);
}

sub eval_list {
  my ($code) = @_;
  my (@value, $err);
  my $ok = eval { @value = $code->(); 1 };
  $err = $@ unless $ok;
  return ($ok ? 1 : 0, \@value, $err);
}

sub norm_hash {
  my ($hash) = @_;
  return undef unless defined $hash;
  $hash =~ s/^\s+//;
  $hash =~ s/\s+$//;
  $hash =~ s/^HMAC//i;
  return 'SHA512_224' if $hash =~ /^SHA-?512\/224$/i;
  return 'SHA512_256' if $hash =~ /^SHA-?512\/256$/i;
  return 'SHA3_224'   if $hash =~ /^SHA3-?224$/i;
  return 'SHA3_256'   if $hash =~ /^SHA3-?256$/i;
  return 'SHA3_384'   if $hash =~ /^SHA3-?384$/i;
  return 'SHA3_512'   if $hash =~ /^SHA3-?512$/i;
  return 'SHA1'       if $hash =~ /^SHA-?1$/i;
  return 'SHA224'     if $hash =~ /^SHA-?224$/i;
  return 'SHA256'     if $hash =~ /^SHA-?256$/i;
  return 'SHA384'     if $hash =~ /^SHA-?384$/i;
  return 'SHA512'     if $hash =~ /^SHA-?512$/i;
  return undef;
}

sub hash_supported {
  my ($hash) = @_;
  return 0 unless defined $hash;
  return $HASH_OK{$hash} if exists $HASH_OK{$hash};
  my $ok = eval { Crypt::Digest::digest_data($hash, ''); 1 } ? 1 : 0;
  $HASH_OK{$hash} = $ok;
  return $ok;
}

sub norm_cipher {
  my ($cipher) = @_;
  return undef unless defined $cipher;
  $cipher = uc $cipher;
  $cipher =~ s/[-_]//g;
  return 'AES'      if $cipher eq 'AES';
  return 'Camellia' if $cipher eq 'CAMELLIA';
  return 'SEED'     if $cipher eq 'SEED';
  return 'SM4'      if $cipher eq 'SM4';
  return undef;
}

sub cipher_supported {
  my ($cipher) = @_;
  return 0 unless defined $cipher;
  return $CIPHER_OK{$cipher} if exists $CIPHER_OK{$cipher};
  my $ok = eval { Crypt::Cipher::blocksize($cipher); 1 } ? 1 : 0;
  $CIPHER_OK{$cipher} = $ok;
  return $ok;
}

sub curve_supported {
  my ($curve) = @_;
  return undef unless defined $curve;
  return undef if $curve =~ /^sect/i;
  return 'secp256r1' if $curve eq 'P-256';
  return 'secp384r1' if $curve eq 'P-384';
  return 'secp521r1' if $curve eq 'P-521';
  return 'secp256k1' if $curve eq 'P-256K';
  $curve =~ s/brainpoolP/brainpoolp/;
  return $curve;
}

sub curve_field_bytes {
  my ($curve) = @_;
  return undef unless defined $curve;
  return 32 if $curve eq 'secp256k1';
  return int(($1 + 7) / 8) if $curve =~ /(\d+)/;
  return undef;
}

sub ec_bigint_to_scalar {
  my ($hex, $curve) = @_;
  $hex = '' unless defined $hex;
  $hex = lc $hex;
  $hex =~ s/^0+//;
  $hex = '0' if $hex eq '';
  $hex = "0$hex" if length($hex) % 2;

  my $bytes = curve_field_bytes($curve);
  if ($bytes && length($hex) <= 2 * $bytes) {
    $hex = ('0' x (2 * $bytes - length($hex))) . $hex;
  }
  return hex_to_bin($hex);
}

sub der_len {
  my ($len) = @_;
  return pack('C', $len) if $len < 128;
  my $bytes = '';
  while ($len) {
    $bytes = pack('C', $len & 0xff) . $bytes;
    $len = int($len / 256);
  }
  return pack('C', 0x80 | length($bytes)) . $bytes;
}

sub der_int {
  my ($bytes) = @_;
  $bytes =~ s/^\x00+//;
  $bytes = "\x00" if $bytes eq '';
  $bytes = "\x00" . $bytes if ord(substr($bytes, 0, 1)) & 0x80;
  return "\x02" . der_len(length($bytes)) . $bytes;
}

sub der_signature_from_p1363 {
  my ($sig) = @_;
  return undef unless defined $sig && length($sig) % 2 == 0;
  my $half = length($sig) / 2;
  my $body = der_int(substr($sig, 0, $half)) . der_int(substr($sig, $half));
  return "\x30" . der_len(length($body)) . $body;
}

sub der_read_len_strict {
  my ($buf, $posref) = @_;
  return undef if $$posref >= length($buf);

  my $first = ord(substr($buf, $$posref, 1));
  $$posref++;
  return $first if $first < 0x80;

  my $nbytes = $first & 0x7f;
  return undef if $nbytes == 0 || $nbytes > 4;
  return undef if $$posref + $nbytes > length($buf);
  return undef if ord(substr($buf, $$posref, 1)) == 0;

  my $len = 0;
  for (1 .. $nbytes) {
    $len = 256 * $len + ord(substr($buf, $$posref, 1));
    $$posref++;
  }
  return undef if $len < 128;
  return $len;
}

sub der_read_positive_int_strict {
  my ($buf, $posref, $end) = @_;
  return () if $$posref >= $end || ord(substr($buf, $$posref, 1)) != 0x02;
  $$posref++;

  my $len = der_read_len_strict($buf, $posref);
  return () unless defined $len;
  return () if $len == 0 || $$posref + $len > $end;

  my $bytes = substr($buf, $$posref, $len);
  $$posref += $len;
  return () if ord(substr($bytes, 0, 1)) & 0x80;
  return () if $len > 1 && substr($bytes, 0, 1) eq "\x00" && !(ord(substr($bytes, 1, 1)) & 0x80);

  $bytes = substr($bytes, 1) if length($bytes) > 1 && substr($bytes, 0, 1) eq "\x00";
  return (norm_unsigned_hex(bin_to_hex($bytes)));
}

sub parse_ecdsa_der_strict {
  my ($sig) = @_;
  return () unless defined $sig && length($sig) >= 8;

  my $pos = 0;
  return () if ord(substr($sig, $pos, 1)) != 0x30;
  $pos++;

  my $seq_len = der_read_len_strict($sig, \$pos);
  return () unless defined $seq_len;
  my $end = $pos + $seq_len;
  return () if $end != length($sig);

  my @r = der_read_positive_int_strict($sig, \$pos, $end);
  return () unless @r;
  my @s = der_read_positive_int_strict($sig, \$pos, $end);
  return () unless @s;
  return () if $pos != $end;

  return ($r[0], $s[0]);
}

sub ecdsa_bitcoin_signature_policy_ok {
  my ($sig) = @_;
  my ($r, $s) = parse_ecdsa_der_strict($sig);
  return 0 unless defined $r && defined $s;
  return 0 if hex_cmp_unsigned($r, '0') <= 0 || hex_cmp_unsigned($s, '0') <= 0;
  return 0 if hex_cmp_unsigned($r, $SECP256K1_ORDER) >= 0;
  return 0 if hex_cmp_unsigned($s, $SECP256K1_ORDER) >= 0;
  return 0 if hex_cmp_unsigned($s, $SECP256K1_HALF_ORDER) > 0;
  return 1;
}

sub check_exact_hex {
  my ($file, $doc, $group, $test, $got, $want_hex, $op) = @_;
  my $result = $test->{result} || '';
  my $name = name_for($file, $doc, $group, $test, $op);
  my $got_hex = bin_to_hex($got);
  $want_hex = lc_hex($want_hex);
  if ($result eq 'valid') {
    is($got_hex, $want_hex, $name);
  }
  elsif ($result eq 'acceptable') {
    ok(!defined($got) || $got_hex eq $want_hex, $name);
  }
  elsif ($result eq 'invalid') {
    ok(!defined($got) || $got_hex ne $want_hex, $name);
  }
  else {
    fail("$name unexpected Wycheproof result");
  }
}

sub check_exact_bin {
  my ($file, $doc, $group, $test, $got, $want, $op) = @_;
  my $result = $test->{result} || '';
  my $name = name_for($file, $doc, $group, $test, $op);
  if ($result eq 'valid') {
    is($got, $want, $name);
  }
  elsif ($result eq 'acceptable') {
    ok(!defined($got) || $got eq $want, $name);
  }
  elsif ($result eq 'invalid') {
    ok(!defined($got) || $got ne $want, $name);
  }
  else {
    fail("$name unexpected Wycheproof result");
  }
}

sub check_verify_bool {
  my ($file, $doc, $group, $test, $valid, $op) = @_;
  my $result = $test->{result} || '';
  my $name = name_for($file, $doc, $group, $test, $op);
  if ($result eq 'valid') {
    ok($valid, $name);
  }
  elsif ($result eq 'acceptable') {
    ok(1, $name);
  }
  elsif ($result eq 'invalid') {
    ok(!$valid, $name);
  }
  else {
    fail("$name unexpected Wycheproof result");
  }
}

sub check_auth_tag {
  my ($file, $doc, $group, $test, $got, $want_hex, $tag_len, $op) = @_;
  my $result = $test->{result} || '';
  my $name = name_for($file, $doc, $group, $test, $op);
  my $got_hex = defined $got ? bin_to_hex(substr($got, 0, $tag_len)) : undef;
  $want_hex = lc_hex($want_hex);
  if ($result eq 'valid') {
    is($got_hex, $want_hex, $name);
  }
  elsif ($result eq 'acceptable') {
    ok(!defined($got) || $got_hex eq $want_hex, $name);
  }
  elsif ($result eq 'invalid') {
    ok(!defined($got_hex) || $got_hex ne $want_hex, $name);
  }
  else {
    fail("$name unexpected Wycheproof result");
  }
}

sub handle_aead {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';

  if ($alg =~ /^A(128|192|256)CBC-HS(256|384|512)$/) {
    return handle_jwe_cbc_hmac($file, $doc, $1, $2);
  }
  if ($alg eq 'AEAD-AES-SIV-CMAC') {
    return handle_aead_siv($file, $doc);
  }
  if ($alg eq 'CHACHA20-POLY1305') {
    return handle_aead_chacha($file, $doc, 0);
  }
  if ($alg eq 'XCHACHA20-POLY1305') {
    return handle_aead_chacha($file, $doc, 1);
  }
  if ($alg eq 'AES-EAX') {
    return handle_aead_mode($file, $doc, 'EAX', 'AES');
  }
  if ($alg =~ /^([A-Z0-9]+)-GCM$/) {
    my $cipher = norm_cipher($1);
    return unsupported_file($file, $doc, "unsupported AEAD algorithm $alg")
      unless $cipher && cipher_supported($cipher);
    return handle_aead_mode($file, $doc, 'GCM', $cipher);
  }
  if ($alg =~ /^([A-Z0-9]+)-CCM$/) {
    my $cipher = norm_cipher($1);
    return unsupported_file($file, $doc, "unsupported AEAD algorithm $alg")
      unless $cipher && cipher_supported($cipher);
    return handle_aead_mode($file, $doc, 'CCM', $cipher);
  }

  unsupported_file($file, $doc, "unsupported AEAD algorithm $alg");
}

sub handle_aead_mode {
  my ($file, $doc, $mode, $cipher) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $tag_len = int(($group->{tagSize} || 128) / 8);
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $iv  = hex_to_bin($test->{iv});
      my $aad = hex_to_bin($test->{aad});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      my $tag = hex_to_bin($test->{tag});

      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $out) = eval_list(sub {
          return Crypt::AuthEnc::GCM::gcm_encrypt_authenticate($cipher, $key, $iv, $aad, $msg)
            if $mode eq 'GCM';
          return Crypt::AuthEnc::CCM::ccm_encrypt_authenticate($cipher, $key, $iv, $aad, $tag_len, $msg)
            if $mode eq 'CCM';
          return Crypt::AuthEnc::EAX::eax_encrypt_authenticate($cipher, $key, $iv, $aad, $msg);
        });
        my ($got_ct, $got_tag) = $ok ? @$out : (undef, undef);
        check_exact_hex($file, $doc, $group, $test, $got_ct, $test->{ct}, "$mode encrypt ct");
        check_exact_hex($file, $doc, $group, $test, defined $got_tag ? substr($got_tag, 0, $tag_len) : undef, $test->{tag}, "$mode encrypt tag");
      }

      my ($ok, $pt) = eval_scalar(sub {
        return Crypt::AuthEnc::GCM::gcm_decrypt_verify($cipher, $key, $iv, $aad, $ct, $tag)
          if $mode eq 'GCM';
        return Crypt::AuthEnc::CCM::ccm_decrypt_verify($cipher, $key, $iv, $aad, $ct, $tag)
          if $mode eq 'CCM';
        return Crypt::AuthEnc::EAX::eax_decrypt_verify($cipher, $key, $iv, $aad, $ct, $tag);
      });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, "$mode decrypt");
    }
  }
}

sub handle_aead_chacha {
  my ($file, $doc, $xchacha) = @_;
  my $mode = $xchacha ? 'XChaCha20-Poly1305' : 'ChaCha20-Poly1305';
  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $iv  = hex_to_bin($test->{iv});
      my $aad = hex_to_bin($test->{aad});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      my $tag = hex_to_bin($test->{tag});

      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $out) = eval_list(sub {
          return $xchacha
            ? Crypt::AuthEnc::XChaCha20Poly1305::xchacha20poly1305_encrypt_authenticate($key, $iv, $aad, $msg)
            : Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_encrypt_authenticate($key, $iv, $aad, $msg);
        });
        my ($got_ct, $got_tag) = $ok ? @$out : (undef, undef);
        check_exact_hex($file, $doc, $group, $test, $got_ct, $test->{ct}, "$mode encrypt ct");
        check_exact_hex($file, $doc, $group, $test, $got_tag, $test->{tag}, "$mode encrypt tag");
      }

      my ($ok, $pt) = eval_scalar(sub {
        return $xchacha
          ? Crypt::AuthEnc::XChaCha20Poly1305::xchacha20poly1305_decrypt_verify($key, $iv, $aad, $ct, $tag)
          : Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_decrypt_verify($key, $iv, $aad, $ct, $tag);
      });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, "$mode decrypt");
    }
  }
}

sub handle_aead_siv {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      my $tag = hex_to_bin($test->{tag});
      my $ad  = [ hex_to_bin($test->{aad}), hex_to_bin($test->{iv}) ];
      my $full_ct = $tag . $ct;

      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $got) = eval_scalar(sub { Crypt::AuthEnc::SIV::siv_encrypt_authenticate('AES', $key, $msg, $ad) });
        $got = undef unless $ok;
        check_exact_bin($file, $doc, $group, $test, $got, $full_ct, 'AES-SIV encrypt');
      }

      my ($ok, $pt) = eval_scalar(sub { Crypt::AuthEnc::SIV::siv_decrypt_verify('AES', $key, $full_ct, $ad) });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'AES-SIV decrypt');
    }
  }
}

sub handle_jwe_cbc_hmac {
  my ($file, $doc, $aes_bits, $hmac_bits) = @_;
  my $key_len = int($aes_bits / 8);
  my $tag_len = int($hmac_bits / 16);
  my $hash = "SHA$hmac_bits";
  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $mac_key = substr($key, 0, $key_len);
      my $enc_key = substr($key, $key_len);
      my $iv  = hex_to_bin($test->{iv});
      my $aad = hex_to_bin($test->{aad});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      my $tag = hex_to_bin($test->{tag});

      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $got_ct) = eval_scalar(sub { Crypt::Mode::CBC->new('AES', 1)->encrypt($msg, $enc_key, $iv) });
        $got_ct = undef unless $ok;
        my $got_tag = defined $got_ct ? jwe_cbc_hmac_tag($hash, $mac_key, $aad, $iv, $got_ct, $tag_len) : undef;
        check_exact_hex($file, $doc, $group, $test, $got_ct, $test->{ct}, 'CBC-HMAC encrypt ct');
        check_exact_hex($file, $doc, $group, $test, $got_tag, $test->{tag}, 'CBC-HMAC encrypt tag');
      }

      my $expected_tag = jwe_cbc_hmac_tag($hash, $mac_key, $aad, $iv, $ct, $tag_len);
      my $pt;
      if (defined $expected_tag && $expected_tag eq $tag) {
        my ($ok, $got) = eval_scalar(sub { Crypt::Mode::CBC->new('AES', 1)->decrypt($ct, $enc_key, $iv) });
        $pt = $ok ? $got : undef;
      }
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'CBC-HMAC decrypt');
    }
  }
}

sub jwe_cbc_hmac_tag {
  my ($hash, $mac_key, $aad, $iv, $ct, $tag_len) = @_;
  my $bits = length($aad) * 8;
  my $al = pack('NN', int($bits / 4294967296), $bits & 0xffffffff);
  return substr(Crypt::Mac::HMAC::hmac($hash, $mac_key, $aad, $iv, $ct, $al), 0, $tag_len);
}

sub handle_daead {
  my ($file, $doc) = @_;
  return unsupported_file($file, $doc, 'unsupported DAEAD algorithm ' . ($doc->{algorithm} || '(none)'))
    unless ($doc->{algorithm} || '') eq 'AES-SIV-CMAC';

  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $aad = hex_to_bin($test->{aad});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $got) = eval_scalar(sub { Crypt::AuthEnc::SIV::siv_encrypt_authenticate('AES', $key, $msg, $aad) });
        $got = undef unless $ok;
        check_exact_hex($file, $doc, $group, $test, $got, $test->{ct}, 'AES-SIV-CMAC encrypt');
      }
      my ($ok, $pt) = eval_scalar(sub { Crypt::AuthEnc::SIV::siv_decrypt_verify('AES', $key, $ct, $aad) });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'AES-SIV-CMAC decrypt');
    }
  }
}

sub handle_ind_cpa {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  return unsupported_file($file, $doc, "unsupported IND-CPA algorithm $alg")
    unless $alg =~ /^([A-Z0-9]+)-CBC-PKCS5$/;
  my $cipher = norm_cipher($1);
  return unsupported_file($file, $doc, "unsupported IND-CPA algorithm $alg")
    unless $cipher && cipher_supported($cipher);

  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $iv  = hex_to_bin($test->{iv});
      my $msg = hex_to_bin($test->{msg});
      my $ct  = hex_to_bin($test->{ct});
      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $got_ct) = eval_scalar(sub { Crypt::Mode::CBC->new($cipher, 1)->encrypt($msg, $key, $iv) });
        $got_ct = undef unless $ok;
        check_exact_hex($file, $doc, $group, $test, $got_ct, $test->{ct}, 'CBC-PKCS5 encrypt');
      }
      my ($ok, $pt) = eval_scalar(sub { Crypt::Mode::CBC->new($cipher, 1)->decrypt($ct, $key, $iv) });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'CBC-PKCS5 decrypt');
    }
  }
}

sub handle_mac {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  my ($kind, $param);

  if ($alg =~ /^HMAC(.+)$/) {
    $kind = 'HMAC';
    $param = norm_hash($1);
    return unsupported_file($file, $doc, "unsupported MAC algorithm $alg")
      unless $param && hash_supported($param);
  }
  elsif ($alg =~ /^([A-Z0-9]+)-CMAC$/) {
    $kind = 'CMAC';
    $param = norm_cipher($1);
    return unsupported_file($file, $doc, "unsupported MAC algorithm $alg")
      unless $param && cipher_supported($param);
  }
  else {
    return unsupported_file($file, $doc, "unsupported MAC algorithm $alg");
  }

  for my $group (@{ $doc->{testGroups} || [] }) {
    my $tag_len = int(($group->{tagSize} || 0) / 8);
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $tag) = eval_scalar(sub {
        return $kind eq 'HMAC'
          ? Crypt::Mac::HMAC::hmac($param, $key, $msg)
          : Crypt::Mac::OMAC::omac($param, $key, $msg);
      });
      $tag = undef unless $ok;
      check_auth_tag($file, $doc, $group, $test, $tag, $test->{tag}, $tag_len, "$kind tag");
    }
  }
}

sub handle_mac_with_iv {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  return unsupported_file($file, $doc, "unsupported MAC-with-IV algorithm $alg")
    unless $alg eq 'AES-GMAC';

  for my $group (@{ $doc->{testGroups} || [] }) {
    my $tag_len = int(($group->{tagSize} || 128) / 8);
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $key = hex_to_bin($test->{key});
      my $iv  = hex_to_bin($test->{iv});
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $out) = eval_list(sub { Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES', $key, $iv, $msg, '') });
      my $tag = $ok ? $out->[1] : undef;
      check_auth_tag($file, $doc, $group, $test, $tag, $test->{tag}, $tag_len, 'GMAC tag');
    }
  }
}

sub handle_hkdf {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  return unsupported_file($file, $doc, "unsupported HKDF algorithm $alg")
    unless $alg =~ /^HKDF-(.+)$/;
  my $hash = norm_hash($1);
  return unsupported_file($file, $doc, "unsupported HKDF algorithm $alg")
    unless $hash && hash_supported($hash);

  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $ikm  = hex_to_bin($test->{ikm});
      my $salt = hex_to_bin($test->{salt});
      my $info = hex_to_bin($test->{info});
      my $size = $test->{size};
      my ($ok, $okm) = eval_scalar(sub { Crypt::KeyDerivation::hkdf($ikm, $salt, $hash, $size, $info) });
      $okm = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $okm, $test->{okm}, 'HKDF');
    }
  }
}

sub handle_pbkdf {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  return unsupported_file($file, $doc, "unsupported PBKDF algorithm $alg")
    unless $alg =~ /^PBKDF2-HMAC(.+)$/;
  my $hash = norm_hash($1);
  return unsupported_file($file, $doc, "unsupported PBKDF algorithm $alg")
    unless $hash && hash_supported($hash);

  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $password = hex_to_bin($test->{password});
      my $salt = hex_to_bin($test->{salt});
      my ($ok, $dk) = eval_scalar(sub {
        Crypt::KeyDerivation::pbkdf2($password, $salt, $test->{iterationCount}, $hash, $test->{dkLen});
      });
      $dk = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $dk, $test->{dk}, 'PBKDF2');
    }
  }
}

sub handle_pbe {
  my ($file, $doc) = @_;
  my $alg = $doc->{algorithm} || '';
  return unsupported_file($file, $doc, "unsupported PBE algorithm $alg")
    unless $alg =~ /^PbeWithHmac(.+)AndAes_(128|192|256)$/;
  my $hash = norm_hash($1);
  my $key_len = int($2 / 8);
  return unsupported_file($file, $doc, "unsupported PBE algorithm $alg")
    unless $hash && hash_supported($hash);

  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $password = hex_to_bin($test->{password});
      my $salt = hex_to_bin($test->{salt});
      my $iv = hex_to_bin($test->{iv});
      my $msg = hex_to_bin($test->{msg});
      my $ct = hex_to_bin($test->{ct});
      my ($ok_key, $key) = eval_scalar(sub {
        Crypt::KeyDerivation::pbkdf2($password, $salt, $test->{iterationCount}, $hash, $key_len);
      });
      $key = undef unless $ok_key;

      if (($test->{result} || '') ne 'invalid') {
        my ($ok, $got_ct) = defined $key
          ? eval_scalar(sub { Crypt::Mode::CBC->new('AES', 1)->encrypt($msg, $key, $iv) })
          : (0, undef, 'key derivation failed');
        $got_ct = undef unless $ok;
        check_exact_hex($file, $doc, $group, $test, $got_ct, $test->{ct}, 'PBES2 encrypt');
      }

      my ($ok, $pt) = defined $key
        ? eval_scalar(sub { Crypt::Mode::CBC->new('AES', 1)->decrypt($ct, $key, $iv) })
        : (0, undef, 'key derivation failed');
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'PBES2 decrypt');
    }
  }
}

sub handle_rsa_pkcs1_verify {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    if (!$hash || !hash_supported($hash)) {
      unsupported_group($file, $doc, $group, 'unsupported RSA PKCS1 hash ' . ($group->{sha} || '(none)'));
      next;
    }
    my $pk = eval { Crypt::PK::RSA->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported RSA public key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $valid) = eval_scalar(sub { $pk->verify_message($sig, $msg, $hash, 'v1.5') });
      $valid = 0 unless $ok;
      check_verify_bool($file, $doc, $group, $test, $valid, 'RSA PKCS1 verify');
    }
  }
}

sub handle_rsa_pss_verify {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    my $mgf_hash = norm_hash($group->{mgfSha});
    if (!$hash || !$mgf_hash || !hash_supported($hash) || !hash_supported($mgf_hash)) {
      unsupported_group($file, $doc, $group, 'unsupported RSA PSS hash');
      next;
    }
    my $pk = eval { Crypt::PK::RSA->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported RSA public key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      my $msg = hex_to_bin($test->{msg});
      my $digest = Crypt::Digest::digest_data($hash, $msg);
      my ($ok, $valid) = eval_scalar(sub {
        $pk->verify_hash($sig, $digest, $hash, 'pss', $group->{sLen}, $mgf_hash);
      });
      $valid = 0 unless $ok;
      check_verify_bool($file, $doc, $group, $test, $valid, 'RSA PSS verify');
    }
  }
}

sub handle_rsa_pkcs1_generate {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    if (!$hash || !hash_supported($hash)) {
      unsupported_group($file, $doc, $group, 'unsupported RSA PKCS1 generate hash ' . ($group->{sha} || '(none)'));
      next;
    }
    my $pk = eval { Crypt::PK::RSA->new(\$group->{privateKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported RSA private key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $sig) = eval_scalar(sub { $pk->sign_message($msg, $hash, 'v1.5') });
      $sig = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $sig, $test->{sig}, 'RSA PKCS1 generate');
    }
  }
}

sub handle_rsa_oaep_decrypt {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    my $mgf_hash = norm_hash($group->{mgfSha});
    if (!$hash || !$mgf_hash || !hash_supported($hash) || !hash_supported($mgf_hash)) {
      unsupported_group($file, $doc, $group, 'unsupported RSA OAEP hash');
      next;
    }
    if ($hash ne $mgf_hash) {
      unsupported_group($file, $doc, $group, 'RSA OAEP distinct MGF hash not exposed by CryptX API');
      next;
    }
    my $pk = eval { Crypt::PK::RSA->new(\$group->{privateKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported RSA private key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $ct = hex_to_bin($test->{ct});
      my $label = hex_to_bin($test->{label});
      my ($ok, $pt) = eval_scalar(sub { $pk->decrypt($ct, 'oaep', $hash, $label) });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'RSA OAEP decrypt');
    }
  }
}

sub handle_rsa_pkcs1_decrypt {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $pk = eval { Crypt::PK::RSA->new(\$group->{privateKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported RSA private key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $ct = hex_to_bin($test->{ct});
      my ($ok, $pt) = eval_scalar(sub { $pk->decrypt($ct, 'v1.5') });
      $pt = undef unless $ok;
      check_exact_hex($file, $doc, $group, $test, $pt, $test->{msg}, 'RSA PKCS1 decrypt');
    }
  }
}

sub handle_dsa_verify {
  my ($file, $doc) = @_;
  my $p1363 = ($doc->{schema} || '') =~ /p1363/;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    if (!$hash || !hash_supported($hash)) {
      unsupported_group($file, $doc, $group, 'unsupported DSA hash ' . ($group->{sha} || '(none)'));
      next;
    }
    my $pk = eval { Crypt::PK::DSA->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported DSA public key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      $sig = der_signature_from_p1363($sig) if $p1363;
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $valid) = eval_scalar(sub { $pk->verify_message($sig, $msg, $hash) });
      $valid = 0 unless $ok;
      check_verify_bool($file, $doc, $group, $test, $valid, $p1363 ? 'DSA P1363 verify' : 'DSA DER verify');
    }
  }
}

sub handle_ec_curve_test {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $name = name_for($file, $doc, $group, $test, 'EC curve params');
      my @mismatch;
      my $curve = curve_supported($test->{name});
      my ($ok_key, $pk, $err) = eval_scalar(sub { Crypt::PK::ECC->new->generate_key($curve) });

      if (!$ok_key || !$pk) {
        chomp($err) if defined $err;
        push @mismatch, 'unsupported curve ' . ($test->{name} || '(none)') . (defined $err ? ": $err" : '');
      }
      else {
        my $h = $pk->key2hash;
        my @hex_fields = (
          [ p  => 'curve_prime' ],
          [ n  => 'curve_order' ],
          [ a  => 'curve_A' ],
          [ b  => 'curve_B' ],
          [ gx => 'curve_Gx' ],
          [ gy => 'curve_Gy' ],
        );
        for my $field (@hex_fields) {
          my ($want_key, $got_key) = @$field;
          my $want = norm_unsigned_hex($test->{$want_key});
          my $got  = norm_unsigned_hex($h->{$got_key});
          push @mismatch, "$want_key got=$got want=$want"
            if !defined($want) || !defined($got) || $got ne $want;
        }

        push @mismatch, 'h got=' . ($h->{curve_cofactor} // '(undef)') . ' want=' . ($test->{h} // '(undef)')
          if !defined($h->{curve_cofactor}) || !defined($test->{h}) || $h->{curve_cofactor} != $test->{h};
        push @mismatch, 'oid got=' . ($h->{curve_oid} // '(undef)') . ' want=' . ($test->{oid} // '(undef)')
          if !defined($h->{curve_oid}) || !defined($test->{oid}) || $h->{curve_oid} ne $test->{oid};
      }

      my $result = $test->{result} || '';
      if ($result eq 'valid') {
        ok(!@mismatch, $name);
      }
      elsif ($result eq 'acceptable') {
        ok(!$ok_key || !@mismatch, $name);
      }
      elsif ($result eq 'invalid') {
        ok(!$ok_key || @mismatch, $name);
      }
      else {
        fail("$name unexpected Wycheproof result");
      }
      diag("$name: " . join('; ', @mismatch)) if @mismatch;
    }
  }
}

sub handle_ecdsa_bitcoin_verify {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    if (!$hash || !hash_supported($hash)) {
      unsupported_group($file, $doc, $group, 'unsupported ECDSA Bitcoin hash ' . ($group->{sha} || '(none)'));
      next;
    }

    my $pk = eval { Crypt::PK::ECC->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported ECDSA Bitcoin public key');
      next;
    }

    my $key_hash = eval { $pk->key2hash } || {};
    if (($key_hash->{curve_name} || '') ne 'secp256k1') {
      unsupported_group($file, $doc, $group, 'unsupported ECDSA Bitcoin curve ' . ($key_hash->{curve_name} || '(none)'));
      next;
    }

    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      my $msg = hex_to_bin($test->{msg});
      my $valid = 0;

      if (ecdsa_bitcoin_signature_policy_ok($sig)) {
        my ($ok, $verified) = eval_scalar(sub { $pk->verify_message($sig, $msg, $hash) });
        $valid = $ok && $verified ? 1 : 0;
      }

      check_verify_bool($file, $doc, $group, $test, $valid, 'ECDSA Bitcoin verify');
    }
  }
}

sub handle_ecdsa_verify {
  my ($file, $doc) = @_;
  my $p1363 = ($doc->{schema} || '') =~ /p1363/;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $hash = norm_hash($group->{sha});
    if (!$hash || !hash_supported($hash)) {
      unsupported_group($file, $doc, $group, 'unsupported ECDSA hash ' . ($group->{sha} || '(none)'));
      next;
    }
    my $pk = eval { Crypt::PK::ECC->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported ECDSA public key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $valid) = eval_scalar(sub {
        return $p1363
          ? $pk->verify_message_rfc7518($sig, $msg, $hash)
          : $pk->verify_message($sig, $msg, $hash);
      });
      $valid = 0 unless $ok;
      check_verify_bool($file, $doc, $group, $test, $valid, $p1363 ? 'ECDSA P1363 verify' : 'ECDSA DER verify');
    }
  }
}

sub handle_eddsa_verify {
  my ($file, $doc) = @_;
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $curve = lc($group->{publicKey}{curve} || $group->{publicKeyJwk}{crv} || '');
    my $class =
      $curve eq 'ed448' || $curve eq 'edwards448'     ? 'Crypt::PK::Ed448' :
      $curve eq 'ed25519' || $curve eq 'edwards25519' ? 'Crypt::PK::Ed25519' :
      undef;
    if (!$class) {
      unsupported_group($file, $doc, $group, 'unsupported EdDSA curve ' . ($curve || '(none)'));
      next;
    }
    my $pk = eval { $class->new(\$group->{publicKeyPem}) };
    if (!$pk) {
      unsupported_group($file, $doc, $group, 'unsupported EdDSA public key');
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my $sig = hex_to_bin($test->{sig});
      my $msg = hex_to_bin($test->{msg});
      my ($ok, $valid) = eval_scalar(sub { $pk->verify_message($sig, $msg) });
      $valid = 0 unless $ok;
      check_verify_bool($file, $doc, $group, $test, $valid, 'EdDSA verify');
    }
  }
}

sub handle_ecdh {
  my ($file, $doc) = @_;
  my $schema = $doc->{schema} || '';
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $curve = curve_supported($group->{curve});
    if (!$curve) {
      unsupported_group($file, $doc, $group, 'unsupported ECDH curve ' . ($group->{curve} || '(none)'));
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my ($priv, $pub);
      if ($schema =~ /pem/) {
        $priv = eval { Crypt::PK::ECC->new(\$test->{private}) };
        $pub  = eval { Crypt::PK::ECC->new(\$test->{public}) };
      }
      elsif ($schema =~ /webcrypto/) {
        $priv = eval { Crypt::PK::ECC->new($test->{private}) };
        $pub  = eval { Crypt::PK::ECC->new($test->{public}) };
      }
      elsif ($schema =~ /ecpoint/) {
        my $sk = ec_bigint_to_scalar($test->{private}, $curve);
        my $pk = hex_to_bin($test->{public});
        $priv = eval { Crypt::PK::ECC->new->import_key_raw($sk, $curve) };
        $pub  = eval { Crypt::PK::ECC->new->import_key_raw($pk, $curve) };
      }
      else {
        my $sk = ec_bigint_to_scalar($test->{private}, $curve);
        my $pk_der = hex_to_bin($test->{public});
        $priv = eval { Crypt::PK::ECC->new->import_key_raw($sk, $curve) };
        $pub  = eval { Crypt::PK::ECC->new(\$pk_der) };
      }
      my $shared;
      if ($priv && $pub) {
        my ($ok, $got) = eval_scalar(sub { $priv->shared_secret($pub) });
        $shared = $ok ? $got : undef;
      }
      check_exact_hex($file, $doc, $group, $test, $shared, $test->{shared}, 'ECDH shared');
    }
  }
}

sub handle_xdh {
  my ($file, $doc) = @_;
  my $schema = $doc->{schema} || '';
  for my $group (@{ $doc->{testGroups} || [] }) {
    my $curve = lc($group->{curve} || '');
    my $class;
    $class = 'Crypt::PK::X25519' if $curve eq 'curve25519' || $curve eq 'x25519';
    $class = 'Crypt::PK::X448'   if $curve eq 'curve448'   || $curve eq 'x448';
    if (!$class) {
      unsupported_group($file, $doc, $group, 'unsupported XDH curve ' . ($group->{curve} || '(none)'));
      next;
    }
    for my $test (@{ $group->{tests} || [] }) {
      mark_tc();
      my ($priv, $pub);
      if ($schema =~ /pem/) {
        $priv = eval { $class->new(\$test->{private}) };
        $pub  = eval { $class->new(\$test->{public}) };
      }
      elsif ($schema =~ /jwk/) {
        $priv = eval { $class->new($test->{private}) };
        $pub  = eval { $class->new($test->{public}) };
      }
      elsif ($schema =~ /asn/) {
        my $sk = hex_to_bin($test->{private});
        my $pk = hex_to_bin($test->{public});
        $priv = eval { $class->new(\$sk) };
        $pub  = eval { $class->new(\$pk) };
      }
      else {
        my $sk = hex_to_bin($test->{private});
        my $pk = hex_to_bin($test->{public});
        $priv = eval { $class->new->import_key_raw($sk, 'private') };
        $pub  = eval { $class->new->import_key_raw($pk, 'public') };
      }
      my $shared;
      if ($priv && $pub) {
        my ($ok, $got) = eval_scalar(sub { $priv->shared_secret($pub) });
        $shared = $ok ? $got : undef;
      }
      check_exact_hex($file, $doc, $group, $test, $shared, $test->{shared}, 'XDH shared');
    }
  }
}
