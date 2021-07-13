# rebuild:
# rm -f src/liballinone.a && touch CryptX.xs && make && perl -Mblib t/wycheproof.t

use strict;
use warnings;

use Test::More;

plan skip_all => "JSON module not installed" unless eval { require JSON };
#plan skip_all => "Temporarily disabled";
plan tests => 14339;

use CryptX;
use Crypt::Misc 'read_rawfile';
use Crypt::Digest 'digest_data';

if (1) {
  use Crypt::PK::Ed25519;
  my $json = 't/wycheproof/eddsa_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type   = $g->{type}; # EDDSAVer
    my $keyDer = pack "H*", $g->{keyDer};
    my $keyPem = $g->{keyPem};
    my $pk     = pack "H*", $g->{key}{pk};
    my $sk     = pack "H*", $g->{key}{sk};
    for my $t (@{$g->{tests}}) {
      my $tcId     = $t->{tcId};
      my $comment  = $t->{comment};
      my $result   = $t->{result};
      my $message  = pack "H*", $t->{msg};
      my $sig      = pack "H*", $t->{sig};
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::Ed25519->new( \$keyPem );
      my $valid = $pk->verify_message($sig, $message);
      if ($result eq 'valid') {
        ok($valid, "$testname valid=$valid");
      }
      elsif ($result eq 'acceptable') {
        ok($valid, "$testname valid=$valid"); # consider: acceptable == valid
      }
      elsif ($result eq 'invalid') {
        SKIP: {
          skip "ltc bug ed25519", 1 if $tcId =~ /^(63|64|65|66)$/; #XXX-FIXME
          ok(!$valid, "$testname valid=$valid");
        }
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::PK::X25519;
  my $json = 't/wycheproof/x25519_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $curve = $g->{curve};
    next if $curve ne 'curve25519';
    for my $t (@{$g->{tests}}) {
      my $pk      = pack "H*", $t->{public};
      my $sk      = pack "H*", $t->{private};
      my $sh      = pack "H*", $t->{shared};
      my $result  = $t->{result};
      my $comment = $t->{comment};
      my $s = Crypt::PK::X25519->new->import_key_raw($sk, 'private');
      my $p = Crypt::PK::X25519->new->import_key_raw($pk, 'public');
      my $shared = $s->shared_secret($p);
      if ($result eq 'valid') {
        is(unpack("H*", $shared), $t->{shared}, "result=$result comment=$comment");
      }
      elsif ($result eq 'acceptable') {
        is(unpack("H*", $shared), $t->{shared}, "result=$result comment=$comment");
      }
      else {
        isnt(unpack("H*", $shared), $t->{shared}, "result=$result comment=$comment");
      }
    }
  }
}

if (1) {
  use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate chacha20poly1305_decrypt_verify);

  my $json = 't/wycheproof/chacha20_poly1305_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    my $tlen    = $g->{tagSize};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $aad     = pack "H*", $t->{aad}; # "6578616d706c65"
      my $ct      = pack "H*", $t->{ct};  # "5d349ead175ef6b1def6fd"
      my $iv      = pack "H*", $t->{iv};  # "752abad3e0afb5f434dc4310"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      my $tag     = pack "H*", $t->{tag}; # "4fbcdeb7e4793f4a1d7e4faa70100af1"
      # do the test
      my ($ct2, $tag2) = eval { chacha20poly1305_encrypt_authenticate($key, $iv, $aad, $msg) };
      my $pt2 = eval { chacha20poly1305_decrypt_verify($key, $iv, $aad, $ct, $tag) };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        is($pt2, undef, "$testname PT-a");
      }
      elsif ($result eq 'invalid') {
        is($pt2, undef, "$testname PT-i");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::Mac::OMAC;

  my $json = 't/wycheproof/aes_cmac_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    my $tsize   = $g->{tagSize} / 8;
    my $ksize   = $g->{keySize} / 8;
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      my $tag     = pack "H*", $t->{tag}; # "4fbcdeb7e4793f4a1d7e4faa70100af1"
      # do the test
      my $tag2 = eval { Crypt::Mac::OMAC->new("AES", $key)->add($msg)->mac };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", substr($tag2, 0, $tsize)), $t->{tag}, "$testname TAG-v");
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        if (defined $tag2) {
          isnt(unpack("H*", substr($tag2, 0, $tsize)), $t->{tag}, "$testname TAG-a");
        }
        else {
          is($tag2, undef, "$testname PT-a");
        }
      }
      elsif ($result eq 'invalid') {
        if (defined $tag2) {
          isnt(unpack("H*", substr($tag2, 0, $tsize)), $t->{tag}, "$testname TAG-i");
        }
        else {
          is($tag2, undef, "$testname PT-i");
        }
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::Mode::CBC;

  my $json = 't/wycheproof/aes_cbc_pkcs5_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $ct      = pack "H*", $t->{ct};  # "5d349ead175ef6b1def6fd"
      my $iv      = pack "H*", $t->{iv};  # "752abad3e0afb5f434dc4310"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      # do the test
      my $enc = Crypt::Mode::CBC->new('AES', 1); #  1 = PKCS5 padding
      my $ct2 = eval { $enc->encrypt($msg, $key, $iv) };
      my $dec = Crypt::Mode::CBC->new('AES', 1); #  1 = PKCS5 padding
      my $pt2 = eval { $dec->decrypt($ct, $key, $iv) };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        is($pt2, undef, "$testname PT-a");
      }
      elsif ($result eq 'invalid') {
        is($pt2, undef, "$testname PT-i");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

  my $json = 't/wycheproof/aes_gcm_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $aad     = pack "H*", $t->{aad}; # "6578616d706c65"
      my $ct      = pack "H*", $t->{ct};  # "5d349ead175ef6b1def6fd"
      my $iv      = pack "H*", $t->{iv};  # "752abad3e0afb5f434dc4310"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      my $tag     = pack "H*", $t->{tag}; # "4fbcdeb7e4793f4a1d7e4faa70100af1"
      # do the test
      my ($ct2, $tag2) = eval { gcm_encrypt_authenticate('AES', $key, $iv, $aad, $msg) };
      my $pt2 = eval { gcm_decrypt_verify('AES', $key, $iv, $aad, $ct, $tag) };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
      }
      elsif ($result eq 'acceptable') {
        if ($comment eq 'small IV sizes') {
          # consider: acceptable == valid
          is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-a");
          is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-a");
          is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-a");
        }
        else {
          # consider: acceptable == invalid
          is($pt2, undef, "$testname PT-a");
        }
      }
      elsif ($result eq 'invalid') {
        is($pt2, undef, "$testname PT-i");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::AuthEnc::EAX qw(eax_encrypt_authenticate eax_decrypt_verify);

  my $json = 't/wycheproof/aes_eax_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    my $tlen    = $g->{tagSize};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $aad     = pack "H*", $t->{aad}; # "6578616d706c65"
      my $ct      = pack "H*", $t->{ct};  # "5d349ead175ef6b1def6fd"
      my $iv      = pack "H*", $t->{iv};  # "752abad3e0afb5f434dc4310"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      my $tag     = pack "H*", $t->{tag}; # "4fbcdeb7e4793f4a1d7e4faa70100af1"
      # do the test
      my ($ct2, $tag2) = eval { eax_encrypt_authenticate('AES', $key, $iv, $aad, $msg) };
      my $pt2 = eval { eax_decrypt_verify('AES', $key, $iv, $aad, $ct, $tag) };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
      }
      elsif ($result eq 'acceptable') {
        if ($comment eq 'small IV size' || $comment eq 'IV size = 0') {
          # consider: acceptable == valid
          is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-a");
          is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-a");
          is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-a");
        }
        else {
          # consider: acceptable == invalid
          is($pt2, undef, "$testname PT-a");
        }
      }
      elsif ($result eq 'invalid') {
        #isnt(unpack("H*", $ct2),  $t->{ct},  "$testname CT-i");
        #isnt(unpack("H*", $tag2), $t->{tag}, "$testname TAG-i");
        is($pt2, undef, "$testname PT-i");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

  my $json = 't/wycheproof/aes_ccm_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type    = $g->{type};
    my $tlen    = $g->{tagSize};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};           # 1
      my $comment = $t->{comment};        # ""
      my $result  = $t->{result};         # "valid"
      my $aad     = pack "H*", $t->{aad}; # "6578616d706c65"
      my $ct      = pack "H*", $t->{ct};  # "5d349ead175ef6b1def6fd"
      my $iv      = pack "H*", $t->{iv};  # "752abad3e0afb5f434dc4310"
      my $key     = pack "H*", $t->{key}; # "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"
      my $msg     = pack "H*", $t->{msg}; # "48656c6c6f20776f726c64"
      my $tag     = pack "H*", $t->{tag}; # "4fbcdeb7e4793f4a1d7e4faa70100af1"
      # do the test
      my ($ct2, $tag2) = eval { ccm_encrypt_authenticate('AES', $key, $iv, $aad, $tlen/8, $msg) };
      my $pt2 = eval { ccm_decrypt_verify('AES', $key, $iv, $aad, $ct, $tag) };
      my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        is($pt2, undef, "$testname PT-a");
      }
      elsif ($result eq 'invalid') {
        is($pt2, undef, "$testname PT-i");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::PK::RSA;
  my @files = ( "t/wycheproof/rsa_signature_test.json" );
  push @files, glob("t/wycheproof/rsa_signature_*_test.json");
  push @files, glob("t/wycheproof/rsa_pss_*.json ");

  for my $json (@files) {
    my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/rsa_signature_test.json';
    my $alg = $tests->{algorithm};
    for my $g (@{$tests->{testGroups}}) {
      my $type   = $g->{type};
      my $keyDer = pack "H*", $g->{keyDer};
      my $keyPem = $g->{keyPem};
      my $sha    = $g->{sha};
      $sha =~ s/-//g; # SHA-1 >> SHA1
      ok(Crypt::PK::RSA->new( \$keyDer ), "Crypt::PK::RSA->new + DER type: $type/$sha");
      ok(Crypt::PK::RSA->new( \$keyPem ), "Crypt::PK::RSA->new + PEM type: $type/$sha");
      for my $t (@{$g->{tests}}) {
        my $tcId    = $t->{tcId};
        my $comment = $t->{comment};
        my $result  = $t->{result};
        my $message = pack "H*", $t->{msg};
        my $sig     = pack "H*", $t->{sig};
        # do the test
        my $testname = "($json) alg=$alg type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
        my $pk = Crypt::PK::RSA->new( \$keyPem );
        my $valid;
        if ($alg eq 'RSASSA-PSS') {
          $valid = $pk->verify_message($sig, $message, $sha,"pss");
        }
        else {
          $valid = $pk->verify_message($sig, $message, $sha,"v1.5");
        }
        if ($result eq 'valid') {
          ok($valid, $testname);
        }
        elsif ($result eq 'acceptable') {
          # consider: acceptable == valid
          ok($valid, $testname);
        }
        elsif ($result eq 'invalid') {
          SKIP: {
            skip "ltc bug RSA", 1 if $comment eq "changing tag value of sequence"; #XXX-FIXME
            ok(!$valid, $testname);
          }
        }
        else {
          ok(0, "UNEXPECTED result=$result");
        }
      }
    }
  }
}

if (1) {
  use Crypt::PK::DSA;

  my $json = 't/wycheproof/dsa_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type   = $g->{type};   # "DSAVer"
    my $keyDer = pack "H*", $g->{keyDer};
    my $keyPem = $g->{keyPem};
    my $sha    = $g->{sha};    # "SHA-1"
    $sha =~ s/-//g; # SHA-1 >> SHA1
    ok(Crypt::PK::DSA->new( \$keyDer ), "Crypt::PK::DSA->new + DER type=$type/$sha");
    ok(Crypt::PK::DSA->new( \$keyPem ), "Crypt::PK::DSA->new + PEM type=$type/$sha");
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};
      my $comment = $t->{comment};
      my $result  = $t->{result};
      my $message = pack "H*", $t->{msg};
      my $sig     = pack "H*", $t->{sig};
      # do the test
      my $testname = "($json) type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::DSA->new( \$keyPem );
      my $hash = digest_data($sha, $message);
      my $valid_h = $pk->verify_hash($sig, $hash);
      my $valid = $pk->verify_message($sig, $message, $sha);
      if ($result eq 'valid') {
        ok($valid, $testname);
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        ok(!$valid, $testname);
      }
      elsif ($result eq 'invalid') {
        SKIP: {
          skip "ltc bug DSA", 1 if $comment eq "changing tag value of sequence"; #XXX-FIXME
          ok(!$valid, $testname);
        }
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (1) {
  use Crypt::PK::ECC;
  my @files = ( "t/wycheproof/ecdsa_test.json" );
  #push @files, glob("t/wycheproof/ecdsa_secp*.json");
  #push @files, glob("t/wycheproof/ecdsa_brainpool*.json");

  for my $json (@files) {
    my $tests = CryptX::_decode_json(read_rawfile($json));
    for my $g (@{$tests->{testGroups}}) {
      my $type   = $g->{type};
      my $keyDer = pack "H*", $g->{keyDer};
      my $keyPem = $g->{keyPem};
      my $sha    = $g->{sha};
      $sha =~ s/-//g; # SHA-1 >> SHA1
      ok(Crypt::PK::ECC->new( \$keyDer ), "Crypt::PK::ECC->new + DER type=$type/$sha");
      ok(Crypt::PK::ECC->new( \$keyPem ), "Crypt::PK::ECC->new + PEM type=$type/$sha");
      for my $t (@{$g->{tests}}) {
        my $tcId    = $t->{tcId};
        my $comment = $t->{comment};
        my $result  = $t->{result};
        my $message = pack "H*", $t->{msg};
        my $sig     = pack "H*", $t->{sig};
        # do the test
        my $testname = "($json) type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
        my $pk = Crypt::PK::ECC->new( \$keyPem );
        my $valid = $pk->verify_message($sig, $message, $sha);
        if ($result eq 'valid') {
          SKIP: {
            skip "ltc bug ECC", 1 if $comment eq "Edge case for Shamir multiplication";     #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "extreme value for k and edgecase s";      #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "extreme value for k";                     #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "extreme value for k and s^-1";            #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "extreme value for k and edgecase s";      #XXX-FIXME
            ok($valid, "$testname verify_message=$valid");
          }
        }
        elsif ($result eq 'acceptable') {
          # consider: acceptable == invalid
          SKIP: {
            skip "ltc bug ECC", 1 if $comment eq "Hash weaker than DL-group";               #XXX-FIXME
            ok(!$valid, "$testname verify_message=$valid");
          }
        }
        elsif ($result eq 'invalid') {
          SKIP: {
            skip "ltc bug ECC", 1 if $comment eq "changing tag value of sequence";          #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "long form encoding of length";            #XXX-FIXME
            skip "ltc bug ECC", 1 if $comment eq "length contains leading 0";               #XXX-FIXME
            ok(!$valid, "$testname verify_message=$valid");
          }

        }
        else {
          ok(0, "UNEXPECTED result=$result");
        }
      }
    }
  }
}

if (1) {
  use Crypt::PK::ECC;

  my $json = 't/wycheproof/ecdsa_webcrypto_test.json';
  my $tests = CryptX::_decode_json read_rawfile $json;
  for my $g (@{$tests->{testGroups}}) {
    my $type   = $g->{type};
    my $keyDer = pack "H*", $g->{keyDer};
    my $keyPem = $g->{keyPem};
    my $sha    = $g->{sha};
    my $jwk    = $g->{jwk};
    $sha =~ s/-//g; # SHA-1 >> SHA1
    ok(Crypt::PK::ECC->new( \$keyDer ), "Crypt::PK::ECC->new + DER type=$type/$sha");
    ok(Crypt::PK::ECC->new( \$keyPem ), "Crypt::PK::ECC->new + PEM type=$type/$sha");
    ok(Crypt::PK::ECC->new( $jwk ),     "Crypt::PK::ECC->new + JWK type=$type/$sha");
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};
      my $comment = $t->{comment};
      my $result  = $t->{result};
      my $message = pack "H*", $t->{msg};
      my $sig     = pack "H*", $t->{sig};
      # do the test
      my $testname = "($json) type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::ECC->new( \$keyPem );
      my $valid = $pk->verify_message_rfc7518($sig, $message, $sha);
      if ($result eq 'valid') {
        SKIP: {
          skip "ltc bug ECC", 1 if $comment eq "Edge case for Shamir multiplication";       #XXX-FIXME
          ok($valid, "$testname verify_message=$valid");
        }
      }
      elsif ($result eq 'acceptable') {
        # consider: acceptable == invalid
        SKIP: {
          skip "ltc bug ECC", 1 if $comment eq "Hash weaker than DL-group";                 #XXX-FIXME
          ok(!$valid, "$testname verify_message=$valid");
        }
      }
      elsif ($result eq 'invalid') {
        ok(!$valid, "$testname verify_message=$valid");
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (0) {
  use Crypt::PK::ECC;
  my @files = ( "t/wycheproof/ecdh_webcrypto_test.json", "t/wycheproof/ecdh_test.json" );
  push @files, glob("t/wycheproof/ecdh_secp*.json");
  push @files, glob("t/wycheproof/ecdh_brainpool*.json");

  for my $json (@files) {
    my $tests = CryptX::_decode_json(read_rawfile($json));
    for my $g (@{$tests->{testGroups}}) {
      my $type   = $g->{type};
      for my $t (@{$g->{tests}}) {
        my $tcId    = $t->{tcId};
        my $comment = $t->{comment};
        my $result  = $t->{result};
        my $shared  = pack "H*", $t->{shared};
        # do the test
        my $testname = "($json) type=$type tcId=$tcId comment='$comment' expected-result=$result";
        my $pub = eval { Crypt::PK::ECC->new( $t->{public} ) };
        my $pri = eval { Crypt::PK::ECC->new( $t->{private} ) };
        my $shared_hex = ($pri && $pub) ? unpack("H*", $pri->shared_secret($pub)) : 'undefined';
        if ($result eq 'valid') {
          is($shared_hex, $t->{shared}, $testname);
        }
        elsif ($result eq 'acceptable') {
          # consider: acceptable == invalid
          isnt($shared_hex, $t->{shared}, $testname);
        }
        elsif ($result eq 'invalid') {
          isnt($shared_hex, $t->{shared}, $testname);
        }
        else {
          ok(0, "UNEXPECTED result=$result");
        }
      }
    }
  }
}
