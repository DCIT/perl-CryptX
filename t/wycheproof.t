# rebuild:
# rm -f src/liballinone.a && touch CryptX.xs && make && perl -Mblib t/wycheproof.t

use strict;
use warnings;

use Test::More;

plan skip_all => "No JSON::* module installed" unless eval { require JSON::PP } || eval { require JSON::XS } || eval { require Cpanel::JSON::XS };
plan skip_all => "Temporarily disabled";
plan tests => 1298;

use CryptX;
use Crypt::Misc 'read_rawfile';
use Crypt::Digest 'digest_data';

if (0) {
  use Crypt::Mode::CBC;

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/aes_cbc_pkcs5_test.json';
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
      my $testname = "type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid' || $result eq 'acceptable') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
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

if (0) {
  use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/aes_gcm_test.json';
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
      my $testname = "type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid' || $result eq 'acceptable') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
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

if (0) {
  use Crypt::AuthEnc::CCM qw(ccm_encrypt_authenticate ccm_decrypt_verify);

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/aes_ccm_test.json';
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
      my $testname = "type=$type tcId=$tcId comment='$comment' expected-result=$result";
      if ($result eq 'valid' || $result eq 'acceptable') {
        is(unpack("H*", $ct2),  $t->{ct},  "$testname CT-v");
        is(unpack("H*", $tag2), $t->{tag}, "$testname TAG-v");
        is(unpack("H*", $pt2),  $t->{msg}, "$testname PT-v");
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

if (0) {
  use Crypt::PK::RSA;
  use Crypt::PK::ECC;
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
          ok($valid, $testname);                   ## treat "acceptable" as "valid"
         #ok(1, "do not care about 'acceptable'"); ## ignore acceptable
        }
        elsif ($result eq 'invalid') {
          ok(!$valid, $testname);
        }
        else {
          ok(0, "UNEXPECTED result=$result");
        }
      }
    }
  }
}

if (0) {
  use Crypt::PK::DSA;

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/dsa_test.json';
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
      # skip unsupported tests:
      next if $tcId==1   && $result eq 'acceptable' && $comment eq "Legacy:ASN encoding of r misses leading 0";
      next if $tcId==286 && $result eq 'acceptable' && $comment eq "Legacy:ASN encoding of s misses leading 0";
      next if $tcId==571 && $result eq 'acceptable' && $comment eq "Legacy:ASN encoding of r misses leading 0";
      # do the test
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::DSA->new( \$keyPem );
      my $hash = digest_data($sha, $message);
      my $valid_h = $pk->verify_hash($sig, $hash);
      my $valid = $pk->verify_message($sig, $message, $sha);
      if ($result eq 'valid') {
        ok($valid, $testname);
      }
      elsif ($result eq 'acceptable') {
       #ok($valid, $testname);                   ## treat "acceptable" as "valid"
        ok(1, "do not care about 'acceptable'"); ## ignore acceptable
      }
      elsif ($result eq 'invalid') {
        ok(!$valid, $testname);
      }
      else {
        ok(0, "UNEXPECTED result=$result");
      }
    }
  }
}

if (0) {
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
        # skip unsupported tests:
        next if $result eq 'acceptable' && $comment =~ /^Legacy:ASN encoding of [rs] misses leading 0$/;
        # do the test
        my $testname = "($json) type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
        my $pk = Crypt::PK::ECC->new( \$keyPem );
        my $valid = $pk->verify_message($sig, $message, $sha);
        if ($result eq 'valid') {
          ok($valid, "$testname verify_message=$valid");
        }
        elsif ($result eq 'acceptable') {
          ok($valid, "$testname verify_message=$valid"); ## treat "acceptable" as "valid"
         #ok(1, "do not care about 'acceptable'");       ## ignore acceptable
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
}

if (0) {
  use Crypt::PK::ECC;

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/ecdsa_webcrypto_test.json';
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
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::ECC->new( \$keyPem );
      my $valid = $pk->verify_message_rfc7518($sig, $message, $sha);
      if ($result eq 'valid') {
        ok($valid, "$testname verify_message=$valid");
      }
      elsif ($result eq 'acceptable') {
       #ok($valid, "$testname verify_message=$valid"); ## treat "acceptable" as "valid"
        ok(1, "do not care about 'acceptable'");       ## ignore acceptable
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
         #is($shared_hex, $t->{shared}, $testname); ## treat "acceptable" as "valid"
          ok(1, "do not care about 'acceptable'");  ## ignore acceptable
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
