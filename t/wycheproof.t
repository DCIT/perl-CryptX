# rebuild:
# rm -f src/liballinone.a && touch CryptX.xs && make && perl -Mblib t/wycheproof.t

use strict;
use warnings;

use Test::More;

plan skip_all => "No JSON::* module installed" unless eval { require JSON::PP } || eval { require JSON::XS } || eval { require Cpanel::JSON::XS };
plan tests => 984;

use CryptX;
use Crypt::Misc 'read_rawfile';
use Crypt::Digest 'digest_data';

if (1) {
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
      if ($result eq 'valid') {
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

if (1) {
  use Crypt::PK::RSA;

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/rsa_signature_test.json';
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
      my $message = pack "H*", $t->{message};
      my $sig     = pack "H*", $t->{sig};
      # do the test
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::RSA->new( \$keyPem );
      my $valid = $pk->verify_message($sig, $message, $sha,"v1.5");
      if ($result eq 'valid' || $result eq 'acceptable') {
        ok($valid, $testname);
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

if (1) {
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
      my $message = pack "H*", $t->{message};
      my $sig     = pack "H*", $t->{sig};
      # skip unsupported tests:
      next if $tcId==12 && $result eq 'acceptable' && $comment eq "Legacy:ASN encoding of s misses leading 0";
      next if $tcId==13 && $result eq 'acceptable' && $comment eq "BER:long form encoding of length";
      next if $tcId==14 && $result eq 'acceptable' && $comment eq "BER:long form encoding of length";
      next if $tcId==15 && $result eq 'acceptable' && $comment eq "BER:long form encoding of length";
      next if $tcId==16 && $result eq 'acceptable' && $comment eq "BER:length contains leading 0";
      next if $tcId==17 && $result eq 'acceptable' && $comment eq "BER:length contains leading 0";
      next if $tcId==18 && $result eq 'acceptable' && $comment eq "BER:length contains leading 0";
      next if $tcId==19 && $result eq 'acceptable' && $comment eq "BER:indefinite length";
      next if $tcId==20 && $result eq 'acceptable' && $comment eq "BER:prepending 0's to integer";
      next if $tcId==21 && $result eq 'acceptable' && $comment eq "BER:prepending 0's to integer";
      # do the test
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::DSA->new( \$keyPem );
      my $hash = digest_data($sha, $message);
      my $valid_h = $pk->verify_hash($sig, $hash);
      my $valid = $pk->verify_message($sig, $message, $sha);
      if ($result eq 'valid' || $result eq 'acceptable') {
        ok($valid, $testname);
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

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/ecdsa_test.json';
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
      my $message = pack "H*", $t->{message};
      my $sig     = pack "H*", $t->{sig};
      # skip unsupported tests:
      next if $tcId==9  && $result eq 'acceptable' && $comment eq "BER:long form encoding of length";
      next if $tcId==10 && $result eq 'acceptable' && $comment eq "BER:long form encoding of length";
      next if $tcId==12 && $result eq 'acceptable' && $comment eq "BER:length contains leading 0";
      next if $tcId==13 && $result eq 'acceptable' && $comment eq "BER:length contains leading 0";
      next if $tcId==14 && $result eq 'acceptable' && $comment eq "BER:indefinite length";
      next if $tcId==15 && $result eq 'acceptable' && $comment eq "BER:prepending 0's to integer";
      next if $tcId==16 && $result eq 'acceptable' && $comment eq "BER:prepending 0's to integer";
      # do the test
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::ECC->new( \$keyPem );
      my $valid = $pk->verify_message($sig, $message, $sha);
      if ($result eq 'valid' || $result eq 'acceptable') {
        ok($valid, "$testname verify_message=$valid");
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

if (1) {
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
      my $message = pack "H*", $t->{message};
      my $sig     = pack "H*", $t->{sig};
      # do the test
      my $testname = "type=$type/$sha tcId=$tcId comment='$comment' expected-result=$result";
      my $pk = Crypt::PK::ECC->new( \$keyPem );
      my $valid = $pk->verify_message_rfc7518($sig, $message, $sha);
      if ($result eq 'valid' || $result eq 'acceptable') {
        ok($valid, "$testname verify_message=$valid");
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

if (1) {
  use Crypt::PK::ECC;

  my $tests = CryptX::_decode_json read_rawfile 't/wycheproof/ecdh_webcrypto_test.json';
  for my $g (@{$tests->{testGroups}}) {
    my $type   = $g->{type};
    for my $t (@{$g->{tests}}) {
      my $tcId    = $t->{tcId};
      my $comment = $t->{comment};
      my $name    = $t->{name};
      my $result  = $t->{result};
      my $shared  = pack "H*", $t->{shared};
      # do the test
      my $testname = "type=$type/$name tcId=$tcId comment='$comment' expected-result=$result";
      my $pub = Crypt::PK::ECC->new( $t->{public} );
      my $pri = Crypt::PK::ECC->new( $t->{private} );
      my $shared_hex = unpack "H*", $pri->shared_secret($pub);
      if ($result eq 'valid' || $result eq 'acceptable') {
        is($shared_hex, $t->{shared}, $testname);
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
