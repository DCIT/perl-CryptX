use strict;
use warnings;

use Test::More tests => 178;

use Crypt::PQ::SLHDSA;
use Crypt::Misc qw(read_rawfile);

# All twelve "pure" parameter sets are exercised but the slow ones (256s, 192s)
# can take a long time per signing operation, so we restrict generate/sign/verify
# round-trips to the "fast" variants and only smoke-test the rest.
#
# pk/sk/sig sizes per FIPS 205 (Table 1)
my %SIZES = (
    'SLH-DSA-SHA2-128s'  => { pk => 32, sk => 64,  sig => 7856   },
    'SLH-DSA-SHA2-128f'  => { pk => 32, sk => 64,  sig => 17088  },
    'SLH-DSA-SHA2-192s'  => { pk => 48, sk => 96,  sig => 16224  },
    'SLH-DSA-SHA2-192f'  => { pk => 48, sk => 96,  sig => 35664  },
    'SLH-DSA-SHA2-256s'  => { pk => 64, sk => 128, sig => 29792  },
    'SLH-DSA-SHA2-256f'  => { pk => 64, sk => 128, sig => 49856  },
    'SLH-DSA-SHAKE-128s' => { pk => 32, sk => 64,  sig => 7856   },
    'SLH-DSA-SHAKE-128f' => { pk => 32, sk => 64,  sig => 17088  },
    'SLH-DSA-SHAKE-192s' => { pk => 48, sk => 96,  sig => 16224  },
    'SLH-DSA-SHAKE-192f' => { pk => 48, sk => 96,  sig => 35664  },
    'SLH-DSA-SHAKE-256s' => { pk => 64, sk => 128, sig => 29792  },
    'SLH-DSA-SHAKE-256f' => { pk => 64, sk => 128, sig => 49856  },
);

my @QUICK_ALGS = $ENV{CRYPTX_TEST_SLHDSA_ALL}
                 ? sort keys %SIZES
                 : ('SLH-DSA-SHA2-128f', 'SLH-DSA-SHAKE-128f');

for my $alg (@QUICK_ALGS) {
  my $sig = Crypt::PQ::SLHDSA->new;
  isa_ok($sig, 'Crypt::PQ::SLHDSA', "$alg: new");
  is($sig->is_private, undef, "$alg: empty obj is_private==undef");
  is($sig->algorithm,  undef, "$alg: empty obj algorithm==undef");

  $sig->generate_key($alg);
  is($sig->algorithm, $alg, "$alg: algorithm");
  is($sig->is_private, 1,   "$alg: generated key is private");

  my $pub_raw  = $sig->export_key_raw('public');
  my $priv_raw = $sig->export_key_raw('private');
  is(length($pub_raw),  $SIZES{$alg}{pk}, "$alg: pub raw len");
  is(length($priv_raw), $SIZES{$alg}{sk}, "$alg: priv raw len");

  # sign + verify
  my $msg = "the message we are signing";
  my $sigval = $sig->sign_message($msg);
  is(length($sigval), $SIZES{$alg}{sig}, "$alg: signature len");
  is($sig->verify_message($sigval, $msg), 1,           "$alg: verify ok");
  is($sig->verify_message($sigval, $msg . 'x'), 0,     "$alg: verify fails on tampered msg");

  # PEM round-trip
  my $pub_pem  = $sig->export_key_pem('public');
  my $priv_pem = $sig->export_key_pem('private');
  like($pub_pem,  qr/-----BEGIN PUBLIC KEY-----/,  "$alg: pub PEM header");
  like($priv_pem, qr/-----BEGIN PRIVATE KEY-----/, "$alg: priv PEM header");

  my $verifier = Crypt::PQ::SLHDSA->new(\$pub_pem);
  is($verifier->algorithm, $alg, "$alg: pub PEM import alg");
  is($verifier->is_private, 0,   "$alg: pub PEM is_private==0");
  is($verifier->verify_message($sigval, $msg), 1, "$alg: pub-only verify ok");

  # context
  my $ctx = "my-context";
  my $sig_ctx = $sig->sign_message($msg, $ctx);
  is($sig->verify_message($sig_ctx, $msg, $ctx), 1, "$alg: ctx verify ok");
  is($sig->verify_message($sig_ctx, $msg),       0, "$alg: ctx verify fails w/o ctx");

  # sign_message_ex: deterministic with fixed optrand of length n
  # n = 16 for the 128* parameter sets used here
  my $optrand = "\0" x 16;
  my $sig_d1 = $sig->sign_message_ex($msg, undef, $optrand);
  my $sig_d2 = $sig->sign_message_ex($msg, undef, $optrand);
  is($sig_d1, $sig_d2,                                       "$alg: sign_message_ex deterministic");
  is($sig->verify_message($sig_d1, $msg), 1,                 "$alg: sign_message_ex output verifies");

  # make_key_from_seed: 3*n bytes (48 for the 128* parameter sets used here)
  my $seed_3n = "\xAB" x 48;
  my $sig_seed1 = Crypt::PQ::SLHDSA->new->make_key_from_seed($seed_3n, $alg);
  my $sig_seed2 = Crypt::PQ::SLHDSA->new->make_key_from_seed($seed_3n, $alg);
  is($sig_seed1->export_key_raw('private'), $sig_seed2->export_key_raw('private'),
     "$alg: make_key_from_seed deterministic priv");
  is($sig_seed1->export_key_raw('public'),  $sig_seed2->export_key_raw('public'),
     "$alg: make_key_from_seed deterministic pub");
  my $sig_kat = $sig_seed1->sign_message_ex($msg, undef, $optrand);
  is($sig_seed1->verify_message($sig_kat, $msg), 1,          "$alg: seeded key signs+verifies");

  # raw round-trip
  my $sig_rp = Crypt::PQ::SLHDSA->new;
  $sig_rp->import_key_raw($priv_raw, 'private', $alg);
  is($sig_rp->algorithm, $alg, "$alg: raw priv import alg");
  is($sig_rp->export_key_raw('private'), $priv_raw, "$alg: raw priv round-trip");
  is($sig_rp->export_key_raw('public'),  $pub_raw,  "$alg: raw priv yields pub");

  my $sig_ru = Crypt::PQ::SLHDSA->new;
  $sig_ru->import_key_raw($pub_raw, 'public', $alg);
  is($sig_ru->is_private, 0, "$alg: raw pub !is_private");
  is($sig_ru->verify_message($sigval, $msg), 1, "$alg: raw pub verify ok");

  # key2hash
  my $h = $sig->key2hash;
  is($h->{alg}, $alg, "$alg: key2hash alg");
  is(length($h->{pub}),  $SIZES{$alg}{pk} * 2, "$alg: key2hash pub hex");
  is(length($h->{priv}), $SIZES{$alg}{sk} * 2, "$alg: key2hash priv hex");
}

# error cases
{
  my $sig = Crypt::PQ::SLHDSA->new;
  eval { $sig->generate_key('SLH-DSA-XX') };
  like($@, qr/invalid SLH-DSA algorithm/, 'invalid alg error');

  $sig->generate_key('SLH-DSA-SHA2-128f');
  eval { $sig->sign_message('msg', 'x' x 256) };
  like($@, qr/context must be at most 255 bytes/, 'context too long');
}


# sizes (LTC slhdsa_get_sizes)
{
  # for every SLH-DSA parameter set: pk = 2n, sk = 4n, optrand = n, keygen_seed = 3n
  for my $alg (sort keys %SIZES) {
    my $n = $SIZES{$alg}{pk} / 2;
    is_deeply(Crypt::PQ::SLHDSA->sizes($alg), {
      public_key  => $SIZES{$alg}{pk},
      private_key => $SIZES{$alg}{sk},
      signature   => $SIZES{$alg}{sig},
      keygen_seed => 3 * $n,
      optrand     => $n,
    }, "$alg: sizes (class method)");
  }
  my $ref = Crypt::PQ::SLHDSA->sizes('SLH-DSA-SHAKE-128f');
  is_deeply(Crypt::PQ::SLHDSA::sizes('SLH-DSA-SHAKE-128f'), $ref, 'sizes (plain function)');
  is_deeply(Crypt::PQ::SLHDSA->sizes('2.16.840.1.101.3.4.3.27'), $ref, 'sizes (by OID)');
  is_deeply(Crypt::PQ::SLHDSA->sizes('HashSLH-DSA-SHAKE-128f-with-SHAKE128'), $ref, 'sizes (HashSLH-DSA name)');

  my $sig = Crypt::PQ::SLHDSA->new;
  is($sig->sizes, undef, 'sizes on empty object == undef');
  $sig->generate_key('SLH-DSA-SHA2-128f');
  my $s = $sig->sizes;
  is_deeply($s, Crypt::PQ::SLHDSA->sizes('SLH-DSA-SHA2-128f'), 'sizes (object method)');
  is_deeply($sig->sizes('SLH-DSA-SHA2-256s'), $s, 'sizes ignores explicit alg on object');

  # advertised sizes match what the module actually produces/accepts
  is(length($sig->export_key_raw('public')),  $s->{public_key},  'sizes public_key matches export_key_raw');
  is(length($sig->export_key_raw('private')), $s->{private_key}, 'sizes private_key matches export_key_raw');
  is(length($sig->sign_message('msg')),       $s->{signature},   'sizes signature matches sign_message');
  ok(eval { $sig->sign_message_ex('msg', undef, 'R' x $s->{optrand}); 1 },              'sizes optrand accepted by sign_message_ex');
  ok(eval { $sig->make_key_from_seed('S' x $s->{keygen_seed}, 'SLH-DSA-SHA2-128f') },   'sizes keygen_seed accepted by make_key_from_seed');

  eval { Crypt::PQ::SLHDSA->sizes('SLH-DSA-XX') };
  like($@, qr/invalid SLH-DSA algorithm/, 'sizes invalid alg error');
  eval { Crypt::PQ::SLHDSA->sizes };
  like($@, qr/undefined algorithm/, 'sizes undef alg error');
}

# supported_algorithms (LTC slhdsa_alg_name)
{
  my @PURE = (
    'SLH-DSA-SHA2-128s',  'SLH-DSA-SHA2-128f',
    'SLH-DSA-SHA2-192s',  'SLH-DSA-SHA2-192f',
    'SLH-DSA-SHA2-256s',  'SLH-DSA-SHA2-256f',
    'SLH-DSA-SHAKE-128s', 'SLH-DSA-SHAKE-128f',
    'SLH-DSA-SHAKE-192s', 'SLH-DSA-SHAKE-192f',
    'SLH-DSA-SHAKE-256s', 'SLH-DSA-SHAKE-256f',
  );
  my @HASH = (
    'HashSLH-DSA-SHA2-128s-with-SHA256',     'HashSLH-DSA-SHA2-128f-with-SHA256',
    'HashSLH-DSA-SHA2-192s-with-SHA512',     'HashSLH-DSA-SHA2-192f-with-SHA512',
    'HashSLH-DSA-SHA2-256s-with-SHA512',     'HashSLH-DSA-SHA2-256f-with-SHA512',
    'HashSLH-DSA-SHAKE-128s-with-SHAKE128',  'HashSLH-DSA-SHAKE-128f-with-SHAKE128',
    'HashSLH-DSA-SHAKE-192s-with-SHAKE256',  'HashSLH-DSA-SHAKE-192f-with-SHAKE256',
    'HashSLH-DSA-SHAKE-256s-with-SHAKE256',  'HashSLH-DSA-SHAKE-256f-with-SHAKE256',
  );
  my @expected = (@PURE, @HASH);
  my @got = Crypt::PQ::SLHDSA->supported_algorithms;
  is_deeply(\@got, \@expected, 'supported_algorithms (class method)');
  is(scalar(@got), 24, 'supported_algorithms returns all 24 parameter sets');
  is_deeply([Crypt::PQ::SLHDSA::supported_algorithms()], \@expected, 'supported_algorithms (plain function)');
  is_deeply([sort @PURE], [sort keys %SIZES], 'the twelve pure names match the FIPS 205 size table above');
  is(scalar(grep { /^HashSLH-DSA-/ } @got), 12, 'twelve HashSLH-DSA (pre-hash) names are included');

  my $sig = Crypt::PQ::SLHDSA->new;
  is_deeply([$sig->supported_algorithms], \@expected, 'supported_algorithms (object method, no key)');
  $sig->generate_key('SLH-DSA-SHA2-128f');
  is_deeply([$sig->supported_algorithms], \@expected, 'supported_algorithms (object method) is not the loaded alg');

  # every advertised name is accepted where a parameter set is expected
  ok(Crypt::PQ::SLHDSA->sizes($_), "$_: advertised name accepted by sizes") for @got;

  # a HashSLH-DSA set has the same key/signature sizes as the pure set it wraps
  for my $h (@HASH) {
    (my $pure = $h) =~ s/^Hash//;
    $pure =~ s/-with-.*\z//;
    is_deeply(Crypt::PQ::SLHDSA->sizes($h), Crypt::PQ::SLHDSA->sizes($pure), "$h: sizes match $pure");
  }

  # keygen/sign/verify on one of the fast HashSLH-DSA sets
  my $hs = Crypt::PQ::SLHDSA->new;
  $hs->generate_key('HashSLH-DSA-SHAKE-128f-with-SHAKE128');
  is($hs->algorithm, 'HashSLH-DSA-SHAKE-128f-with-SHAKE128', 'HashSLH-DSA: generate_key/algorithm round-trip');
  my $sv = $hs->sign_message('the message we are signing');
  is($hs->verify_message($sv, 'the message we are signing'), 1, 'HashSLH-DSA: sign/verify round-trip');
}

# JWK per draft-ietf-cose-sphincs-plus (kty=AKP, priv = full 64-byte private key,
# and only the two NIST category 1 "small" parameter sets have a registered alg)
SKIP: {
  skip "JSON module not installed", 38 unless eval { require JSON };

    for my $alg ('SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s') {
      my $s = Crypt::PQ::SLHDSA->new;
      $s->generate_key($alg);
      my $pub_raw  = $s->export_key_raw('public');
      my $priv_raw = $s->export_key_raw('private');

      my $priv_h = $s->export_key_jwk('private', 1);
      my $pub_h  = $s->export_key_jwk('public',  1);
      is($priv_h->{kty}, 'AKP', "$alg: kty is AKP");
      is($priv_h->{alg}, $alg,  "$alg: alg names the parameter set");
      is(Crypt::Misc::decode_b64u($priv_h->{pub}),  $pub_raw,  "$alg: pub is PK.seed||PK.root");
      is(Crypt::Misc::decode_b64u($priv_h->{priv}), $priv_raw, "$alg: priv is the full private key");
      is(length(Crypt::Misc::decode_b64u($priv_h->{pub})),  32, "$alg: pub is 32 bytes");
      is(length(Crypt::Misc::decode_b64u($priv_h->{priv})), 64, "$alg: priv is 64 bytes");
      is_deeply([sort keys %$pub_h], [qw(alg kty pub)], "$alg: public JWK has no priv");

      for my $src (['json', \($s->export_key_jwk('private'))], ['hashref', $priv_h]) {
        my ($label, $arg) = @$src;
        my $back = Crypt::PQ::SLHDSA->new($arg);
        is($back->export_key_raw('private'), $priv_raw, "$alg: $label private round-trips");
        is($back->is_private, 1, "$alg: $label is_private");
      }
      my $back_pub = Crypt::PQ::SLHDSA->new($pub_h);
      is($back_pub->export_key_raw('public'), $pub_raw, "$alg: public JWK round-trips");
      is($back_pub->is_private, 0, "$alg: public JWK is not private");
      is($back_pub->verify_message($s->sign_message('msg'), 'msg'), 1,
         "$alg: JWK-imported public key verifies");
      is($s->export_key_jwk_thumbprint, $back_pub->export_key_jwk_thumbprint,
         "$alg: thumbprint matches");
    }

    # every other parameter set has no registered alg
    for my $alg ('SLH-DSA-SHA2-128f', 'SLH-DSA-SHAKE-256f',
                 'HashSLH-DSA-SHA2-128s-with-SHA256') {
      my $s = Crypt::PQ::SLHDSA->new;
      $s->generate_key($alg);
      eval { $s->export_key_jwk('public') };
      like($@, qr/no 'alg' is registered for \Q$alg\E/, "$alg: no JWK encoding");
    }

    my $s = Crypt::PQ::SLHDSA->new;
    $s->generate_key('SLH-DSA-SHA2-128s');
    eval { $s->export_key_jwk('private_seed') };
    like($@, qr/invalid type/, 'no private_* variants');
    eval { Crypt::PQ::SLHDSA->new({kty=>'OKP', alg=>'SLH-DSA-SHA2-128s', pub=>'AA'}) };
    like($@, qr/unsupported JWK kty 'OKP'/, 'wrong kty rejected');
    eval { Crypt::PQ::SLHDSA->new({kty=>'AKP', pub=>'AA'}) };
    like($@, qr/missing 'alg'/, 'missing alg rejected');
    eval { Crypt::PQ::SLHDSA->new({kty=>'AKP', alg=>'SLH-DSA-SHA2-128s'}) };
    like($@, qr/missing 'pub'/, 'missing pub rejected');
    eval { Crypt::PQ::SLHDSA->new({foo=>1}) };
    like($@, qr/unexpected SLH-DSA key hash/, 'hashref without kty rejected');
}

### password-protected PEM export is refused rather than writing an unreadable file
{
  my $gen = sub { my $k=Crypt::PQ::SLHDSA->new; $k->generate_key("SLH-DSA-SHA2-128f"); $k };
  my $k = $gen->();
  my $ref = $k->export_key_der('private');

  # unencrypted export is unaffected
  my $plain = $k->export_key_pem('private');
  like($plain, qr/^-----BEGIN PRIVATE KEY-----/, 'unencrypted PEM keeps the PRIVATE KEY label');
  unlike($plain, qr/Proc-Type|DEK-Info/, 'RFC 7468 permits no PEM headers');
  is(Crypt::PQ::SLHDSA->new(\$plain)->export_key_der('private'), $ref, 'unencrypted PEM round-trips');
  ok($k->export_key_pem('public'), 'public PEM is unaffected');

  # a password croaks instead of producing something nothing can read
  eval { $k->export_key_pem('private', 'secret') };
  like($@, qr/password-protected PEM is not supported/, 'password croaks');
  eval { $k->export_key_pem('private', 'secret', 'AES-128-CBC') };
  like($@, qr/password-protected PEM is not supported/, 'password + cipher croaks');
  eval { $k->export_key_pem('private', '') };
  like($@, qr/password-protected PEM is not supported/, 'even an empty password croaks');

  # reading an externally produced ENCRYPTED PRIVATE KEY is a separate path and stays supported
  ok(Crypt::PQ::SLHDSA->can('import_key'), 'import_key still available for reading encrypted keys');
}
