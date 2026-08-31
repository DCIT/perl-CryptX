use strict;
use warnings;

use Test::More tests => 204;

use Crypt::PQ::MLKEM;
use Crypt::Misc qw(read_rawfile);

my @ALGS = ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024');
my %SIZES = (
    'ML-KEM-512'  => { pk =>  800, sk => 1632 },
    'ML-KEM-768'  => { pk => 1184, sk => 2400 },
    'ML-KEM-1024' => { pk => 1568, sk => 3168 },
);

for my $alg (@ALGS) {
  # generate_key + sizes + algorithm
  my $kem = Crypt::PQ::MLKEM->new;
  isa_ok($kem, 'Crypt::PQ::MLKEM', "$alg: new");
  is($kem->is_private, undef, "$alg: empty obj is_private==undef");
  is($kem->algorithm,  undef, "$alg: empty obj algorithm==undef");

  $kem->generate_key($alg);
  is($kem->algorithm, $alg,    "$alg: algorithm");
  is($kem->is_private, 1,      "$alg: generated key is private");

  my $pub_raw  = $kem->export_key_raw('public');
  my $priv_raw = $kem->export_key_raw('private');
  is(length($pub_raw),  $SIZES{$alg}{pk}, "$alg: pub raw len");
  is(length($priv_raw), $SIZES{$alg}{sk}, "$alg: priv raw len");

  # encapsulate / decapsulate
  my ($ct, $ss_a) = $kem->encapsulate;
  ok($ct,                "$alg: encapsulate returns ct");
  is(length($ss_a), 32,  "$alg: shared secret is 32 bytes");
  my $ss_b = $kem->decapsulate($ct);
  is($ss_a, $ss_b,       "$alg: round-trip shared secret");

  # PEM round-trip
  my $pub_pem  = $kem->export_key_pem('public');
  my $priv_pem = $kem->export_key_pem('private');
  like($pub_pem,  qr/-----BEGIN PUBLIC KEY-----/,  "$alg: pub PEM header");
  like($priv_pem, qr/-----BEGIN PRIVATE KEY-----/, "$alg: priv PEM header");

  my $kem_pub = Crypt::PQ::MLKEM->new(\$pub_pem);
  is($kem_pub->algorithm, $alg, "$alg: pub PEM import alg");
  is($kem_pub->is_private, 0,   "$alg: pub PEM import !is_private");

  my $kem_priv = Crypt::PQ::MLKEM->new(\$priv_pem);
  is($kem_priv->algorithm, $alg, "$alg: priv PEM import alg");
  is($kem_priv->is_private, 1,   "$alg: priv PEM import is_private");

  # peer encapsulates with our public key, we decapsulate
  my ($ct2, $ss_p) = $kem_pub->encapsulate;
  my $ss_q = $kem_priv->decapsulate($ct2);
  is($ss_p, $ss_q, "$alg: peer encaps + decaps");

  # raw round-trip
  my $kem_rp = Crypt::PQ::MLKEM->new;
  $kem_rp->import_key_raw($priv_raw, 'private', $alg);
  is($kem_rp->algorithm, $alg, "$alg: raw priv import alg");
  is($kem_rp->is_private, 1,   "$alg: raw priv is_private");
  is($kem_rp->export_key_raw('private'), $priv_raw, "$alg: raw priv round-trip");
  is($kem_rp->export_key_raw('public'),  $pub_raw,  "$alg: raw priv yields pub");

  my $kem_ru = Crypt::PQ::MLKEM->new;
  $kem_ru->import_key_raw($pub_raw, 'public', $alg);
  is($kem_ru->algorithm, $alg, "$alg: raw pub import alg");
  is($kem_ru->is_private, 0,   "$alg: raw pub !is_private");
  is($kem_ru->export_key_raw('public'), $pub_raw, "$alg: raw pub round-trip");

  # invalid ciphertext to decapsulate -> implicit rejection (no error, value differs)
  my $bogus_ct = "\x00" x length($ct);
  my $ss_bogus = $kem->decapsulate($bogus_ct);
  is(length($ss_bogus), 32,           "$alg: bogus ct -> 32-byte ss (implicit rejection)");
  isnt($ss_bogus, $ss_a,              "$alg: bogus ct ss differs from real");

  # encapsulate_ex: deterministic with fixed entropy m
  my $m = "A" x 32;
  my ($ct_d1, $ss_d1) = $kem->encapsulate_ex($m);
  my ($ct_d2, $ss_d2) = $kem->encapsulate_ex($m);
  is($ct_d1, $ct_d2, "$alg: encapsulate_ex deterministic ct");
  is($ss_d1, $ss_d2, "$alg: encapsulate_ex deterministic ss");
  is($kem->decapsulate($ct_d1), $ss_d1, "$alg: encapsulate_ex round-trips through decapsulate");

  # key2hash
  my $h = $kem->key2hash;
  is($h->{alg}, $alg,                                "$alg: key2hash alg");
  is(length($h->{pub}),  $SIZES{$alg}{pk} * 2,       "$alg: key2hash pub hex");
  is(length($h->{priv}), $SIZES{$alg}{sk} * 2,       "$alg: key2hash priv hex");
}

# error cases
{
  my $kem = Crypt::PQ::MLKEM->new;
  eval { $kem->generate_key('ML-KEM-XXX') };
  like($@, qr/invalid ML-KEM algorithm/, 'invalid alg error');

  $kem->generate_key('ML-KEM-512');
  eval { $kem->encapsulate_ex("A" x 31) };
  like($@, qr/m must be exactly 32 bytes/, 'encapsulate_ex bad m length');
  eval { $kem->generate_key() };
  like($@, qr/undefined algorithm|Usage:/, 'undef alg error');
  eval { $kem->generate_key(undef) };
  like($@, qr/undefined algorithm/, 'undef alg error (explicit undef)');
}


# sizes (LTC mlkem_get_sizes)
{
  my %EXPECTED = (
    'ML-KEM-512'  => { public_key =>  800, private_key => 1632, ciphertext =>  768, shared_secret => 32, keygen_seed => 64, encaps_seed => 32 },
    'ML-KEM-768'  => { public_key => 1184, private_key => 2400, ciphertext => 1088, shared_secret => 32, keygen_seed => 64, encaps_seed => 32 },
    'ML-KEM-1024' => { public_key => 1568, private_key => 3168, ciphertext => 1568, shared_secret => 32, keygen_seed => 64, encaps_seed => 32 },
  );
  is_deeply(Crypt::PQ::MLKEM->sizes($_), $EXPECTED{$_}, "$_: sizes (class method)") for @ALGS;
  is_deeply(Crypt::PQ::MLKEM::sizes('ML-KEM-768'), $EXPECTED{'ML-KEM-768'}, 'sizes (plain function)');
  is_deeply(Crypt::PQ::MLKEM->sizes('2.16.840.1.101.3.4.4.2'), $EXPECTED{'ML-KEM-768'}, 'sizes (by OID)');

  my $kem = Crypt::PQ::MLKEM->new;
  is($kem->sizes, undef, 'sizes on empty object == undef');
  $kem->generate_key('ML-KEM-768');
  is_deeply($kem->sizes, $EXPECTED{'ML-KEM-768'}, 'sizes (object method)');
  is_deeply($kem->sizes('ML-KEM-512'), $EXPECTED{'ML-KEM-768'}, 'sizes ignores explicit alg on object');

  # advertised sizes match what the module actually produces/accepts
  my $s = $kem->sizes;
  is(length($kem->export_key_raw('public')),  $s->{public_key},  'sizes public_key matches export_key_raw');
  is(length($kem->export_key_raw('private')), $s->{private_key}, 'sizes private_key matches export_key_raw');
  my ($ct, $ss) = $kem->encapsulate;
  is(length($ct), $s->{ciphertext},    'sizes ciphertext matches encapsulate');
  is(length($ss), $s->{shared_secret}, 'sizes shared_secret matches encapsulate');
  ok(eval { $kem->encapsulate_ex('M' x $s->{encaps_seed}); 1 }, 'sizes encaps_seed accepted by encapsulate_ex');
  ok(eval { $kem->make_key_from_seed('S' x $s->{keygen_seed}, 'ML-KEM-768') }, 'sizes keygen_seed accepted by make_key_from_seed');

  eval { Crypt::PQ::MLKEM->sizes('ML-KEM-XXX') };
  like($@, qr/invalid ML-KEM algorithm/, 'sizes invalid alg error');
  eval { Crypt::PQ::MLKEM->sizes };
  like($@, qr/undefined algorithm/, 'sizes undef alg error');
}

# supported_algorithms (LTC mlkem_alg_name)
{
  my @expected = ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024');
  is_deeply([Crypt::PQ::MLKEM->supported_algorithms], \@expected, 'supported_algorithms (class method)');
  is_deeply([Crypt::PQ::MLKEM::supported_algorithms()], \@expected, 'supported_algorithms (plain function)');
  is_deeply([sort @expected], [sort @ALGS], 'supported_algorithms covers the algs exercised above');

  my $kem = Crypt::PQ::MLKEM->new;
  is_deeply([$kem->supported_algorithms], \@expected, 'supported_algorithms (object method, no key)');
  $kem->generate_key('ML-KEM-512');
  is_deeply([$kem->supported_algorithms], \@expected, 'supported_algorithms (object method) is not the loaded alg');

  # every advertised name is actually usable
  for my $alg (Crypt::PQ::MLKEM->supported_algorithms) {
    my $k = Crypt::PQ::MLKEM->new;
    $k->generate_key($alg);
    is($k->algorithm, $alg, "$alg: advertised name round-trips through generate_key/algorithm");
    ok(Crypt::PQ::MLKEM->sizes($alg), "$alg: advertised name accepted by sizes");
  }
}

# seed-form private key export/import (LTC *_export_ex / *_export_seed)
{
  my $k = Crypt::PQ::MLKEM->new;
  $k->generate_key('ML-KEM-768');
  is($k->has_seed, 1, 'generated key has a seed');
  is(Crypt::PQ::MLKEM->new->has_seed, undef, 'has_seed on an empty object == undef');

  my $seed = $k->export_key_raw('seed');
  is(length($seed), 64, 'export_key_raw(seed) length');
  is($k->key2hash->{seed}, unpack('H*', $seed), 'key2hash seed matches export_key_raw(seed)');

  # the seed really is the generation seed
  my $reseeded = Crypt::PQ::MLKEM->new;
  $reseeded->make_key_from_seed($seed, 'ML-KEM-768');
  is($reseeded->export_key_raw('private'), $k->export_key_raw('private'),
     'seed regenerates the same key');

  # each encoding has its own size, and 'private' follows the seed
  my %der = map { $_ => $k->export_key_der($_) } qw(private private_seed private_expanded private_both);
  is(length($der{private_seed}),     86, 'private_seed DER length');
  is(length($der{private_expanded}), 2428,  'private_expanded DER length');
  is(length($der{private_both}),     2498, 'private_both DER length');
  is($der{private}, $der{private_seed}, "'private' == 'private_seed' for a seeded key");

  # all four re-import to the same key material
  my $sk = $k->export_key_raw('private');
  for my $t (sort keys %der) {
    my $back = Crypt::PQ::MLKEM->new(\$der{$t});
    is($back->export_key_raw('private'), $sk, "$t: DER round-trip");
    is($back->has_seed, ($t eq 'private_expanded' ? 0 : 1), "$t: has_seed after re-import");
    is($back->export_key_raw('seed'), $seed, "$t: seed survives") if $t ne 'private_expanded';
  }

  # PEM works for the named forms too, same header
  for my $t (qw(private_seed private_expanded private_both)) {
    my $pem = $k->export_key_pem($t);
    like($pem, qr/-----BEGIN PRIVATE KEY-----/, "$t: PEM header");
    is(Crypt::PQ::MLKEM->new(\$pem)->export_key_raw('private'), $sk, "$t: PEM round-trip");
  }

  # a key with no seed: 'private' falls back, seed forms croak
  my $raw = Crypt::PQ::MLKEM->new;
  $raw->import_key_raw($sk, 'private', 'ML-KEM-768');
  is($raw->has_seed, 0, 'raw-imported key has no seed');
  is($raw->key2hash->{seed}, undef, 'key2hash seed undef without a seed');
  is($raw->export_key_der('private'), $der{private_expanded},
     "'private' falls back to expanded without a seed");
  eval { $raw->export_key_der('private_seed') };
  like($@, qr/needs a key with a seed/, 'private_seed croaks without a seed');
  eval { $raw->export_key_der('private_both') };
  like($@, qr/needs a key with a seed/, 'private_both croaks without a seed');
  eval { $raw->export_key_raw('seed') };
  like($@, qr/no seed/, 'export_key_raw(seed) croaks without a seed');

  eval { $k->export_key_der('private_bogus') };
  like($@, qr/invalid type/, 'unknown private_* type croaks');
  eval { $k->export_key_raw('bogus') };
  like($@, qr/invalid type/, 'unknown raw type croaks');
}

# JWK per draft-ietf-jose-pqc-kem (kty=AKP, priv = 64-byte seed d || z)
SKIP: {
  skip "JSON module not installed", 29 unless eval { require JSON };

    my $k = Crypt::PQ::MLKEM->new;
    $k->generate_key('ML-KEM-768');
    my $pub_raw = $k->export_key_raw('public');
    my $seed    = $k->export_key_raw('seed');

    my $priv_h = $k->export_key_jwk('private', 1);
    my $pub_h  = $k->export_key_jwk('public',  1);
    is($priv_h->{kty}, 'AKP',       'kty is AKP');
    is($priv_h->{alg}, 'ML-KEM-768','alg names the parameter set');
    is(Crypt::Misc::decode_b64u($priv_h->{pub}),  $pub_raw, 'pub is the encapsulation key');
    is(Crypt::Misc::decode_b64u($priv_h->{priv}), $seed,    'priv is the seed d || z');
    is(length(Crypt::Misc::decode_b64u($priv_h->{priv})), 64, 'priv is 64 bytes');
    is_deeply([sort keys %$priv_h], [qw(alg kty priv pub)], 'private JWK members');
    is_deeply([sort keys %$pub_h],  [qw(alg kty pub)],      'public JWK has no priv');

    for my $src (['json private', \($k->export_key_jwk('private'))],
                 ['json public',  \($k->export_key_jwk('public'))],
                 ['hashref private', $priv_h], ['hashref public', $pub_h]) {
      my ($label, $arg) = @$src;
      my $back = Crypt::PQ::MLKEM->new($arg);
      is($back->export_key_raw('public'), $pub_raw, "$label: public key round-trips");
      my $want = $label =~ /private/ ? 1 : 0;
      is($back->is_private, $want, "$label: is_private");
      is($back->has_seed,   $want, "$label: has_seed");
      is($back->export_key_raw('seed'), $seed, "$label: seed round-trips") if $want;
    }

    # a JWK-imported private key decapsulates what the original encapsulates
    my $from_jwk = Crypt::PQ::MLKEM->new($priv_h);
    my ($ct, $ss) = $k->encapsulate;
    is($from_jwk->decapsulate($ct), $ss, 'JWK-imported key decapsulates correctly');

    is($k->export_key_jwk_thumbprint,
       Crypt::PQ::MLKEM->new($pub_h)->export_key_jwk_thumbprint, 'thumbprint from public JWK matches');

    # no seed -> no private JWK
    my $raw = Crypt::PQ::MLKEM->new;
    $raw->import_key_raw($k->export_key_raw('private'), 'private', 'ML-KEM-768');
    eval { $raw->export_key_jwk('private') };
    like($@, qr/needs a key with a seed/, 'private JWK croaks without a seed');
    ok($raw->export_key_jwk('public'), 'public JWK works without a seed');

    eval { $k->export_key_jwk('private_seed') };
    like($@, qr/invalid type/, 'no private_* variants');
    eval { Crypt::PQ::MLKEM->new({kty=>'OKP', alg=>'ML-KEM-768', pub=>'AA'}) };
    like($@, qr/unsupported JWK kty 'OKP'/, 'wrong kty rejected');
    eval { Crypt::PQ::MLKEM->new({kty=>'AKP', alg=>'ML-KEM-768',
             pub=>Crypt::Misc::encode_b64u($pub_raw), priv=>Crypt::Misc::encode_b64u('x' x 63)}) };
    like($@, qr/64-byte ML-KEM seed/, 'short priv rejected');
    eval { Crypt::PQ::MLKEM->new({foo=>1}) };
    like($@, qr/unexpected ML-KEM key hash/, 'hashref without kty rejected');
}

### password-protected PEM export is refused rather than writing an unreadable file
{
  my $gen = sub { my $k=Crypt::PQ::MLKEM->new; $k->generate_key("ML-KEM-512"); $k };
  my $k = $gen->();
  my $ref = $k->export_key_der('private');

  # unencrypted export is unaffected
  my $plain = $k->export_key_pem('private');
  like($plain, qr/^-----BEGIN PRIVATE KEY-----/, 'unencrypted PEM keeps the PRIVATE KEY label');
  unlike($plain, qr/Proc-Type|DEK-Info/, 'RFC 7468 permits no PEM headers');
  is(Crypt::PQ::MLKEM->new(\$plain)->export_key_der('private'), $ref, 'unencrypted PEM round-trips');
  ok($k->export_key_pem('public'), 'public PEM is unaffected');

  # a password croaks instead of producing something nothing can read
  eval { $k->export_key_pem('private', 'secret') };
  like($@, qr/password-protected PEM is not supported/, 'password croaks');
  eval { $k->export_key_pem('private', 'secret', 'AES-128-CBC') };
  like($@, qr/password-protected PEM is not supported/, 'password + cipher croaks');
  eval { $k->export_key_pem('private', '') };
  like($@, qr/password-protected PEM is not supported/, 'even an empty password croaks');
  eval { $k->export_key_pem('private_seed', 'secret') };
  like($@, qr/password-protected PEM is not supported/, "'private_seed' with a password croaks");
  ok($k->export_key_pem('private_seed'), "'private_seed' without a password still works");
  eval { $k->export_key_pem('private_expanded', 'secret') };
  like($@, qr/password-protected PEM is not supported/, "'private_expanded' with a password croaks");
  ok($k->export_key_pem('private_expanded'), "'private_expanded' without a password still works");
  eval { $k->export_key_pem('private_both', 'secret') };
  like($@, qr/password-protected PEM is not supported/, "'private_both' with a password croaks");
  ok($k->export_key_pem('private_both'), "'private_both' without a password still works");

  # reading an externally produced ENCRYPTED PRIVATE KEY is a separate path and stays supported
  ok(Crypt::PQ::MLKEM->can('import_key'), 'import_key still available for reading encrypted keys');
}
