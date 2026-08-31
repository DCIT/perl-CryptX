use strict;
use warnings;

use Test::More tests => 297;

use Crypt::PQ::MLDSA;
use Crypt::Misc qw(read_rawfile);

my @ALGS = ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87');
my %SIZES = (
    'ML-DSA-44' => { pk => 1312, sk => 2560, sig => 2420 },
    'ML-DSA-65' => { pk => 1952, sk => 4032, sig => 3309 },
    'ML-DSA-87' => { pk => 2592, sk => 4896, sig => 4627 },
);

for my $alg (@ALGS) {
  my $sig = Crypt::PQ::MLDSA->new;
  isa_ok($sig, 'Crypt::PQ::MLDSA', "$alg: new");
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
  is($sig->verify_message($sigval, $msg . 'x'), 0,     "$alg: verify fails (msg)");

  # verify with imported public key
  my $pub_pem = $sig->export_key_pem('public');
  like($pub_pem, qr/-----BEGIN PUBLIC KEY-----/, "$alg: pub PEM header");
  my $verifier = Crypt::PQ::MLDSA->new(\$pub_pem);
  is($verifier->algorithm, $alg, "$alg: pub PEM import alg");
  is($verifier->is_private, 0,   "$alg: pub PEM is_private==0");
  is($verifier->verify_message($sigval, $msg), 1, "$alg: pub-only verify ok");

  # priv PEM round-trip
  my $priv_pem = $sig->export_key_pem('private');
  like($priv_pem, qr/-----BEGIN PRIVATE KEY-----/, "$alg: priv PEM header");
  my $sig2 = Crypt::PQ::MLDSA->new(\$priv_pem);
  is($sig2->algorithm, $alg, "$alg: priv PEM import alg");
  my $sigval2 = $sig2->sign_message($msg);
  is($sig->verify_message($sigval2, $msg), 1, "$alg: imported priv signs valid signature");

  # context
  my $ctx = "my-context";
  my $sig_ctx = $sig->sign_message($msg, $ctx);
  isnt($sig_ctx, $sigval, "$alg: ctx changes signature");
  is($sig->verify_message($sig_ctx, $msg, $ctx), 1,         "$alg: ctx verify ok");
  is($sig->verify_message($sig_ctx, $msg),       0,         "$alg: ctx verify fails w/o ctx");
  is($sig->verify_message($sig_ctx, $msg, "wrong"), 0,      "$alg: ctx verify fails w/wrong ctx");
  is($sig->verify_message($sigval, $msg, $ctx),  0,         "$alg: empty-ctx sig fails with non-empty ctx");

  # sign_message_ex: deterministic with fixed rnd
  my $rnd = "\0" x 32;
  my $sig_d1 = $sig->sign_message_ex($msg, undef, $rnd);
  my $sig_d2 = $sig->sign_message_ex($msg, undef, $rnd);
  is($sig_d1, $sig_d2,                                       "$alg: sign_message_ex deterministic with rnd=0");
  is($sig->verify_message($sig_d1, $msg), 1,                 "$alg: sign_message_ex output verifies");
  my $sig_d_ctx = $sig->sign_message_ex($msg, $ctx, $rnd);
  is($sig->verify_message($sig_d_ctx, $msg, $ctx), 1,        "$alg: sign_message_ex with ctx verifies");
  isnt($sig_d_ctx, $sig_d1,                                  "$alg: ctx changes deterministic sig");

  # sign_message_ex_mu: external-mu signing, mu must be 64 bytes
  my $mu = "\xCC" x 64;
  my $sig_mu1 = $sig->sign_message_ex_mu($mu, $rnd);
  my $sig_mu2 = $sig->sign_message_ex_mu($mu, $rnd);
  is($sig_mu1, $sig_mu2,                                     "$alg: sign_message_ex_mu deterministic");
  ok(length($sig_mu1) == $SIZES{$alg}{sig},                  "$alg: sign_message_ex_mu sig len");
  eval { $sig->sign_message_ex_mu("X" x 63, $rnd) };
  like($@, qr/mu must be exactly 64 bytes/,                  "$alg: sign_message_ex_mu rejects bad mu length");

  # raw round-trip
  my $sig_rp = Crypt::PQ::MLDSA->new;
  $sig_rp->import_key_raw($priv_raw, 'private', $alg);
  is($sig_rp->algorithm, $alg, "$alg: raw priv import alg");
  is($sig_rp->export_key_raw('private'), $priv_raw, "$alg: raw priv round-trip");
  is($sig_rp->export_key_raw('public'),  $pub_raw,  "$alg: raw priv yields pub");
  my $sigval3 = $sig_rp->sign_message($msg);
  is($sig->verify_message($sigval3, $msg), 1, "$alg: raw imported priv sigs verify");

  my $sig_ru = Crypt::PQ::MLDSA->new;
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
  my $sig = Crypt::PQ::MLDSA->new;
  eval { $sig->generate_key('ML-DSA-XX') };
  like($@, qr/invalid ML-DSA algorithm/, 'invalid alg error');

  $sig->generate_key('ML-DSA-44');
  eval { $sig->sign_message('msg', 'x' x 256) };
  like($@, qr/context must be at most 255 bytes/, 'context too long');
}


# sizes (LTC mldsa_get_sizes)
{
  for my $alg (@ALGS) {
    is_deeply(Crypt::PQ::MLDSA->sizes($alg), {
      public_key  => $SIZES{$alg}{pk},
      private_key => $SIZES{$alg}{sk},
      signature   => $SIZES{$alg}{sig},
      keygen_seed => 32,
      rnd         => 32,
      mu          => 64,
    }, "$alg: sizes (class method)");
  }
  is_deeply(Crypt::PQ::MLDSA::sizes('ML-DSA-65'), Crypt::PQ::MLDSA->sizes('ML-DSA-65'), 'sizes (plain function)');
  is_deeply(Crypt::PQ::MLDSA->sizes('2.16.840.1.101.3.4.3.18'), Crypt::PQ::MLDSA->sizes('ML-DSA-65'), 'sizes (by OID)');

  my $sig = Crypt::PQ::MLDSA->new;
  is($sig->sizes, undef, 'sizes on empty object == undef');
  $sig->generate_key('ML-DSA-65');
  is_deeply($sig->sizes, Crypt::PQ::MLDSA->sizes('ML-DSA-65'), 'sizes (object method)');
  is_deeply($sig->sizes('ML-DSA-44'), Crypt::PQ::MLDSA->sizes('ML-DSA-65'), 'sizes ignores explicit alg on object');

  # advertised sizes match what the module actually produces/accepts
  my $s = $sig->sizes;
  is(length($sig->export_key_raw('public')),  $s->{public_key},  'sizes public_key matches export_key_raw');
  is(length($sig->export_key_raw('private')), $s->{private_key}, 'sizes private_key matches export_key_raw');
  is(length($sig->sign_message('msg')),       $s->{signature},   'sizes signature matches sign_message');
  ok(eval { $sig->sign_message_ex('msg', undef, 'R' x $s->{rnd}); 1 },              'sizes rnd accepted by sign_message_ex');
  ok(eval { $sig->sign_message_ex_mu('M' x $s->{mu}, 'R' x $s->{rnd}); 1 },         'sizes mu/rnd accepted by sign_message_ex_mu');
  ok(eval { $sig->make_key_from_seed('S' x $s->{keygen_seed}, 'ML-DSA-65') },       'sizes keygen_seed accepted by make_key_from_seed');

  eval { Crypt::PQ::MLDSA->sizes('ML-DSA-XX') };
  like($@, qr/invalid ML-DSA algorithm/, 'sizes invalid alg error');
  eval { Crypt::PQ::MLDSA->sizes };
  like($@, qr/undefined algorithm/, 'sizes undef alg error');
}

# supported_algorithms (LTC mldsa_alg_name)
{
  my @expected = ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87');
  is_deeply([Crypt::PQ::MLDSA->supported_algorithms], \@expected, 'supported_algorithms (class method)');
  is_deeply([Crypt::PQ::MLDSA::supported_algorithms()], \@expected, 'supported_algorithms (plain function)');
  is_deeply([sort @expected], [sort @ALGS], 'supported_algorithms covers the algs exercised above');

  my $sig = Crypt::PQ::MLDSA->new;
  is_deeply([$sig->supported_algorithms], \@expected, 'supported_algorithms (object method, no key)');
  $sig->generate_key('ML-DSA-44');
  is_deeply([$sig->supported_algorithms], \@expected, 'supported_algorithms (object method) is not the loaded alg');

  # every advertised name is actually usable
  for my $alg (Crypt::PQ::MLDSA->supported_algorithms) {
    my $k = Crypt::PQ::MLDSA->new;
    $k->generate_key($alg);
    is($k->algorithm, $alg, "$alg: advertised name round-trips through generate_key/algorithm");
    ok(Crypt::PQ::MLDSA->sizes($alg), "$alg: advertised name accepted by sizes");
  }
}

# External-mu: compute_mu / sign_mu / verify_mu (RFC 9881)
{
  my $msg = 'the message we are signing';
  my $ctxs = 'application-context';

  for my $alg (@ALGS) {
    my $sig = Crypt::PQ::MLDSA->new;
    $sig->generate_key($alg);

    # one-shot mu
    my $mu = $sig->compute_mu($msg);
    is(length($mu), 64, "$alg: compute_mu returns 64 bytes");

    # ... and with a context string
    my $mu_c = $sig->compute_mu($msg, $ctxs);
    isnt($mu_c, $mu, "$alg: context changes mu");

    # sign_mu produces an ordinary ML-DSA signature
    my $sigval = $sig->sign_mu($mu);
    is(length($sigval), $SIZES{$alg}{sig}, "$alg: sign_mu signature length");
    is($sig->verify_message($sigval, $msg), 1, "$alg: sign_mu verifies with plain verify_message");
    is($sig->verify_mu($sigval, $mu), 1,       "$alg: sign_mu verifies with verify_mu");
    is($sig->verify_message($sigval, 'other'), 0, "$alg: sign_mu rejects a different message");
    is($sig->verify_mu($sigval, $mu_c), 0,        "$alg: sign_mu rejects a different mu");

    # signing is hedged: same mu, different signatures, both valid
    my $sigval2 = $sig->sign_mu($mu);
    isnt($sigval2, $sigval, "$alg: sign_mu is hedged (differs across calls)");
    is($sig->verify_mu($sigval2, $mu), 1, "$alg: second hedged signature also verifies");

    # a context-bound signature needs the same context at verification time
    my $sigval_c = $sig->sign_mu($mu_c);
    is($sig->verify_message($sigval_c, $msg, $ctxs), 1, "$alg: context signature verifies with context");
    is($sig->verify_message($sigval_c, $msg), 0,        "$alg: context signature fails without context");

    # a public key is enough to compute mu and to verify
    my $pub_der = $sig->export_key_der('public');
    my $ver = Crypt::PQ::MLDSA->new(\$pub_der);
    is($ver->compute_mu($msg), $mu, "$alg: public key computes the same mu");
    is($ver->verify_mu($sigval, $mu), 1, "$alg: public key verifies via verify_mu");
    eval { $ver->sign_mu($mu) };
    like($@, qr/not a private key/, "$alg: sign_mu on a public key croaks");

    # mu of a key is bound to that key
    my $other = Crypt::PQ::MLDSA->new;
    $other->generate_key($alg);
    isnt($other->compute_mu($msg), $mu, "$alg: mu is bound to the key");
    is($other->verify_mu($sigval, $mu), 0, "$alg: another key does not verify this signature");
  }

  # empty message and empty context are accepted and distinct from the non-empty ones
  my $sig = Crypt::PQ::MLDSA->new;
  $sig->generate_key('ML-DSA-44');
  my $mu_empty = $sig->compute_mu('');
  is(length($mu_empty), 64, 'compute_mu of the empty message');
  is($sig->compute_mu($msg, ''), $sig->compute_mu($msg), 'empty context == no context');
  is($sig->verify_mu($sig->sign_mu($mu_empty), $mu_empty), 1, 'empty message signature verifies');

  # a long message still round-trips through compute_mu/sign_mu
  my $whole = 'x' x 5000;
  my $mu_whole = $sig->compute_mu($whole);
  is($sig->verify_mu($sig->sign_mu($mu_whole), $mu_whole), 1, 'long message signature verifies');

  # error cases
  {
    my $mu = $sig->compute_mu($msg);
    eval { $sig->sign_mu(substr($mu, 0, 63)) };
    like($@, qr/mu must be exactly 64 bytes/, 'sign_mu rejects a short mu');
    eval { $sig->sign_mu(undef) };
    like($@, qr/mu must be string/, 'sign_mu rejects undef mu');
    eval { $sig->compute_mu($msg, 'x' x 256) };
    like($@, qr/context must be at most 255 bytes/, 'compute_mu rejects an over-long context');
    is($sig->verify_mu($sig->sign_mu($mu), substr($mu, 0, 63)), 0, 'verify_mu rejects a short mu');

    my $empty = Crypt::PQ::MLDSA->new;
    eval { $empty->compute_mu($msg) };
    like($@, qr/no key loaded/, 'compute_mu without a key croaks');
    eval { $empty->sign_mu($mu) };
    like($@, qr/no key loaded/, 'sign_mu without a key croaks');
    eval { $empty->verify_mu('x', $mu) };
    like($@, qr/no key loaded/, 'verify_mu without a key croaks');
  }
}

# magical SVs: a value passed straight from substr() must not look undefined
# (SvOK() alone does not fetch get-magic)
{
  my $sig = Crypt::PQ::MLDSA->new;
  $sig->generate_key('ML-DSA-44');
  my $msg = 'the message we are signing';
  my $ctxs = 'application-context';

  my $mu_buf  = $sig->compute_mu($msg, $ctxs) . 'trailing junk';
  my $ctx_buf = $ctxs . 'trailing junk';
  my $mu  = substr($mu_buf,  0, 64);
  my $len = length $ctxs;

  is($sig->compute_mu($msg, substr($ctx_buf, 0, $len)), $sig->compute_mu($msg, $ctxs),
     'compute_mu honours a substr() context');

  my $sigval = eval { $sig->sign_mu(substr($mu_buf, 0, 64)) };
  is($@, '', 'sign_mu accepts a substr() mu');
  is($sig->verify_mu($sigval, $mu), 1, 'signature over a substr() mu verifies');
  is($sig->verify_message($sigval, $msg, substr($ctx_buf, 0, $len)), 1,
     'verify_message honours a substr() context');

  ok(eval { $sig->sign_message_ex_mu(substr($mu_buf, 0, 64), 'R' x 32); 1 },
     'sign_message_ex_mu accepts a substr() mu');
  ok(eval { Crypt::PQ::MLDSA->new->make_key_from_seed(substr(('S' x 32) . 'junk', 0, 32), 'ML-DSA-44') },
     'make_key_from_seed accepts a substr() seed');
}

# seed-form private key export/import (LTC *_export_ex / *_export_seed)
{
  my $k = Crypt::PQ::MLDSA->new;
  $k->generate_key('ML-DSA-65');
  is($k->has_seed, 1, 'generated key has a seed');
  is(Crypt::PQ::MLDSA->new->has_seed, undef, 'has_seed on an empty object == undef');

  my $seed = $k->export_key_raw('seed');
  is(length($seed), 32, 'export_key_raw(seed) length');
  is($k->key2hash->{seed}, unpack('H*', $seed), 'key2hash seed matches export_key_raw(seed)');

  # the seed really is the generation seed
  my $reseeded = Crypt::PQ::MLDSA->new;
  $reseeded->make_key_from_seed($seed, 'ML-DSA-65');
  is($reseeded->export_key_raw('private'), $k->export_key_raw('private'),
     'seed regenerates the same key');

  # each encoding has its own size, and 'private' follows the seed
  my %der = map { $_ => $k->export_key_der($_) } qw(private private_seed private_expanded private_both);
  is(length($der{private_seed}),     54, 'private_seed DER length');
  is(length($der{private_expanded}), 4060,  'private_expanded DER length');
  is(length($der{private_both}),     4098, 'private_both DER length');
  is($der{private}, $der{private_seed}, "'private' == 'private_seed' for a seeded key");

  # all four re-import to the same key material
  my $sk = $k->export_key_raw('private');
  for my $t (sort keys %der) {
    my $back = Crypt::PQ::MLDSA->new(\$der{$t});
    is($back->export_key_raw('private'), $sk, "$t: DER round-trip");
    is($back->has_seed, ($t eq 'private_expanded' ? 0 : 1), "$t: has_seed after re-import");
    is($back->export_key_raw('seed'), $seed, "$t: seed survives") if $t ne 'private_expanded';
  }

  # PEM works for the named forms too, same header
  for my $t (qw(private_seed private_expanded private_both)) {
    my $pem = $k->export_key_pem($t);
    like($pem, qr/-----BEGIN PRIVATE KEY-----/, "$t: PEM header");
    is(Crypt::PQ::MLDSA->new(\$pem)->export_key_raw('private'), $sk, "$t: PEM round-trip");
  }

  # a key with no seed: 'private' falls back, seed forms croak
  my $raw = Crypt::PQ::MLDSA->new;
  $raw->import_key_raw($sk, 'private', 'ML-DSA-65');
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

# JWK per RFC 9964 "ML-DSA for JOSE and COSE"
SKIP: {
  skip "JSON module not installed", 41 unless eval { require JSON };

    my $k = Crypt::PQ::MLDSA->new;
    $k->generate_key('ML-DSA-65');
    my $pub_raw = $k->export_key_raw('public');
    my $seed    = $k->export_key_raw('seed');

    my $priv_h = $k->export_key_jwk('private', 1);
    my $pub_h  = $k->export_key_jwk('public',  1);

    is($priv_h->{kty}, 'AKP',        'kty is AKP');
    is($priv_h->{alg}, 'ML-DSA-65',  'alg names the parameter set');
    is(Crypt::Misc::decode_b64u($priv_h->{pub}),  $pub_raw, 'pub is the FIPS 204 public key');
    is(Crypt::Misc::decode_b64u($priv_h->{priv}), $seed,    'priv is the seed');
    is(length(Crypt::Misc::decode_b64u($priv_h->{priv})), 32, 'priv is 32 bytes');
    is_deeply([sort keys %$priv_h], [qw(alg kty priv pub)], 'private JWK members');
    is_deeply([sort keys %$pub_h],  [qw(alg kty pub)],      'public JWK has no priv');

    # JSON form
    my $json = $k->export_key_jwk('private');
    unlike($json, qr/\s/, 'JWK JSON is compact');
    like($json, qr/"kty":"AKP"/, 'JWK JSON carries kty');

    # round-trips: JSON, hashref, public
    for my $src (['json private', \$json], ['json public', \($k->export_key_jwk('public'))],
                 ['hashref private', $priv_h], ['hashref public', $pub_h]) {
      my ($label, $arg) = @$src;
      my $back = Crypt::PQ::MLDSA->new($arg);
      is($back->export_key_raw('public'), $pub_raw, "$label: public key round-trips");
      my $want_priv = $label =~ /private/ ? 1 : 0;
      is($back->is_private, $want_priv, "$label: is_private");
      is($back->has_seed,   $want_priv, "$label: has_seed");
      is($back->export_key_raw('seed'), $seed, "$label: seed round-trips") if $want_priv;
    }

    # a signature made from a JWK-imported key verifies against the original
    my $from_jwk = Crypt::PQ::MLDSA->new($priv_h);
    is($k->verify_message($from_jwk->sign_message('msg'), 'msg'), 1,
       'signature from a JWK-imported key verifies');

    # thumbprint over kty+alg+pub only
    my $tp = $k->export_key_jwk_thumbprint;
    is($tp, Crypt::PQ::MLDSA->new($pub_h)->export_key_jwk_thumbprint,
       'thumbprint is the same from the public JWK');
    is($tp, Crypt::Misc::encode_b64u(Crypt::Digest::digest_data('SHA256',
         CryptX::_encode_json({alg=>'ML-DSA-65', kty=>'AKP', pub=>$pub_h->{pub}}))),
       'thumbprint is RFC 7638 over kty/alg/pub');
    isnt($tp, $k->export_key_jwk_thumbprint('SHA512'), 'thumbprint honours the hash argument');

    # RFC 9964 has no expanded-private encoding: a seedless key cannot be exported
    my $raw = Crypt::PQ::MLDSA->new;
    $raw->import_key_raw($k->export_key_raw('private'), 'private', 'ML-DSA-65');
    is($raw->has_seed, 0, 'raw-imported key has no seed');
    eval { $raw->export_key_jwk('private') };
    like($@, qr/needs a key with a seed/, 'private JWK croaks without a seed');
    ok($raw->export_key_jwk('public'), 'public JWK still works without a seed');

    # no private_* variants here, unlike export_key_der
    for my $t (qw(private_seed private_expanded private_both bogus)) {
      eval { $k->export_key_jwk($t) };
      like($@, qr/invalid type/, "export_key_jwk('$t') croaks");
    }
    eval { $k->export_key_jwk };
    like($@, qr/invalid type/, 'export_key_jwk with no type croaks');

    # import validation
    my $good_pub = Crypt::Misc::encode_b64u($pub_raw);
    eval { Crypt::PQ::MLDSA->new({kty=>'OKP', alg=>'ML-DSA-65', pub=>$good_pub}) };
    like($@, qr/unsupported JWK kty 'OKP'/, 'wrong kty rejected');
    eval { Crypt::PQ::MLDSA->new({kty=>'AKP', pub=>$good_pub}) };
    like($@, qr/missing 'alg'/, 'missing alg rejected');
    eval { Crypt::PQ::MLDSA->new({kty=>'AKP', alg=>'ML-DSA-65'}) };
    like($@, qr/missing 'pub'/, 'missing pub rejected (pub is REQUIRED)');
    eval { Crypt::PQ::MLDSA->new({kty=>'AKP', alg=>'ML-DSA-65', pub=>$good_pub,
                                  priv=>Crypt::Misc::encode_b64u('x' x 31)}) };
    like($@, qr/must be a 32-byte seed/, 'short priv rejected');
    eval { Crypt::PQ::MLDSA->new({kty=>'AKP', alg=>'ML-DSA-65',
                                  pub=>Crypt::Misc::encode_b64u(substr($pub_raw,0,-1).'X'),
                                  priv=>$priv_h->{priv}}) };
    like($@, qr/does not match the key derived from 'priv'/, 'pub inconsistent with priv rejected');
    eval { Crypt::PQ::MLDSA->new({foo=>1}) };
    like($@, qr/unexpected ML-DSA key hash/, 'hashref without kty rejected');
}

### password-protected PEM export is refused rather than writing an unreadable file
{
  my $gen = sub { my $k=Crypt::PQ::MLDSA->new; $k->generate_key("ML-DSA-44"); $k };
  my $k = $gen->();
  my $ref = $k->export_key_der('private');

  # unencrypted export is unaffected
  my $plain = $k->export_key_pem('private');
  like($plain, qr/^-----BEGIN PRIVATE KEY-----/, 'unencrypted PEM keeps the PRIVATE KEY label');
  unlike($plain, qr/Proc-Type|DEK-Info/, 'RFC 7468 permits no PEM headers');
  is(Crypt::PQ::MLDSA->new(\$plain)->export_key_der('private'), $ref, 'unencrypted PEM round-trips');
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
  ok(Crypt::PQ::MLDSA->can('import_key'), 'import_key still available for reading encrypted keys');
}
