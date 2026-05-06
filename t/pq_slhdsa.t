use strict;
use warnings;

use Test::More tests => 62;

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

