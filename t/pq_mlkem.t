use strict;
use warnings;

use Test::More tests => 100;

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

