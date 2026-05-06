use strict;
use warnings;

use Test::More tests => 116;

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

