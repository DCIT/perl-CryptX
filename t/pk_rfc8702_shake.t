use strict;
use warnings;

use Test::More tests => 16;

use Crypt::PK::RSA;
use Crypt::PK::ECC;

# RFC 8702: RSASSA-PSS with SHAKE128 / SHAKE256 and ECDSA with SHAKE128 / SHAKE256.
# RFC 8702 fixes the message-hash output to 32 bytes (SHAKE128) or 64 bytes (SHAKE256)
# and, for RSA-PSS, requires the salt length to equal the hash output length and the
# MGF to be SHAKE used directly (not MGF1). The libtomcrypt backend handles the
# MGF special case internally; in Perl you only need to pass 'SHAKE128' / 'SHAKE256'
# as the hash name.

# --- RSASSA-PSS-SHAKE128 / SHAKE256 -----------------------------------------
{
  my $priv = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa1.pem');
  my $pub  = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa1.pem');
  my $msg  = 'RFC 8702 test message';

  for my $cfg (['SHAKE128', 32], ['SHAKE256', 64]) {
    my ($h, $sl) = @$cfg;

    my $sig = eval { $priv->sign_message($msg, $h, 'pss', $sl) };
    diag("$@") if $@;
    ok($sig && length($sig) == 256, "RSA-PSS-$h sign_message (saltlen=$sl)");

    ok($pub->verify_message($sig, $msg, $h, 'pss', $sl), "RSA-PSS-$h verify_message");
    ok(!$pub->verify_message($sig, "$msg.tampered", $h, 'pss', $sl), "RSA-PSS-$h verify_message rejects modified message");

    # round-trip through sign_hash / verify_hash using a SHAKE digest of the message
    use Crypt::Digest::SHAKE;
    my $hashlen = $h eq 'SHAKE128' ? 32 : 64;
    my $d = Crypt::Digest::SHAKE->new($h eq 'SHAKE128' ? 128 : 256);
    $d->add($msg);
    my $hash = $d->done($hashlen);

    my $sig2 = eval { $priv->sign_hash($hash, $h, 'pss', $sl) };
    diag("$@") if $@;
    ok($sig2 && length($sig2) == 256, "RSA-PSS-$h sign_hash");
    ok($pub->verify_hash($sig2, $hash, $h, 'pss', $sl), "RSA-PSS-$h verify_hash");
  }
}

# --- ECDSA-SHAKE128 / SHAKE256 ----------------------------------------------
{
  my $priv = Crypt::PK::ECC->new;
  $priv->generate_key('secp256r1');
  my $pub = Crypt::PK::ECC->new(\$priv->export_key_der('public'));
  my $msg = 'RFC 8702 test message';

  for my $h ('SHAKE128', 'SHAKE256') {
    my $sig = eval { $priv->sign_message($msg, $h) };
    diag("$@") if $@;
    ok($sig && length($sig) > 60, "ECDSA-$h sign_message");
    ok($pub->verify_message($sig, $msg, $h), "ECDSA-$h verify_message");
    ok(!$pub->verify_message($sig, "$msg.tampered", $h), "ECDSA-$h verify_message rejects modified message");
  }
}
