use strict;
use warnings;
use Test::More tests => 14;

use Crypt::Mac::HMAC qw(hmac_hex);
use Crypt::Mac::KMAC;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);

# XS argument checks of the form
#   if (!SvPOK_spec(sv)) croak("FATAL: key must be string/buffer scalar");
# must not reject an argument whose value is only produced when the SV is read.
#
# SvOK(), which SvPOK_spec() is built on, is a plain flag test: it does not fetch
# get-magic. Until something reads such an SV its value flags are simply absent
#   SV = PVLV  FLAGS = (GMG,SMG)  PV = 0        <- substr($buf,0,32) as an argument
#   SV = PV    FLAGS = (POK,pPOK) PV = "KK..."  <- the same value in a lexical
# so SvOK() answers "has this been materialized yet" where we meant "is this
# defined". SvPVbyte() on the next line does fetch magic, so the value was never
# in doubt - only the test in front of it.
#
# The magical value has to reach the call inline: copying it into a lexical first
# (my $k = substr(...)) materializes it and the bug disappears.

my $msg  = 'message to authenticate';
my $key  = 'K' x 32;
my $buf  = ('K' x 32) . 'trailing junk';   # the key inside a larger buffer
my $want = hmac_hex('SHA256', $key, $msg);

{ package My::Tied;  sub TIESCALAR { bless {} } sub FETCH { 'K' x 32 } sub STORE {} }
{ package My::Overld; use overload q{""} => sub { 'K' x 32 }, fallback => 1; sub new { bless {} } }

# control: a plain lexical key works, so $want is a usable reference value
is(length($want), 64, 'control: plain lexical key produces a MAC');

# the defect
{
  my $got = eval { hmac_hex('SHA256', substr($buf, 0, 32), $msg) };
  my $err = $@;
  is($got, $want, 'hmac_hex accepts a substr() key');
  diag("died with: $err") if $err;
}
{
  my $got = eval { Crypt::Mac::HMAC->new('SHA256', substr($buf, 0, 32))->add($msg)->hexmac };
  my $err = $@;
  is($got, $want, 'Crypt::Mac::HMAC->new accepts a substr() key');
  diag("died with: $err") if $err;
}
{
  tie my $tied, 'My::Tied';
  my $got = eval { hmac_hex('SHA256', $tied, $msg) };
  my $err = $@;
  is($got, $want, 'hmac_hex accepts a tied-scalar key');
  diag("died with: $err") if $err;
}

# guards: fixing the above must not widen what gets accepted
{
  my $got = eval { hmac_hex('SHA256', My::Overld->new, $msg) };
  my $err = $@;
  is($got, $want, 'hmac_hex still accepts a string-overloaded object (issue 105)');
  diag("died with: $err") if $err;
}
{
  eval { hmac_hex('SHA256', undef, $msg) };
  like($@, qr/key must be string/, 'hmac_hex still rejects an undef key');
}
{
  eval { hmac_hex('SHA256', {}, $msg) };
  like($@, qr/key must be string/, 'hmac_hex still rejects a hashref key');
}

# the message argument goes straight to SvPVbyte and was never affected
is(hmac_hex('SHA256', $key, substr($buf, 0, 5)), hmac_hex('SHA256', $key, 'KKKKK'),
   'a substr() message argument was already handled correctly');

# The same flaw in the optional-argument guards was silent rather than fatal:
#   if (header && SvOK(header)) { ... }
# skipped the branch for a magical SV, so associated data / a customization
# string was quietly left out instead of being bound into the tag.
{
  my $k = 'K' x 32;
  my $n = 'N' x 12;
  my $aad  = 'bind-to-alice';
  my $abuf = 'bind-to-alice!!!';
  my $len  = length $aad;

  my (undef, $tag_plain)  = gcm_encrypt_authenticate('AES', $k, $n, $aad, 'secret');
  my (undef, $tag_none)   = gcm_encrypt_authenticate('AES', $k, $n, undef, 'secret');
  my ($ct, $tag_substr)   = gcm_encrypt_authenticate('AES', $k, $n, substr($abuf, 0, $len), 'secret');

  isnt($tag_plain, $tag_none, 'control: AAD changes the GCM tag');
  is($tag_substr, $tag_plain, 'GCM binds a substr() AAD');
  ok(!defined gcm_decrypt_verify('AES', $k, $n, undef, $ct, $tag_substr),
     'a substr()-AAD ciphertext does not verify without the AAD');
  ok(defined gcm_decrypt_verify('AES', $k, $n, $aad, $ct, $tag_substr),
     'a substr()-AAD ciphertext verifies with the AAD');

  my $mac_plain  = Crypt::Mac::KMAC->new('KMAC128', $k, 'MyCustom')->add('m')->hexmac(32);
  my $mac_none   = Crypt::Mac::KMAC->new('KMAC128', $k, undef)->add('m')->hexmac(32);
  my $cbuf = 'MyCustomXXXX';
  my $mac_substr = Crypt::Mac::KMAC->new('KMAC128', $k, substr($cbuf, 0, 8))->add('m')->hexmac(32);
  isnt($mac_plain, $mac_none, 'control: cust changes the KMAC');
  is($mac_substr, $mac_plain, 'KMAC binds a substr() customization string');
}
