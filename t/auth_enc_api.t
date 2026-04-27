use strict;
use warnings;

use Test::More;

use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate);
use Crypt::AuthEnc::EAX;
use Crypt::AuthEnc::OCB;
use Crypt::AuthEnc::CCM;
use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate);

{
  package Local::OverStr;
  use overload q{""} => sub { $_[0]->{value} }, fallback => 1;
  sub new { bless { value => $_[1] }, $_[0] }
}

sub dies_like {
  my ($code, $regex, $name) = @_;
  my $err = eval { $code->(); 1 } ? '' : $@;
  like($err, $regex, $name);
}

my $aes_key   = "12345678901234561234567890123456";
my $chacha_key = $aes_key;
my $nonce12   = "123456789012";
my $ocb_pt    = "plain_half_12345";
my $short_pt  = "abc";
my $aad       = "adata-123456789012";

{
  my $gcm = Crypt::AuthEnc::GCM->new("AES", $aes_key, $nonce12);
  $gcm->adata_add($aad);
  $gcm->encrypt_add($short_pt);
  my $gcm_clone = $gcm->clone;
  is($gcm->encrypt_done, $gcm_clone->encrypt_done, "GCM clone preserves tag state");
  dies_like(sub { $gcm->encrypt_done }, qr/AEAD object already finalized/, "GCM second encrypt_done croaks");
  dies_like(sub { $gcm->encrypt_add("x") }, qr/AEAD object already finalized/, "GCM add after encrypt_done croaks");
  $gcm->reset;
  $gcm->iv_add($nonce12);
  $gcm->adata_add($aad);
  $gcm->encrypt_add($short_pt);
  is(length($gcm->encrypt_done), 16, "GCM reset clears finalized state");
}

{
  my $eax = Crypt::AuthEnc::EAX->new("AES", $aes_key, $nonce12);
  $eax->adata_add($aad);
  $eax->encrypt_add($short_pt);
  my $eax_clone = $eax->clone;
  is($eax->encrypt_done, $eax_clone->encrypt_done, "EAX clone preserves tag state");
  dies_like(sub { $eax->encrypt_done }, qr/AEAD object already finalized/, "EAX second encrypt_done croaks");
  dies_like(sub { $eax->encrypt_add("x") }, qr/AEAD object already finalized/, "EAX add after encrypt_done croaks");
}

{
  my $ocb = Crypt::AuthEnc::OCB->new("AES", $aes_key, $nonce12, 16);
  $ocb->adata_add($aad);
  $ocb->encrypt_add($ocb_pt);
  my $ocb_clone = $ocb->clone;
  is($ocb->encrypt_done, $ocb_clone->encrypt_done, "OCB clone preserves tag state");
  dies_like(sub { $ocb->encrypt_done }, qr/AEAD object already finalized/, "OCB second encrypt_done croaks");
  dies_like(sub { $ocb->encrypt_add($ocb_pt) }, qr/AEAD object already finalized/, "OCB add after encrypt_done croaks");
}

{
  my $ccm = Crypt::AuthEnc::CCM->new("AES", $aes_key, $nonce12, "", 16, length($short_pt));
  $ccm->encrypt_add($short_pt);
  my $ccm_clone = $ccm->clone;
  is($ccm->encrypt_done, $ccm_clone->encrypt_done, "CCM clone preserves tag state");
  dies_like(sub { $ccm->encrypt_done }, qr/AEAD object already finalized/, "CCM second encrypt_done croaks");
  dies_like(sub { $ccm->encrypt_add("x") }, qr/AEAD object already finalized/, "CCM add after encrypt_done croaks");
}

{
  my $cp = Crypt::AuthEnc::ChaCha20Poly1305->new($chacha_key, $nonce12);
  $cp->adata_add($aad);
  $cp->encrypt_add($short_pt);
  my $cp_clone = $cp->clone;
  is($cp->encrypt_done, $cp_clone->encrypt_done, "ChaCha20Poly1305 clone preserves tag state");
  dies_like(sub { $cp->encrypt_done }, qr/AEAD object already finalized/, "ChaCha20Poly1305 second encrypt_done croaks");
  dies_like(sub { $cp->encrypt_add("x") }, qr/AEAD object already finalized/, "ChaCha20Poly1305 add after encrypt_done croaks");
}

{
  my ($ct1, $tag1) = gcm_encrypt_authenticate('AES', $aes_key, $nonce12, '', $short_pt);
  my ($ct2, $tag2) = gcm_encrypt_authenticate(
    'AES',
    Local::OverStr->new($aes_key),
    Local::OverStr->new($nonce12),
    '',
    $short_pt,
  );
  is($ct2,  $ct1,  "GCM functional helper accepts overloaded key/nonce");
  is($tag2, $tag1, "GCM functional helper overloaded output matches plain scalars");
}

{
  my ($ct1, $tag1) = chacha20poly1305_encrypt_authenticate($chacha_key, $nonce12, '', $short_pt);
  my ($ct2, $tag2) = chacha20poly1305_encrypt_authenticate(
    Local::OverStr->new($chacha_key),
    Local::OverStr->new($nonce12),
    '',
    $short_pt,
  );
  is($ct2,  $ct1,  "ChaCha20Poly1305 functional helper accepts overloaded key/nonce");
  is($tag2, $tag1, "ChaCha20Poly1305 functional helper overloaded output matches plain scalars");
}

done_testing();
