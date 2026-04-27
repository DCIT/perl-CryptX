use strict;
use warnings;

use Test::More;

plan tests => 23;

use Crypt::AuthEnc::XChaCha20Poly1305 qw(
  xchacha20poly1305_encrypt_authenticate
  xchacha20poly1305_decrypt_verify
);

{
  package Local::XOverStr;
  use overload q{""} => sub { $_[0]->{value} }, fallback => 1;
  sub new { bless { value => $_[1] }, $_[0] }
}

my $key   = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
my $nonce = pack("H*", "000102030405060708090a0b0c0d0e0f1011121314151617");
my $aad   = "adata-123456789012";
my $pt    = "plain_halfplain_half";
my $ct_hex  = "eeae6e16fe8de5cf5f2256a2aa3bc6b7232644c3";
my $tag_hex = "996a94a6808314a5d012d9e4e329aabf";

{
  my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
  isa_ok($ae, 'Crypt::AuthEnc::XChaCha20Poly1305');
  $ae->adata_add($aad);
  my $ct = $ae->encrypt_add("plain_half");
  $ct .= $ae->encrypt_add("plain_half");
  my $tag = $ae->encrypt_done;

  is(unpack('H*', $ct), $ct_hex, 'OO encrypt ciphertext');
  is(unpack('H*', $tag), $tag_hex, 'OO encrypt tag');
}

{
  my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key)->set_iv($nonce);
  isa_ok($ae, 'Crypt::AuthEnc::XChaCha20Poly1305');
  $ae->adata_add($aad);
  my $pt2 = $ae->decrypt_add(pack('H*', $ct_hex));
  ok($ae->decrypt_done(pack('H*', $tag_hex)), 'OO decrypt_done verifies tag');
  is($pt2, $pt, 'OO decrypt plaintext');
}

{
  my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
  $ae->adata_add($aad);
  $ae->encrypt_add("plain_half");
  my $clone = $ae->clone;
  isa_ok($clone, 'Crypt::AuthEnc::XChaCha20Poly1305');
  is($ae->encrypt_add("plain_half"), $clone->encrypt_add("plain_half"), 'clone preserves state');
  is($ae->encrypt_done, $clone->encrypt_done, 'clone preserves tag state');
}

{
  my $ae = Crypt::AuthEnc::XChaCha20Poly1305->new($key, $nonce);
  $ae->adata_add($aad);
  $ae->encrypt_add("plain_half");
  is(length($ae->encrypt_done), 16, 'encrypt_done returns tag');
  like((eval { $ae->encrypt_done; 1 } ? '' : $@), qr/AEAD object already finalized/, 'second encrypt_done croaks');
  like((eval { $ae->encrypt_add("x"); 1 } ? '' : $@), qr/AEAD object already finalized/, 'encrypt_add after encrypt_done croaks');
}

{
  my ($ct, $tag) = xchacha20poly1305_encrypt_authenticate($key, $nonce, $aad, $pt);
  is(unpack('H*', $ct), $ct_hex, 'functional ciphertext');
  is(unpack('H*', $tag), $tag_hex, 'functional tag');

  my $pt2 = xchacha20poly1305_decrypt_verify($key, $nonce, $aad, $ct, $tag);
  is($pt2, $pt, 'functional decrypt');

  substr($tag, 0, 1) = pack("H2", "aa");
  is(xchacha20poly1305_decrypt_verify($key, $nonce, $aad, $ct, $tag), undef, 'functional rejects bad tag');
}

{
  my ($ct1, $tag1) = xchacha20poly1305_encrypt_authenticate($key, $nonce, $aad, $pt);
  my ($ct2, $tag2) = xchacha20poly1305_encrypt_authenticate(
    Local::XOverStr->new($key),
    Local::XOverStr->new($nonce),
    $aad,
    $pt,
  );
  is($ct2, $ct1, 'functional helper accepts overloaded key/nonce');
  is($tag2, $tag1, 'functional helper overloaded output matches plain scalars');

  my $pt2 = xchacha20poly1305_decrypt_verify(
    Local::XOverStr->new($key),
    Local::XOverStr->new($nonce),
    $aad,
    $ct1,
    $tag1,
  );
  is($pt2, $pt, 'functional decrypt accepts overloaded key/nonce');
}

{
  my $ok = eval { Crypt::AuthEnc::XChaCha20Poly1305->new(substr($key, 0, 16), $nonce); 1 };
  ok(!$ok, 'rejects non-32-byte key');
  like($@, qr/key length must be 32 bytes/, 'invalid key error');

  $ok = eval { Crypt::AuthEnc::XChaCha20Poly1305->new($key, substr($nonce, 0, 12)); 1 };
  ok(!$ok, 'rejects non-24-byte nonce');
  like($@, qr/nonce length must be 24 bytes/, 'invalid nonce error');

}
