use strict;
use warnings;

use Test::More tests => 4;

use Crypt::PK::X25519;
use Crypt::PK::X448;
use Crypt::PK::RSA;

# X25519 / X448 - ZeroSharedSecret
{
  # Two normal keys -> non-zero shared secret; works in both modes.
  my $alice = Crypt::PK::X25519->new->generate_key;
  my $zero_pub = Crypt::PK::X25519->new->import_key_raw("\x00" x 32, 'public');
  my $sret = eval { $alice->shared_secret($zero_pub) };
  ok(!defined $sret, 'X25519 rejects all-zero shared secret (returns undef)');
}
{
  my $alice = Crypt::PK::X448->new->generate_key;
  my $zero_pub = Crypt::PK::X448->new->import_key_raw("\x00" x 56, 'public');
  my $sret = eval { $alice->shared_secret($zero_pub) };
  ok(!defined $sret, 'X448 rejects all-zero shared secret (returns undef)');
}

# RSA OAEP - SmallIntegerCiphertext
{
  my $priv = Crypt::PK::RSA->new->generate_key(128, 65537);
  my $kh = $priv->key2hash;
  my $k = $kh->{size};   # modulus size in bytes

  # Small-integer ciphertexts that violate SP 800-56B Rev 2 §7.1.2.1.
  my $ct_zero = "\x00" x $k;
  my $ct_one  = ("\x00" x ($k - 1)) . "\x01";
  for my $pair ([0, $ct_zero], [1, $ct_one]) {
    my ($val, $ct) = @$pair;
    my $r = eval { $priv->decrypt($ct, 'oaep', 'SHA256', '', 'SHA256') };
    ok(!defined $r, "OAEP rejects c == $val");
  }
}
