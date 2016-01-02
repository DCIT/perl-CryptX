use strict;
use warnings;
use Test::More tests => 57;

use Crypt::PK::RSA;
use Crypt::PK::ECC;
use Crypt::PK::DSA;
use Data::Dumper;

my $rsa = Crypt::PK::RSA->new;
my $ec  = Crypt::PK::ECC->new;
my $dsa = Crypt::PK::DSA->new;
ok($rsa, "RSA new");
ok($ec,  "ECC new");
ok($dsa, "DSA new");

my $dir = "t/data/ssh";

for my $f (qw/ssh_rsa_1024 ssh_rsa_1536 ssh_rsa_2048 ssh_rsa_4096 ssh_rsa_768 ssh_rsa_8192/) {
  $rsa->import_key("$dir/$f");
  ok($rsa->is_private, "RSA is_private $f");
  $rsa->import_key("$dir/$f\_passwd", "secret");
  ok($rsa->is_private, "RSA is_private $f\_passwd");
  $rsa->import_key("$dir/$f.pub.pkcs8");
  ok(!$rsa->is_private, "RSA !is_private $f.pub.pkcs8");
  $rsa->import_key("$dir/$f.pub");
  ok(!$rsa->is_private, "RSA !is_private $f.pub");
  $rsa->import_key("$dir/$f.pub.pem");
  ok(!$rsa->is_private, "RSA !is_private $f.pub.pem");
  $rsa->import_key("$dir/$f.pub.rfc4716");
  ok(!$rsa->is_private, "RSA !is_private $f.pub.rfc4716");
}

for my $f (qw/ssh_ecdsa_256 ssh_ecdsa_384 ssh_ecdsa_521/) {
  $ec->import_key("$dir/$f");
  ok($ec->is_private, "ECC is_private $f");
  $ec->import_key("$dir/$f.pub.pkcs8");
  ok(!$ec->is_private, "ECC !is_private $f.pub.pkcs8");
  $ec->import_key("$dir/$f.pub");
  ok(!$ec->is_private, "ECC !is_private $f.pub");
  $ec->import_key("$dir/$f.pub.rfc4716");
  ok(!$ec->is_private, "ECC !is_private $f.pub.rfc4716");
}

{
  my $f = "ssh_dsa_1024";
  $dsa->import_key("$dir/$f");
  ok($dsa->is_private, "DSA is_private $f");
  my $kh_priv = $dsa->key2hash;
  $dsa->import_key("$dir/$f.pub.pkcs8");
  ok(!$dsa->is_private, "DSA !is_private $f.pub.pkcs8");
  my $kh_pub = $dsa->key2hash;
  $dsa->import_key("$dir/$f.pub");
  ok(!$dsa->is_private, "DSA !is_private $f.pub");
  $dsa->import_key("$dir/$f.pub.rfc4716");
  ok(!$dsa->is_private, "DSA !is_private $f.pub.rfc4716");
  $dsa->import_key($kh_priv);
  ok($dsa->is_private, "DSA is_private HASH");
  $dsa->import_key($kh_pub);
  ok(!$dsa->is_private, "DSA !is_private HASH");
}
