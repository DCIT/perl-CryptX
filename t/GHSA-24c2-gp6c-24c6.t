use strict;
use warnings;
use Config;
use POSIX ();
use Test::More;

plan skip_all => "fork not available on this platform" unless $Config{d_fork};

use IO::Handle;
use Crypt::PK::DH;
use Crypt::PK::DSA;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::RSA;
use Crypt::PK::X25519;
use Crypt::PRNG;
use Crypt::PRNG::ChaCha20;
use Crypt::PRNG::Fortuna;
use Crypt::PRNG::RC4;
use Crypt::PRNG::Sober128;
use Crypt::PRNG::Yarrow;

sub fork_capture {
  my ($code) = @_;

  pipe(my $child_read, my $child_write) or BAIL_OUT("pipe failed: $!");
  binmode $child_read;
  binmode $child_write;
  $child_write->autoflush(1);

  my $pid = fork();
  BAIL_OUT("fork failed: $!") unless defined $pid;

  if ($pid == 0) {
    my $ok = eval {
      close $child_read or die "close child_read failed: $!";
      my $value = $code->();
      die "callback returned undef" unless defined $value;
      print {$child_write} $value;
      close $child_write or die "close child_write failed: $!";
      1;
    };
    POSIX::_exit($ok ? 0 : 1);
  }

  close $child_write or BAIL_OUT("close child_write failed: $!");

  my $parent_value = eval { $code->() };
  my $parent_error = $@;
  waitpid($pid, 0) if $parent_error;
  BAIL_OUT("parent callback failed: $parent_error") if $parent_error;

  my $child_value = do { local $/; <$child_read> };
  close $child_read or BAIL_OUT("close child_read failed: $!");

  waitpid($pid, 0);
  return ($parent_value, $child_value, $? >> 8);
}

sub expect_fork_divergence {
  my ($name, $code) = @_;

  subtest $name => sub {
    my ($parent_value, $child_value, $child_status) = fork_capture($code);

    ok(defined $parent_value && length $parent_value, 'parent produced output');
    ok(defined $child_value && length $child_value, 'child produced output');
    is($child_status, 0, 'child exited cleanly');
    isnt($parent_value, $child_value, 'parent and child diverge after fork');
  };
}

expect_fork_divergence(
  'Crypt::PRNG bytes',
  do {
    my $prng = Crypt::PRNG->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PRNG::Fortuna bytes',
  do {
    my $prng = Crypt::PRNG::Fortuna->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PRNG::Yarrow bytes',
  do {
    my $prng = Crypt::PRNG::Yarrow->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PRNG::RC4 bytes',
  do {
    my $prng = Crypt::PRNG::RC4->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PRNG::Sober128 bytes',
  do {
    my $prng = Crypt::PRNG::Sober128->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PRNG::ChaCha20 bytes',
  do {
    my $prng = Crypt::PRNG::ChaCha20->new;
    sub {
      return $prng->bytes_hex(32);
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::RSA generate_key',
  do {
    my $pk = Crypt::PK::RSA->new;
    sub {
      $pk->generate_key(128, 65537);
      return $pk->export_key_jwk_thumbprint('SHA256');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::ECC generate_key',
  do {
    my $pk = Crypt::PK::ECC->new;
    sub {
      $pk->generate_key('secp256k1');
      return $pk->export_key_jwk_thumbprint('SHA256');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::DH generate_key',
  do {
    my $pk = Crypt::PK::DH->new;
    sub {
      $pk->generate_key(128);
      return $pk->key2hash->{y};
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::DSA generate_key',
  do {
    my $pk = Crypt::PK::DSA->new;
    sub {
      $pk->generate_key(20, 128);
      return $pk->key2hash->{y};
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::Ed25519 generate_key',
  do {
    my $pk = Crypt::PK::Ed25519->new;
    sub {
      $pk->generate_key;
      return $pk->key2hash->{pub};
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::X25519 generate_key',
  do {
    my $pk = Crypt::PK::X25519->new;
    sub {
      $pk->generate_key;
      return $pk->key2hash->{pub};
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::RSA encrypt',
  do {
    my $pk = Crypt::PK::RSA->new('t/data/cryptx_pub_rsa1.der');
    sub {
      return unpack 'H*', $pk->encrypt('secret message', 'oaep', 'SHA256');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::RSA sign_message',
  do {
    my $pk = Crypt::PK::RSA->new('t/data/cryptx_priv_rsa1.der');
    sub {
      return unpack 'H*', $pk->sign_message('secret message', 'SHA256', 'pss', 12);
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::ECC encrypt',
  do {
    my $pk = Crypt::PK::ECC->new('t/data/cryptx_pub_ecc1.der');
    sub {
      return unpack 'H*', $pk->encrypt('secret message');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::ECC sign_message',
  do {
    my $pk = Crypt::PK::ECC->new('t/data/cryptx_priv_ecc1.der');
    sub {
      return unpack 'H*', $pk->sign_message('secret message', 'SHA256');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::DSA encrypt',
  do {
    my $pk = Crypt::PK::DSA->new('t/data/cryptx_pub_dsa1.der');
    sub {
      return unpack 'H*', $pk->encrypt('secret message');
    };
  },
);

expect_fork_divergence(
  'Crypt::PK::DSA sign_message',
  do {
    my $pk = Crypt::PK::DSA->new('t/data/cryptx_priv_dsa1.der');
    sub {
      return unpack 'H*', $pk->sign_message('secret message', 'SHA256');
    };
  },
);

done_testing;
