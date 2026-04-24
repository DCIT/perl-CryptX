use strict;
use warnings;

use Test::More;
use Digest::SHA qw(sha256_hex);
use Crypt::Stream::XChaCha;

plan tests => 6;

my $key   = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
my $nonce = pack("H*", "000102030405060708090a0b0c0d0e0f1011121314151617");

{ ### encrypt / decrypt round-trip
  my $pt = "Kilroy was here!\x00";
  my $ct = Crypt::Stream::XChaCha->new($key, $nonce)->crypt($pt);

  is(unpack('H*', $ct), 'ae530dbc9e28c86360755d8b5fada50f90', 'encrypt');

  my $pt2 = Crypt::Stream::XChaCha->new($key, $nonce)->crypt($ct);
  is($pt2, $pt, 'decrypt round-trip');
}

{ ### clone preserves state
  my $s1 = Crypt::Stream::XChaCha->new($key, $nonce);
  $s1->keystream(100);
  my $s2 = $s1->clone;
  is($s1->keystream(32), $s2->keystream(32), 'clone');
}

{ ### keystream SHA256
  my $ks = Crypt::Stream::XChaCha->new($key, $nonce)->keystream(91101);
  is(sha256_hex($ks), 'c7d2796522e59ccb2396d022356192a5a89100b22d57fb0d86495198643e3d8b',
     'keystream sha256');
}

{ ### invalid nonce length
  my $short_nonce = substr($nonce, 0, 12);
  my $err = eval { Crypt::Stream::XChaCha->new($key, $short_nonce); 1 };
  ok(!$err, 'rejects non-24-byte nonce');
  like($@, qr/xchacha20_setup failed/, 'invalid nonce error');
}
