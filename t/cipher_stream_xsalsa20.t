use strict;
use warnings;

use Test::More tests => 4;
use Crypt::Digest::SHA256 qw(sha256_hex);
use Crypt::Stream::XSalsa20;

# Test vectors from libtomcrypt xsalsa20_test.c
# Key and nonce from D.J. Bernstein's XSalsa20 reference

my $key   = pack("H*", "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
my $nonce = pack("H*", "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

{ ### encrypt / decrypt round-trip
  my $pt = "Kilroy was here!\x00";  # 17 bytes
  my $ct = Crypt::Stream::XSalsa20->new($key, $nonce)->crypt($pt);

  is(unpack('H*', $ct), 'a5cfcb57736752e60c62e2a3443f590425', 'encrypt');

  my $pt2 = Crypt::Stream::XSalsa20->new($key, $nonce)->crypt($ct);
  is($pt2, $pt, 'decrypt round-trip');
}

{ ### clone preserves state
  my $s1 = Crypt::Stream::XSalsa20->new($key, $nonce);
  $s1->keystream(100);
  my $s2 = $s1->clone;
  is($s1->keystream(32), $s2->keystream(32), 'clone');
}

{ ### keystream SHA256 (91101 bytes, from libtomcrypt xsalsa20_test.c)
  my $ks = Crypt::Stream::XSalsa20->new($key, $nonce)->keystream(91101);
  is(sha256_hex($ks), '6a60576527e000516db0da604620f6d095654539f486834364dfd95a6f3fbeb7',
     'keystream sha256');
}
