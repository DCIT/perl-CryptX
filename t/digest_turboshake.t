use strict;
use warnings;

use Test::More tests => 18;
use Crypt::Digest::TurboSHAKE;

# RFC 9861 test vectors - https://www.rfc-editor.org/rfc/rfc9861
# Input pattern: ptn(n) = bytes 0x00, 0x01, ..., 0x(n-1) (each mod 0xfb)
sub ptn { join("", map { chr($_ % 0xfb) } 0..$_[0]-1) }

{ ### TurboSHAKE128
  is(unpack('H*', Crypt::Digest::TurboSHAKE->new(128)->done(32)),
     '1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c',
     'TS128 empty 32');

  is(unpack('H*', Crypt::Digest::TurboSHAKE->new(128)->add(ptn(1))->done(32)),
     '55cedd6f60af7bb29a4042ae832ef3f58db7299f893ebb9247247d856958daa9',
     'TS128 ptn(1) 32');

  is(unpack('H*', Crypt::Digest::TurboSHAKE->new(128)->add(ptn(17))->done(32)),
     '9c97d036a3bac819db70ede0ca554ec6e4c2a1a4ffbfd9ec269ca6a111161233',
     'TS128 ptn(17) 32');
}

{ ### TurboSHAKE256
  is(unpack('H*', Crypt::Digest::TurboSHAKE->new(256)->done(64)),
     '367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db' .
     '11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0',
     'TS256 empty 64');

  is(unpack('H*', Crypt::Digest::TurboSHAKE->new(256)->add(ptn(1))->done(64)),
     '3e1712f928f8eaf1054632b2aa0a246ed8b0c378728f60bc970410155c28820e' .
     '90cc90d8a3006aa2372c5c5ea176b0682bf22bae7467ac94f74d43d39b0482e2',
     'TS256 ptn(1) 64');
}

{ ### streaming done() and clone
  my $d1 = Crypt::Digest::TurboSHAKE->new(128);
  my $out1 = $d1->done(16) . $d1->done(16);
  my $out2 = Crypt::Digest::TurboSHAKE->new(128)->done(32);
  is($out1, $out2, 'TS128 streaming done');

  my $d2 = Crypt::Digest::TurboSHAKE->new(128)->add(ptn(17));
  my $d3 = $d2->clone;
  is($d2->done(32), $d3->done(32), 'TS128 clone');

  my $d4 = Crypt::Digest::TurboSHAKE->new(128)->add(ptn(17));
  $d4->reset;
  is(unpack('H*', $d4->done(32)),
     '1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c',
     'TS128 reset');

  eval { $d4->add('x'); 1 };
  like($@, qr/^FATAL: cannot add after done; call reset first\b/, 'TS128 add after done croaks');
  is(unpack('H*', $d4->reset->add(ptn(17))->done(32)),
     '9c97d036a3bac819db70ede0ca554ec6e4c2a1a4ffbfd9ec269ca6a111161233',
     'TS128 reset re-enables add after done');
}

{
  my @cases = (
    {
      label => 'done(-1)',
      action => sub { Crypt::Digest::TurboSHAKE->new(128)->done(-1) },
      re => qr/^FATAL: output length too large\b/,
    },
    {
      label => 'done(1000000001)',
      action => sub { Crypt::Digest::TurboSHAKE->new(128)->done(1000000001) },
      re => qr/^FATAL: output length too large\b/,
    },
    {
      label => 'done(0)',
      action => sub { Crypt::Digest::TurboSHAKE->new(128)->done(0) },
      re => qr/^FATAL: invalid output length\b/,
    },
    {
      label => 'done(1.5)',
      action => sub { Crypt::Digest::TurboSHAKE->new(128)->done(1.5) },
      len => 1,
    },
  );

  for my $case (@cases) {
    my $out;
    my $ok = eval { $out = $case->{action}->(); 1 };
    if (exists $case->{len}) {
      ok($ok, "$case->{label} succeeds");
      is(length($out), $case->{len}, "$case->{label} output length");
    }
    else {
      ok(!$ok, "$case->{label} croaks");
      like($@, $case->{re}, "$case->{label} croak text");
    }
  }
}
