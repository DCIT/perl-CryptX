use strict;
use warnings;

use Test::More tests => 18;
use File::Temp qw(tempfile);
use Crypt::Digest::TurboSHAKE;

# RFC 9861 test vectors - https://www.rfc-editor.org/rfc/rfc9861
# Input pattern: ptn(n) = bytes 0x00, 0x01, ..., 0x(n-1) (each mod 0xfb)
sub ptn { join("", map { chr($_ % 0xfb) } 0..$_[0]-1) }

sub run_turboshake_child {
  my ($code) = @_;
  my ($script_fh, $script_path) = tempfile('digest-turboshake-XXXX', SUFFIX => '.pl', UNLINK => 1);
  print {$script_fh} "use strict;\nuse warnings;\n$code\n"
    or die "cannot write child script: $!";
  close($script_fh) or die "cannot close child script: $!";
  open(my $fh, '-|', $^X, '-Mblib', $script_path) or die "cannot run child: $!";
  local $/;
  my $out = <$fh>;
  close($fh);
  my $status = $?;
  return ($out, $status >> 8, $status & 127);
}

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
      code => 'use Crypt::Digest::TurboSHAKE; my $ok = eval { Crypt::Digest::TurboSHAKE->new(128)->done(-1); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(1000000001)',
      code => 'use Crypt::Digest::TurboSHAKE; my $ok = eval { Crypt::Digest::TurboSHAKE->new(128)->done(1000000001); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(0)',
      code => 'use Crypt::Digest::TurboSHAKE; my $ok = eval { Crypt::Digest::TurboSHAKE->new(128)->done(0); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: invalid output length\b/,
    },
    {
      label => 'done(1.5)',
      code => 'use Crypt::Digest::TurboSHAKE; my $ok = eval { my $out = Crypt::Digest::TurboSHAKE->new(128)->done(1.5); print "ok len=", length($out), "\n"; 1 }; my $err = $@; $err =~ s/\n\z//; print "error=$err\n" if !$ok;',
      re => qr/^ok len=1$/,
    },
  );

  for my $case (@cases) {
    my ($out, $exit, $signal) = run_turboshake_child($case->{code});
    is($signal, 0, "$case->{label} does not crash");
    like($out, $case->{re}, "$case->{label} behaves as documented");
  }
}
