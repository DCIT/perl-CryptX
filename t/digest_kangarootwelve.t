use strict;
use warnings;

use Test::More tests => 20;
use File::Temp qw(tempfile);
use Crypt::Digest::KangarooTwelve;

# RFC 9861 test vectors - https://www.rfc-editor.org/rfc/rfc9861
# Input pattern: ptn(n) = bytes 0x00, 0x01, ..., (each mod 0xfb)
sub ptn { join("", map { chr($_ % 0xfb) } 0..$_[0]-1) }

sub run_k12_child {
  my ($code) = @_;
  my ($script_fh, $script_path) = tempfile('digest-k12-XXXX', SUFFIX => '.pl', UNLINK => 1);
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

{ ### KangarooTwelve 128-bit security
  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(128)->done(32)),
     '1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5',
     'K12-128 empty input, no customization, 32 bytes');

  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(128)->add(ptn(1))->done(32)),
     '2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f',
     'K12-128 ptn(1) input, no customization, 32 bytes');

  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(128)->customization(ptn(1))->done(32)),
     'fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583',
     'K12-128 empty input, ptn(1) customization, 32 bytes');

  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(128)->add(ptn(17))->done(32)),
     '6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888',
     'K12-128 ptn(17) input, no customization, 32 bytes');
}

{ ### KangarooTwelve 256-bit security
  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(256)->done(64)),
     'b23d2e9cea9f4904e02bec06817fc10ce38ce8e93ef4c89e6537076af8646404' .
     'e3e8b68107b8833a5d30490aa33482353fd4adc7148ecb782855003aaebde4a9',
     'K12-256 empty input, no customization, 64 bytes');

  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(256)->add(ptn(1))->done(64)),
     '0d005a194085360217128cf17f91e1f71314efa5564539d444912e3437efa17f' .
     '82db6f6ffe76e781eaa068bce01f2bbf81eacb983d7230f2fb02834a21b1ddd0',
     'K12-256 ptn(1) input, no customization, 64 bytes');

  is(unpack('H*', Crypt::Digest::KangarooTwelve->new(256)->customization(ptn(1))->done(64)),
     '9280f5cc39b54a5a594ec63de0bb99371e4609d44bf845c2f5b8c316d72b1598' .
     '11f748f23e3fabbe5c3226ec96c62186df2d33e9df74c5069ceecbb4dd10eff6',
     'K12-256 empty input, ptn(1) customization, 64 bytes');
}

{ ### streaming done() and clone
  my $d1 = Crypt::Digest::KangarooTwelve->new(128);
  my $out1 = $d1->done(16) . $d1->done(16);
  my $out2 = Crypt::Digest::KangarooTwelve->new(128)->done(32);
  is($out1, $out2, 'K12-128 streaming done');

  my $d2 = Crypt::Digest::KangarooTwelve->new(128)->add(ptn(17));
  my $d3 = $d2->clone;
  is($d2->done(32), $d3->done(32), 'K12-128 clone');

  eval { $d2->add("x"); 1 };
  like($@, qr/^FATAL: cannot add after done; call reset first\b/, 'K12 add after done croaks');
  eval { $d3->customization("ctx"); 1 };
  like($@, qr/^FATAL: cannot add after done; call reset first\b/, 'K12 customization after done croaks');

  my $d4 = Crypt::Digest::KangarooTwelve->new(128)->add(ptn(17))->customization("ctx");
  my $first = $d4->done(32);
  is($d4->reset->add(ptn(17))->customization("ctx")->done(32), $first, 'K12 reset re-enables add/customization');
}

{
  my @cases = (
    {
      label => 'done(-1)',
      code => 'use Crypt::Digest::KangarooTwelve; my $ok = eval { Crypt::Digest::KangarooTwelve->new(128)->done(-1); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(1000000001)',
      code => 'use Crypt::Digest::KangarooTwelve; my $ok = eval { Crypt::Digest::KangarooTwelve->new(128)->done(1000000001); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(0)',
      code => 'use Crypt::Digest::KangarooTwelve; my $ok = eval { Crypt::Digest::KangarooTwelve->new(128)->done(0); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: invalid output length\b/,
    },
    {
      label => 'done(1.5)',
      code => 'use Crypt::Digest::KangarooTwelve; my $ok = eval { my $out = Crypt::Digest::KangarooTwelve->new(128)->done(1.5); print "ok len=", length($out), "\n"; 1 }; my $err = $@; $err =~ s/\n\z//; print "error=$err\n" if !$ok;',
      re => qr/^ok len=1$/,
    },
  );

  for my $case (@cases) {
    my ($out, $exit, $signal) = run_k12_child($case->{code});
    is($signal, 0, "$case->{label} does not crash");
    like($out, $case->{re}, "$case->{label} behaves as documented");
  }
}
