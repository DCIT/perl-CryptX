use strict;
use warnings;

use Test::More tests => 28;

use Crypt::Digest::SHAKE;

sub run_shake_child {
  my ($code) = @_;
  open(my $fh, '-|', $^X, '-Mblib', '-we', $code) or die "cannot run child: $!";
  local $/;
  my $out = <$fh>;
  close($fh);
  my $status = $?;
  return ($out, $status >> 8, $status & 127);
}


my $sh128 = Crypt::Digest::SHAKE->new(128);
ok($sh128, "Crypt::Digest::SHAKE->new(128)");

my $sh256 = Crypt::Digest::SHAKE->new(256);
ok($sh256, "Crypt::Digest::SHAKE->new(256)");

is(unpack("H*", $sh128->add("")->done(32)), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
is(unpack("H*", $sh256->add("")->done(64)), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

is(unpack("H*", Crypt::Digest::SHAKE->new(128)->add("The quick brown fox jumps over the lazy dog")->done(32)),
   "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e");
is(unpack("H*", Crypt::Digest::SHAKE->new(128)->add("The quick brown fox jumps over the lazy dof")->done(32)),
   "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c");

{
  my $sh128 = Crypt::Digest::SHAKE->new(128);
  $sh128->add("The qui");
  $sh128->add("ck bro");
  $sh128->add("wn fox j");
  $sh128->add("umps o");
  $sh128->add("ver the l");
  $sh128->add("azy dof");
  my $res = $sh128->done(5);
  $res .= $sh128->done(7);
  $res .= $sh128->done(8);
  $res .= $sh128->done(12);
  is(unpack("H*", $res), "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c");
}

is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(9)),  "dbf9928a270d58ed5a");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(19)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(29)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c917698bcc971fe6b973e");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(39)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c917698bcc971fe6b973ec8aac9666a6f6829c58a");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(49)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c917698bcc971fe6b973ec8aac9666a6f6829c58aba66ebbb34dbd7acab94");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(59)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c917698bcc971fe6b973ec8aac9666a6f6829c58aba66ebbb34dbd7acab94cd20c6de1916fc29a890");
is(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(69)), "dbf9928a270d58ed5a6c00f2f849cac54aef8c917698bcc971fe6b973ec8aac9666a6f6829c58aba66ebbb34dbd7acab94cd20c6de1916fc29a890ad14e4f95af8c3c20147");

{
  my $hex = substr(unpack("H*", Crypt::Digest::SHAKE->new(256)->add("A" x 307)->done(999)), -100);
  is($hex, "e8e5fc62297c4ce6f915d79148470b87f539f2806160e3114ae210a3c4707e73adcdb33410606aad260c4f5dbb1575fa3d1e");
}
{
  my $hex = substr(unpack("H*", Crypt::Digest::SHAKE->new(128)->add("A" x 307)->done(999)), -100);
  is($hex, "868064bc8e37bd63713aa58ee7dae1c8d022aab26f079b13dfbc6c986a2d0200b046a99ed716380f691b7d15689236a0a8e6");
}

{
  my @cases = (
    {
      label => 'done(-1)',
      check => 'croaks cleanly',
      code => 'use Crypt::Digest::SHAKE; my $ok = eval { Crypt::Digest::SHAKE->new(128)->done(-1); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(oversized string)',
      check => 'croaks cleanly',
      code => 'use Crypt::Digest::SHAKE; my $ok = eval { Crypt::Digest::SHAKE->new(128)->done("18446744073709551615"); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(1000000001)',
      check => 'rejects over per-call cap',
      code => 'use Crypt::Digest::SHAKE; my $ok = eval { Crypt::Digest::SHAKE->new(128)->done(1000000001); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: output length too large\b/,
    },
    {
      label => 'done(0)',
      check => 'croaks cleanly',
      code => 'use Crypt::Digest::SHAKE; my $ok = eval { Crypt::Digest::SHAKE->new(128)->done(0); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re => qr/^error=FATAL: invalid output length\b/,
    },
    {
      label => 'done(1.5)',
      check => 'coerces via unsigned long',
      code => 'use Crypt::Digest::SHAKE; my $ok = eval { my $out = Crypt::Digest::SHAKE->new(128)->done(1.5); print "ok len=", length($out), "\n"; 1 }; my $err = $@; $err =~ s/\n\z//; print "error=$err\n" if !$ok;',
      re => qr/^ok len=1$/,
    },
  );

  for my $case (@cases) {
    my ($out, $exit, $signal) = run_shake_child($case->{code});
    is($signal, 0, "$case->{label} does not crash");
    like($out, $case->{re}, "$case->{label} $case->{check}");
  }
}

{
  my $d = Crypt::Digest::SHAKE->new(128);
  my $first = $d->add("abc")->done(4);
  eval { $d->add("x"); 1 };
  like($@, qr/^FATAL: cannot add after done; call reset first\b/, 'add after done croaks');
  is($d->reset->add("abc")->done(4), $first, 'reset re-enables add after done');
}
