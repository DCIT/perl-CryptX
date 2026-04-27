use strict;
use warnings;

use Test::More tests => 9;
use File::Temp qw(tempfile);
use Crypt::Digest::SHA256 qw(sha256_hex);
use Crypt::Stream::XSalsa20;

sub run_stream_child {
  my ($code) = @_;
  my ($script_fh, $script_path) = tempfile('cipher-stream-xsalsa-XXXX', SUFFIX => '.pl', UNLINK => 1);
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

# Test vectors from libtomcrypt xsalsa20_test.c
# Key and nonce from D.J. Bernstein's XSalsa20 reference

my $key   = pack("H*", "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
my $nonce = pack("H*", "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

{ ### encrypt / decrypt round-trip
  is(Crypt::Stream::XSalsa20->CLONE_SKIP, 1, 'CLONE_SKIP');

  my $pt = "Kilroy was here!\x00";  # 17 bytes
  my $ct = Crypt::Stream::XSalsa20->new($key, $nonce)->crypt($pt);

  is(unpack('H*', $ct), 'a5cfcb57736752e60c62e2a3443f590425', 'encrypt');

  my $pt2 = Crypt::Stream::XSalsa20->new($key, $nonce)->crypt($ct);
  is($pt2, $pt, 'decrypt round-trip');

  my $undef_out;
  {
    local $SIG{__WARN__} = sub { };
    $undef_out = Crypt::Stream::XSalsa20->new($key, $nonce)->crypt(undef);
  }
  is($undef_out, '', 'crypt(undef) behaves like empty input');
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

{
  my $key_hex = unpack('H*', $key);
  my $nonce_hex = unpack('H*', $nonce);
  my ($out, $exit, $signal) = run_stream_child(
    "use Crypt::Stream::XSalsa20; local \$SIG{__WARN__} = sub { }; my \$ok = eval { Crypt::Stream::XSalsa20->new(pack('H*', '$key_hex'), pack('H*', '$nonce_hex'))->keystream(-1); 1 }; my \$err = \$@; \$err =~ s/\\n\\z//; print \$ok ? \"NOERROR\" : \$err;"
  );
  is($signal, 0, 'keystream(-1) does not crash');
  is($exit, 0, 'keystream(-1) exits after croak');
  like($out, qr/^FATAL: output length too large\b/, 'keystream(-1) croaks cleanly');
}
