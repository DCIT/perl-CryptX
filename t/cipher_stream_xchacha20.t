use strict;
use warnings;

use Test::More;
use File::Temp qw(tempfile);
use Crypt::Digest::SHA256 qw(sha256_hex);
use Crypt::Stream::XChaCha;

plan tests => 11;

sub run_stream_child {
  my ($code) = @_;
  my ($script_fh, $script_path) = tempfile('cipher-stream-xchacha-XXXX', SUFFIX => '.pl', UNLINK => 1);
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

my $key   = pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
my $nonce = pack("H*", "000102030405060708090a0b0c0d0e0f1011121314151617");

{ ### encrypt / decrypt round-trip
  is(Crypt::Stream::XChaCha->CLONE_SKIP, 1, 'CLONE_SKIP');

  my $pt = "Kilroy was here!\x00";
  my $ct = Crypt::Stream::XChaCha->new($key, $nonce)->crypt($pt);

  is(unpack('H*', $ct), 'ae530dbc9e28c86360755d8b5fada50f90', 'encrypt');

  my $pt2 = Crypt::Stream::XChaCha->new($key, $nonce)->crypt($ct);
  is($pt2, $pt, 'decrypt round-trip');

  my $undef_out;
  {
    local $SIG{__WARN__} = sub { };
    $undef_out = Crypt::Stream::XChaCha->new($key, $nonce)->crypt(undef);
  }
  is($undef_out, '', 'crypt(undef) behaves like empty input');
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

{
  my $key_hex = unpack('H*', $key);
  my $nonce_hex = unpack('H*', $nonce);
  my ($out, $exit, $signal) = run_stream_child(
    "use Crypt::Stream::XChaCha; local \$SIG{__WARN__} = sub { }; my \$ok = eval { Crypt::Stream::XChaCha->new(pack('H*', '$key_hex'), pack('H*', '$nonce_hex'))->keystream(-1); 1 }; my \$err = \$@; \$err =~ s/\\n\\z//; print \$ok ? \"NOERROR\" : \$err;"
  );
  is($signal, 0, 'keystream(-1) does not crash');
  is($exit, 0, 'keystream(-1) exits after croak');
  like($out, qr/^FATAL: output length too large\b/, 'keystream(-1) croaks cleanly');
}
