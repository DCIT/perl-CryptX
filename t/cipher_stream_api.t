use strict;
use warnings;

use Test::More;

use Crypt::Stream::ChaCha;
use Crypt::Stream::Salsa20;
use Crypt::Stream::RC4;
use Crypt::Stream::Rabbit;
use Crypt::Stream::Sober128;
use Crypt::Stream::Sosemanuk;

my @cases = (
  {
    name         => 'ChaCha',
    class        => 'Crypt::Stream::ChaCha',
    args         => [ "K" x 32, "N" x 8 ],
    invalid_args => [ "K" x 32, "N" x 7 ],
  },
  {
    name         => 'Salsa20',
    class        => 'Crypt::Stream::Salsa20',
    args         => [ "K" x 32, "N" x 8 ],
    invalid_args => [ "K" x 32, "N" x 7 ],
  },
  {
    name         => 'RC4',
    class        => 'Crypt::Stream::RC4',
    args         => [ "K" x 16 ],
    invalid_args => [ "K" x 4 ],
  },
  {
    name         => 'Rabbit',
    class        => 'Crypt::Stream::Rabbit',
    args         => [ "K" x 16, "N" x 8 ],
    invalid_args => [ "K" x 16, "N" x 9 ],
  },
  {
    name         => 'Sober128',
    class        => 'Crypt::Stream::Sober128',
    args         => [ "K" x 16, "N" x 12 ],
    invalid_args => [ "K" x 16, "N" x 5 ],
  },
  {
    name         => 'Sosemanuk',
    class        => 'Crypt::Stream::Sosemanuk',
    args         => [ "K" x 16, "N" x 12 ],
    invalid_args => [ "K" x 16, "N" x 17 ],
  },
);

sub fresh_stream {
  my ($case) = @_;
  my $class = $case->{class};
  return $class->new(@{ $case->{args} });
}

sub child_croaks_cleanly {
  my ($label, $code, $pattern) = @_;
  pipe(my $reader, my $writer) or die "pipe failed: $!";

  my $pid = fork();
  die "fork failed: $!" if !defined $pid;

  if ($pid == 0) {
    close $reader;
    local $SIG{__WARN__} = sub { };
    my $ok = eval { $code->(); 1 };
    if ($ok) {
      print {$writer} "NOERROR";
      close $writer;
      exit 1;
    }
    print {$writer} $@;
    close $writer;
    exit 0;
  }

  close $writer;
  local $/;
  my $msg = <$reader>;
  close $reader;
  waitpid($pid, 0);

  is($? & 127, 0, "$label does not crash with a signal");
  is($? >> 8, 0, "$label exits after croak");
  unlike($msg // '', qr/^NOERROR\z/, "$label croaks");
  like($msg // '', $pattern, "$label croak message");
}

for my $case (@cases) {
  my $name = $case->{name};
  my $class = $case->{class};

  is($class->CLONE_SKIP, 1, "$name CLONE_SKIP");

  my $stream = fresh_stream($case);
  isa_ok($stream, $case->{class}, "$name constructor");

  is($stream->keystream(0), '', "$name keystream(0) returns empty string");

  my $ks_stream = fresh_stream($case);
  my $ct_stream = fresh_stream($case);
  is(
    $ks_stream->keystream(16),
    $ct_stream->crypt("\x00" x 16),
    "$name keystream matches crypt(zeroes)",
  );

  my $clone_source = fresh_stream($case);
  $clone_source->crypt("prefix");
  my $clone = $clone_source->clone;
  is(
    $clone_source->crypt("abcdef"),
    $clone->crypt("abcdef"),
    "$name clone preserves stream position",
  );

  my $undef_stream = fresh_stream($case);
  my $undef_out;
  {
    local $SIG{__WARN__} = sub { };
    $undef_out = $undef_stream->crypt(undef);
  }
  is($undef_out, '', "$name crypt(undef) behaves like empty input");

  my $ok = eval { $class->new(@{ $case->{invalid_args} }); 1 };
  ok(!$ok, "$name rejects invalid constructor input");
  like($@, qr/^FATAL:/, "$name invalid constructor croak text");

  if ($name eq 'ChaCha') {
    my $overflow_ok = eval { $class->new("K" x 32, "N" x 12, 4294967296); 1 };
    ok(!$overflow_ok, 'ChaCha rejects oversized counter for 12-byte nonce');
    like($@, qr/^FATAL: chacha counter too large for 12-byte nonce\b/, 'ChaCha oversized counter croak text');

    my $wide_counter_ok = eval { $class->new("K" x 32, "N" x 8, 4294967296); 1 };
    ok($wide_counter_ok, 'ChaCha still accepts wide counter for 8-byte nonce');
  }

  child_croaks_cleanly(
    "$name keystream(-1)",
    sub { fresh_stream($case)->keystream(-1) },
    qr/^FATAL: output length too large\b/,
  );

  child_croaks_cleanly(
    "$name keystream(huge numeric string)",
    sub { fresh_stream($case)->keystream('999999999999999999999999999999') },
    qr/^FATAL: output length too large\b/,
  );
}

done_testing;
