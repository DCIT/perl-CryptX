use strict;
use warnings;

use Config ();
use Test::More tests => 75;
use Data::Dumper ();

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

sub stream_croaks_like {
  my ($label, $code, $pattern) = @_;
  my $ok;
  {
    local $SIG{__WARN__} = sub { };
    $ok = eval $code;
  }
  ok(!$ok, "$label croaks");
  like($@, $pattern, "$label croak message");
}

for my $case (@cases) {
  my $name = $case->{name};
  my $class = $case->{class};
  my $args_src = Data::Dumper->new([$case->{args}])->Terse(1)->Indent(0)->Dump;

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
    SKIP: {
      skip 'requires 64-bit Perl integers', 2 if ($Config::Config{ivsize} || 0) < 8;

      my $overflow_ok = eval { $class->new("K" x 32, "N" x 12, 4294967296); 1 };
      ok(!$overflow_ok, 'ChaCha rejects oversized counter for 12-byte nonce');
      like($@, qr/^FATAL: chacha counter too large for 12-byte nonce\b/, 'ChaCha oversized counter croak text');
    }

    my $wide_counter_ok = eval { $class->new("K" x 32, "N" x 8, 4294967296); 1 };
    ok($wide_counter_ok, 'ChaCha still accepts wide counter for 8-byte nonce');
  }

  stream_croaks_like(
    "$name keystream(-1)",
    qq{use $class; my \$args = $args_src; $class->new(\@{\$args})->keystream(-1); 1;},
    qr/^FATAL: output length too large\b/,
  );

  stream_croaks_like(
    "$name keystream(huge numeric string)",
    qq{use $class; my \$args = $args_src; $class->new(\@{\$args})->keystream('999999999999999999999999999999'); 1;},
    qr/^FATAL: output length too large\b/,
  );
}
