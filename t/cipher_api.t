use strict;
use warnings;

use Test::More;

use Crypt::Cipher;
use Crypt::Cipher::AES;
use Crypt::Cipher::Blowfish;
use Crypt::Cipher::RC5;

sub run_child {
  my ($code) = @_;
  open(my $fh, '-|', $^X, '-Mblib', '-we', $code) or die "cannot run child: $!";
  local $/;
  my $out = <$fh>;
  close($fh);
  my $status = $?;
  return ($out, $status >> 8, $status & 127);
}

{
  my @cases = (
    {
      label => 'new(1, $key)',
      code  => 'use Crypt::Cipher; my $ok = eval { Crypt::Cipher->new(1, "1234567890123456"); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re    => qr/^error=FATAL: find_cipher failed for '1'/,
    },
    {
      label => 'new([], $key)',
      code  => 'use Crypt::Cipher; my $ok = eval { Crypt::Cipher->new([], "1234567890123456"); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re    => qr/^error=FATAL: invalid cipher name\b/,
    },
    {
      label => 'new({}, $key)',
      code  => 'use Crypt::Cipher; my $ok = eval { Crypt::Cipher->new({}, "1234567890123456"); 1 }; my $err = $@; $err =~ s/\n\z//; print $ok ? "ok\n" : "error=$err\n";',
      re    => qr/^error=FATAL: invalid cipher name\b/,
    },
  );

  for my $case (@cases) {
    my ($out, $exit, $signal) = run_child($case->{code});
    is($signal, 0, "$case->{label} does not crash");
    like($out, $case->{re}, "$case->{label} croaks cleanly");
  }
}

{
  package Local::CipherName;
  use overload q{""} => sub { 'AES' }, fallback => 1;
  package Local::CipherKey;
  use overload q{""} => sub { '1234567890123456' }, fallback => 1;
  package main;

  my $name = bless {}, 'Local::CipherName';
  my $key  = bless {}, 'Local::CipherKey';

  my $c1 = Crypt::Cipher->new($name, '1234567890123456');
  isa_ok($c1, 'Crypt::Cipher', 'base constructor accepts overloaded cipher name');
  is($c1->blocksize, 16, 'overloaded cipher name uses AES');

  my $c2 = Crypt::Cipher->new('AES', $key);
  isa_ok($c2, 'Crypt::Cipher', 'base constructor accepts overloaded key');
  is($c2->encrypt(''), '', 'encrypt empty string passes through unchanged');
  is($c2->decrypt(''), '', 'decrypt empty string passes through unchanged');
}

for my $class (qw(Crypt::Cipher::AES Crypt::Cipher::Blowfish Crypt::Cipher::RC5)) {
  my $key = 'K' x $class->min_keysize;
  my $obj = $class->new($key);
  isa_ok($obj, $class, "$class->new returns subclass instance");
}

done_testing;
