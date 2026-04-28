use strict;
use warnings;

use Test::More tests => 14;

use Crypt::Cipher;
use Crypt::Cipher::AES;
use Crypt::Cipher::Blowfish;
use Crypt::Cipher::RC5;

{
  my @cases = (
    {
      label => 'new(1, $key)',
      action => sub { Crypt::Cipher->new(1, "1234567890123456") },
      re    => qr/^error=FATAL: find_cipher failed for '1'/,
    },
    {
      label => 'new([], $key)',
      action => sub { Crypt::Cipher->new([], "1234567890123456") },
      re    => qr/^error=FATAL: invalid cipher name\b/,
    },
    {
      label => 'new({}, $key)',
      action => sub { Crypt::Cipher->new({}, "1234567890123456") },
      re    => qr/^error=FATAL: invalid cipher name\b/,
    },
  );

  for my $case (@cases) {
    my $ok = eval { $case->{action}->(); 1 };
    ok(!$ok, "$case->{label} croaks");
    like("error=$@", $case->{re}, "$case->{label} croak text");
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
