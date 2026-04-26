use strict;
use warnings;

use Test::More;

use Crypt::Mac::BLAKE2b qw(blake2b_hex);
use Crypt::Mac::HMAC qw(hmac_hex);
use Crypt::Mac::OMAC;

{
  package Local::Stringy;
  use overload '""' => sub { $_[0]->{value} }, fallback => 1;
  sub new { bless { value => $_[1] }, $_[0] }
}

sub dies_like {
  my ($code, $re, $name) = @_;
  my $err = eval { $code->(); '' };
  $err = $@ if $@;
  like($err, $re, $name);
}

dies_like(
  sub { Crypt::Mac::HMAC->new('SHA256', undef) },
  qr/key must be string\/buffer scalar/,
  'HMAC OO undef key rejected',
);
dies_like(
  sub { hmac_hex('SHA256', undef, 'abc') },
  qr/key must be string\/buffer scalar/,
  'HMAC functional undef key rejected',
);

is(
  Crypt::Mac::HMAC->new('SHA256', '')->add('abc')->hexmac,
  hmac_hex('SHA256', '', 'abc'),
  'HMAC OO and functional empty key agree',
);

my $h_num = 123;
is(
  Crypt::Mac::HMAC->new('SHA256', $h_num)->add('abc')->hexmac,
  hmac_hex('SHA256', $h_num, 'abc'),
  'HMAC OO and functional numeric key agree',
);

my $h_str = Local::Stringy->new('key');
is(
  Crypt::Mac::HMAC->new('SHA256', $h_str)->add('abc')->hexmac,
  hmac_hex('SHA256', $h_str, 'abc'),
  'HMAC OO and functional overloaded key agree',
);
dies_like(
  sub { Crypt::Mac::HMAC->new('NoSuchHash', 'key') },
  qr/find_hash failed/,
  'HMAC OO invalid hash error uses find_hash spelling',
);
dies_like(
  sub { hmac_hex('NoSuchHash', 'key', 'abc') },
  qr/find_hash failed/,
  'HMAC functional invalid hash error uses find_hash spelling',
);

dies_like(
  sub { Crypt::Mac::BLAKE2b->new(32, undef) },
  qr/key must be string\/buffer scalar/,
  'BLAKE2b OO undef key rejected',
);
dies_like(
  sub { blake2b_hex(32, undef, 'abc') },
  qr/key must be string\/buffer scalar/,
  'BLAKE2b functional undef key rejected',
);

dies_like(
  sub { Crypt::Mac::BLAKE2b->new(32, '') },
  qr/failed:/,
  'BLAKE2b OO empty key still rejected by init',
);
dies_like(
  sub { blake2b_hex(32, '', 'abc') },
  qr/failed:/,
  'BLAKE2b functional empty key still rejected by init',
);

my $b_num = 123;
is(
  Crypt::Mac::BLAKE2b->new(32, $b_num)->add('abc')->hexmac,
  blake2b_hex(32, $b_num, 'abc'),
  'BLAKE2b OO and functional numeric key agree',
);

my $b_str = Local::Stringy->new('key');
is(
  Crypt::Mac::BLAKE2b->new(32, $b_str)->add('abc')->hexmac,
  blake2b_hex(32, $b_str, 'abc'),
  'BLAKE2b OO and functional overloaded key agree',
);

dies_like(
  sub { Crypt::Mac::OMAC->new('NoSuchCipher', '1234567890123456') },
  qr/find_cipher failed/,
  'OMAC invalid cipher error uses find_cipher spelling',
);

my $path = __FILE__;
my $mac_by_path = Crypt::Mac::HMAC->new('SHA256', 'key')->addfile($path)->hexmac;
open my $mac_fh, '<', $path or die "open($path): $!";
binmode($mac_fh);
is(
  Crypt::Mac::HMAC->new('SHA256', 'key')->addfile($mac_fh)->hexmac,
  $mac_by_path,
  'HMAC addfile path and handle agree',
);

dies_like(
  sub { Crypt::Mac::HMAC->new('SHA256', 'key')->addfile([]) },
  qr/invalid handle/,
  'HMAC addfile invalid ref rejected',
);

done_testing;
