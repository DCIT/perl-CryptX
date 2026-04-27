use strict;
use warnings;

use Test::More tests => 6;

use Crypt::Digest qw(digest_file_hex);
use Crypt::Digest::SHAKE;

sub dies_like {
  my ($code, $re, $name) = @_;
  my $err = eval { $code->(); '' };
  $err = $@ if $@;
  like($err, $re, $name);
}

my $path = __FILE__;

my $digest_by_path = Crypt::Digest->new('SHA256')->addfile($path)->hexdigest;
open my $digest_fh, '<', $path or die "open($path): $!";
binmode($digest_fh);
is(
  Crypt::Digest->new('SHA256')->addfile($digest_fh)->hexdigest,
  $digest_by_path,
  'Digest addfile path and handle agree',
);

is(
  digest_file_hex('SHA256', $path),
  $digest_by_path,
  'digest_file_hex path matches OO addfile',
);

open my $digest_fh2, '<', $path or die "open($path): $!";
binmode($digest_fh2);
is(
  digest_file_hex('SHA256', $digest_fh2),
  $digest_by_path,
  'digest_file_hex handle matches OO addfile',
);

dies_like(
  sub { Crypt::Digest->new('SHA256')->addfile([]) },
  qr/invalid handle/,
  'Digest addfile invalid ref rejected',
);

my $shake_by_path = Crypt::Digest::SHAKE->new(128)->addfile($path)->done(32);
open my $shake_fh, '<', $path or die "open($path): $!";
binmode($shake_fh);
is(
  Crypt::Digest::SHAKE->new(128)->addfile($shake_fh)->done(32),
  $shake_by_path,
  'SHAKE addfile path and handle agree',
);

dies_like(
  sub { Crypt::Digest::SHAKE->new(128)->addfile([]) },
  qr/invalid handle/,
  'SHAKE addfile invalid ref rejected',
);
