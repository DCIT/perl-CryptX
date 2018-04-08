use strict;
use warnings;

use Test::More;

plan skip_all => "set AUTHOR_MODE to enable this test (developer only!)" unless $ENV{AUTHOR_MODE};
plan skip_all => "File::Find not installed" unless eval { require File::Find };
plan tests => 1;


sub _read {
  open my $fh, "<", shift;
  binmode $fh;
  return do { local $/; <$fh> };
}

my @err;
my $cryptx = _read("lib/CryptX.pm");
my $compile_t = _read("t/001_compile.t");
my @files;
File::Find::find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

for my $m (sort @files) {
  my $content = _read($m);
  push @err, "ERROR: no newline at the end '$m'" unless $content =~ /\n$/s;
  push @err, "ERROR: avoid __END__ '$m'"         if $content =~ /__END__/s;
  push @err, "ERROR: =pod ... =cut '$m'"         unless $content =~ /=pod\n.*?=cut\n$/s;
  push @err, "ERROR: trailing whitespace '$m'"   if $content =~ / \n/s;
  push @err, "ERROR: avoid tabs '$m'"            if $content =~ /\t/s;
  push @err, "ERROR: avoid CRLF '$m'"            if $content =~ /\r/s;
  $m =~ s|[\\/]|::|g;
  $m =~ s|^lib::||;
  $m =~ s|\.pm$||;
  push @err, "ERROR: '$m' is missing in CryptX.pm"  unless $cryptx =~ /L<$m>/s || $m =~ /^(CryptX|Math::BigInt::LTM|Crypt::(PK|Mode|Mac|AuthEnc|Checksum))$/;
  push @err, "ERROR: '$m' is missing in 001_compile.t"  unless $compile_t =~ /\nuse $m;/s;
  eval "use $m; 1;" or push @err, "ERROR: 'use $m' failed";
}

my @others = ('CryptX.xs');
File::Find::find({ wanted=>sub { push @others, $_ if /\.inc$/ }, no_chdir=>1 }, 'inc');
File::Find::find({ wanted=>sub { push @others, $_ if /\.(t|pl)$/ }, no_chdir=>1 }, 't');

for my $m (sort @others) {
  my $content = _read($m);
  push @err, "ERROR: no newline at the end '$m'" unless $content =~ /\n$/s;
  push @err, "ERROR: trailing whitespace '$m'"   if $content =~ / \n/s;
  push @err, "ERROR: avoid tabs '$m'"            if $content =~ /\t/s;
  push @err, "ERROR: avoid CRLF '$m'"            if $content =~ /\r/s;
}

warn "$_\n" for (@err);
die if @err;

ok 1, 'all done';
