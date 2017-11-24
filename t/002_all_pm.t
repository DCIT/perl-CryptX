use strict;
use warnings;

use Test::More;

plan skip_all => "File::Find not installed" unless eval { require File::Find };
plan tests => 1;


sub _read {
  open my $fh, "<", shift;
  binmode $fh;
  return do { local $/; <$fh> };
}

my @files;
File::Find::find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

my @err;
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
