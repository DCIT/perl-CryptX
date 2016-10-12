use 5.014;
use strict;
use warnings;

use File::Find qw(find);
use File::Slurp qw(read_file write_file);

die "bad arg\n" unless $ARGV[0] && $ARGV[0] =~ /^(inc|dec|incdev|decdev|sync)$/;

my $crx = read_file('lib/CryptX.pm');
my ($ver) = $crx =~ /\nour \$VERSION = '([0-9_.]+)';/;
die "invalid current version '$ver'" unless $ver =~ /^(\d+\.\d+|\d+\.\d+_\d+)$/ && $ver !~ /_0*$/;

if ($ARGV[0] ne 'sync') {
  $ver =~ s/_//;
  $ver = sprintf("%.3f", $ver + 0.001) if $ARGV[0] eq 'inc';
  $ver = sprintf("%.3f", $ver - 0.001) if $ARGV[0] eq 'dec';
  $ver = sprintf("%.6f", $ver + 0.000001) =~ s/(...)$/_$1/r if $ARGV[0] eq 'incdev';
  $ver = sprintf("%.6f", $ver - 0.000001) =~ s/(...)$/_$1/r if $ARGV[0] eq 'decdev';
  die "invalid next version '$ver'" unless $ver =~ /^(\d+\.\d+|\d+\.\d+_\d+)$/ && $ver !~ /_0*$/;
}

my @files;
find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

for my $f (@files) {
  next if $ARGV[0] eq 'sync' && $f eq 'lib/CryptX.pm';
  my $txt = read_file($f, {binmode=>':unix'});
  #$txt =~ s/\nuse warnings;/\nuse warnings;\nour \$VERSION = '$ver';/;
  $txt =~ s/\nour \$VERSION = '([0-9_.]+)';/\nour \$VERSION = '$ver';/;
  die "incorrect '$f'\n" unless $txt =~ /\nour \$VERSION = '$ver';/s;
  write_file($f, {binmode=>':unix'}, $txt);
}


