use strict;
use warnings;

use Test::More;
use Test::Pod;
use File::Find qw(find);

my @files;
find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

for my $m (sort @files) {
  pod_file_ok( $m, "Valid POD in '$m'" );
}

done_testing;