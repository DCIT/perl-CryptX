use strict;
use warnings;

use Test::More;

plan skip_all => "File::Find not installed" unless eval { require File::Find };
plan skip_all => "Test::Pod not installed" unless eval { require Test::Pod };

my @files;
File::Find::find({ wanted=>sub { push @files, $_ if /\.pm$/ }, no_chdir=>1 }, 'lib');

for my $m (sort @files) {
  Test::Pod::pod_file_ok( $m, "Valid POD in '$m'" );
}

done_testing;