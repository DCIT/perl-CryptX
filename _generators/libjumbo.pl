use strict;
use warnings;

use File::Find 'find';

my @files;
find({ wanted=>sub { push @files, $_ if /\.o$/ }, no_chdir=>1 }, 'src/ltc');

system('ar', 'csr', 'libjumbo.a', @files);
system('ranlib', 'libjumbo.a');