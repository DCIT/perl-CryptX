#!/usr/bin/env perl

use Modern::Perl;
use File::Find qw(find);
use File::Slurper qw(read_text write_text);
use File::Glob qw(bsd_glob);
use FindBin;

my $ltc_branch = "some-improvements";
my $ltm_branch = "develop";
my $tmpdir = "/tmp/libtom.git.checkout.$$";

warn "update libtommath from github (branch: $ltm_branch)..\n";
system 'rm', '-rf', bsd_glob("$FindBin::Bin/ltm/*");
system "rm -rf $tmpdir; mkdir $tmpdir";
# IMPORTANT HACK: make -C $tmpdir c89
system "git clone -b $ltm_branch https://github.com/libtom/libtommath.git $tmpdir && make -C $tmpdir c89 && cp $tmpdir/LICENSE $tmpdir/*.c $tmpdir/tom*.h $FindBin::Bin/ltm/ && echo ok";
system "(cd $tmpdir && git log  --pretty='%h %ai %s') | head -1";

warn "update libtomcrypt from github (branch: $ltc_branch)..\n";
system 'rm', '-rf', bsd_glob("$FindBin::Bin/ltc/*");
system "rm -rf $tmpdir; mkdir $tmpdir";
system "git clone -b $ltc_branch https://github.com/libtom/libtomcrypt.git $tmpdir && cp -R $tmpdir/LICENSE $tmpdir/src/* $FindBin::Bin/ltc/ && echo ok";
system "(cd $tmpdir && git log  --pretty='%h %ai %s') | head -1";

system "rm -rf $tmpdir";

### another style
#system "wget https://github.com/libtom/libtomcrypt/tarball/$ltc_branch -q -O - | tar xz --wildcards --transform 's,^libtom.*/src/,,' -C '$FindBin::Bin/ltc' 'libtom*/src/*'";
#system "wget https://github.com/libtom/libtommath/tarball/$ltm_branch -q -O - | tar xz --wildcards --transform 's,^libtom.*/,,' -C '$FindBin::Bin/ltm' 'libtom*/bn*.c' 'libtom*/tom*.h'";

warn "gonna remove unwanted..\n";
system 'rm', '-rf', "$FindBin::Bin/ltc/encauth/ocb/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/f8/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/lrw/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/xts/";
system 'rm', '-rf', "$FindBin::Bin/ltc/pk/katja/";
system 'rm', '-rf', "$FindBin::Bin/ltc/math/gmp_desc.c";
# ltm
system 'rm', '-rf', "$FindBin::Bin/ltm/mp_get_double.c";
system 'rm', '-rf', "$FindBin::Bin/ltm/mp_set_double.c";

find({ wanted=>sub { unlink $_ if -f $_ && $_ =~ /test\.c$/ && $_ !~ /sha3_test.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltc");
find({ wanted=>sub { unlink $_ if -f $_ && $_ =~ /\.o$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm", "$FindBin::Bin/ltc");

# hacks
system 'cp', 'src/patched_tommath_c89.h', 'src/ltm/tommath_c89.h';
system 'cp', 'src/patched_s_mp_rand_platform.c', 'src/ltm/s_mp_rand_platform.c';
system 'sed', '-i', 's,SIZE_MAX,0xFFFFFFFF,', 'src/ltc/math/ltm_desc.c';
system 'sed', '-i', 's, bool res;, mp_bool res;,', 'src/ltc/math/ltm_desc.c';
system 'sed', '-i', 's,#include <stdbool.h>,/*#include <stdbool.h>*/,', 'src/ltc/math/ltm_desc.c';

#fix modes
warn "gonna chmod..\n";
find({ wanted=>sub { system "chmod -x $_" if -f $_ && -x $_ && $_ =~ /\.(c|h)/ }, no_chdir=>1 }, "$FindBin::Bin/ltm", "$FindBin::Bin/ltc");

my @objs = ();
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ && $_ !~ /tab\.c$/}, no_chdir=>1 }, "$FindBin::Bin/ltc");
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm");

my $o   = "OBJS=" . (join " ", map { s/\.c$/.o/r }   map { s!^.*/(ltm|ltc)/!$1/!r } sort @objs) =~ s/(.{80}) /$1 \\\n/gr;
my $obj = "OBJS=" . (join " ", map { s/\.c$/.obj/r } map { s!^.*/(ltm|ltc)/!$1/!r } sort @objs) =~ s/(.{80}) /$1 \\\n/gr;

write_text("$FindBin::Bin/Makefile", read_text("$FindBin::Bin/Makefile") =~ s/OBJS=.+?\.o\n/$o\n/sr);
write_text("$FindBin::Bin/Makefile.nmake", read_text("$FindBin::Bin/Makefile.nmake") =~ s/OBJS=.+?\.obj\n/$obj\n/sr);
