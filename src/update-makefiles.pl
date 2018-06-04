#!/usr/bin/env perl

use Modern::Perl;
use File::Find qw(find);
use File::Slurper qw(read_text write_text);
use FindBin;

warn "gonna remove unwanted..\n";
system 'rm', '-rf', "$FindBin::Bin/ltc/encauth/ocb/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/f8/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/lrw/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/xts/";
system 'rm', '-rf', "$FindBin::Bin/ltc/pk/katja/";
system 'rm', '-rf', "$FindBin::Bin/ltc/math/gmp_desc.c";

### get rid of bn_mp_set_long_long + bn_mp_get_long_long
system 'rm', '-rf', "$FindBin::Bin/ltm/bn_mp_set_long_long.c";
system 'rm', '-rf', "$FindBin::Bin/ltm/bn_mp_get_long_long.c";
system 'sed', '-i', 's,^\(int *mp_set_long_long.*\),/* \1 */,', 'src//ltm/tommath.h';
system 'sed', '-i', 's,^\(unsigned *long *long *mp_get_long_long.*\),/* \1 */,', 'src//ltm/tommath.h';

### MSVC hack required for VC6 compatibility
#  #ifdef _MSC_VER
#  typedef unsigned __int64 mp_word
#  #else
#  typedef unsigned long long mp_word;
#  #endif
system 'sed', '-i', 's,^\(typedef *unsigned *long *long *mp_word;\)$,#ifdef _MSC_VER\ntypedef unsigned __int64 mp_word;\n#else\n\1 /* PATCHED */\n#endif,', 'src//ltm/tommath.h';

find({ wanted=>sub { unlink $_ if -f $_ && $_ =~ /test\.c$/ && $_ !~ /sha3_test.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltc");
find({ wanted=>sub { unlink $_ if -f $_ && $_ =~ /\.o$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm", "$FindBin::Bin/ltc");

#fix modes
warn "gonna chmod..\n";
find({ wanted=>sub { system "chmod -x $_" if -f $_ && -x $_ && $_ =~ /\.(c|h)/ }, no_chdir=>1 }, "$FindBin::Bin/ltm", "$FindBin::Bin/ltc");
 
my @objs = ();
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ && $_ !~ /tab\.c$/}, no_chdir=>1 }, "$FindBin::Bin/ltc");
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm");

my $o   = "OBJS=" . (join " ", map { s/\.c$/.o/r }   map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;
my $obj = "OBJS=" . (join " ", map { s/\.c$/.obj/r } map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;

write_text("$FindBin::Bin/Makefile", read_text("$FindBin::Bin/Makefile") =~ s/OBJS=.+?\.o\n/$o\n/sr);
write_text("$FindBin::Bin/Makefile.nmake", read_text("$FindBin::Bin/Makefile.nmake") =~ s/OBJS=.+?\.obj\n/$obj\n/sr);
