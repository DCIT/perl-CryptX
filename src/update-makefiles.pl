#!/usr/bin/env perl

use Modern::Perl;
use File::Find qw(find);
use File::Slurper qw(read_text write_text);
use FindBin;

#remove test files
warn "gonna remove unwanted..\n";
system 'rm', '-rf', "$FindBin::Bin/ltc/encauth/ocb/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/f8/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/lrw/";
system 'rm', '-rf', "$FindBin::Bin/ltc/modes/xts/";
system 'rm', '-rf', "$FindBin::Bin/ltc/pk/katja/";
system 'rm', '-rf', "$FindBin::Bin/ltc/math/gmp_desc.c";
find({ wanted=>sub { unlink $_ if $_ =~ /test\.c$/ && $_ !~ /sha3_test.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltc");

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
