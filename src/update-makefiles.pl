#!/usr/bin/env perl

use Modern::Perl;
use File::Find qw(find);
use File::Slurper qw(read_text write_text);
use FindBin;
 
my @objs = ();
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ && $_ !~ /tab\.c$/}, no_chdir=>1 }, "$FindBin::Bin/ltc");
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm");

my $o   = "OBJS=" . (join " ", map { s/\.c$/.o/r }   map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;
my $obj = "OBJS=" . (join " ", map { s/\.c$/.obj/r } map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;

write_text("$FindBin::Bin/Makefile", read_text("$FindBin::Bin/Makefile") =~ s/OBJS=.+?\.o\n/$o\n/sr);
write_text("$FindBin::Bin/Makefile.nmake", read_text("$FindBin::Bin/Makefile.nmake") =~ s/OBJS=.+?\.obj\n/$obj\n/sr);
