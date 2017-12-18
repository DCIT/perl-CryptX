#!/usr/bin/env perl

use Modern::Perl;
use File::Find qw(find);
use File::Slurper qw(read_text write_text);
use FindBin;

warn "gonna chmod..\n";
find({ wanted=>sub { system "chmod -x $_" if -f $_ && -x $_ && $_ =~ /\.(c|h)/ }, no_chdir=>1 }, "$FindBin::Bin/ltm", "$FindBin::Bin/ltc");
 
my @objs = ();
warn "gonna find ltc..\n";
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ && $_ !~ /tab\.c$/}, no_chdir=>1 }, "$FindBin::Bin/ltc");
warn "gonna find ltm..\n";
find({ wanted=>sub { push @objs, $_ if $_ =~ /\.c$/ }, no_chdir=>1 }, "$FindBin::Bin/ltm");

my $o   = "OBJS=" . (join " ", map { s/\.c$/.o/r }   map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;
my $obj = "OBJS=" . (join " ", map { s/\.c$/.obj/r } map { s!^.*/(ltm|ltc)/!$1/!r } @objs) =~ s/(.{80}) /$1 \\\n/gr;

warn "gonna write makefiles..\n";
write_text("$FindBin::Bin/Makefile", read_text("$FindBin::Bin/Makefile") =~ s/OBJS=.+?\.o\n/$o\n/sr);
write_text("$FindBin::Bin/Makefile.nmake", read_text("$FindBin::Bin/Makefile.nmake") =~ s/OBJS=.+?\.obj\n/$obj\n/sr);
