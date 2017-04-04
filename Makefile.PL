use strict;
use warnings;
use ExtUtils::MakeMaker;
use Config;

my @myobjs = map { s|.c$|$Config{obj_ext}|; $_ } grep { $_ !~ m|^src/ltc/\.*tab\.c$| } (
    glob('src/ltm/*.c'),
    glob('src/ltc/*/*.c'),
    glob('src/ltc/*/*/*.c'),
    glob('src/ltc/*/*/*/*.c'),
    glob('src/ltc/*/*/*/*/*.c'),
);
my $myextlib = "src/liballinone$Config{lib_ext}";
my $mycflags = "$Config{cccdlflags} $Config{ccflags} $Config{optimize} -Iltm -Iltc/headers -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -DLTM_DESC";

# gcc with -flto is a trouble maker see https://github.com/DCIT/perl-CryptX/issues/32
my $myar = $mycflags =~ /-flto/ && $Config{gccversion} ? 'gcc-ar' : '$(AR)';

my %eumm_args = (
  NAME             => 'CryptX',
  VERSION_FROM     => 'lib/CryptX.pm',
  AUTHOR           => 'Karel Miko',
  ABSTRACT         => 'Crypto toolkit',
  MIN_PERL_VERSION => '5.006',
  LICENSE          => 'perl_5',
  META_MERGE       => { resources  => { repository => 'https://github.com/DCIT/perl-CryptX', bugtracker => 'https://github.com/DCIT/perl-CryptX/issues' } },
  DEFINE           => '-DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -DLTM_DESC',
  INC              => '-Isrc/ltc/headers -Isrc/ltm',
  LIBS             => [''],
  MYEXTLIB         => $myextlib,
  clean            => { 'FILES' => join(' ', @myobjs, $myextlib) },
);

my $eumm_ver  = eval $ExtUtils::MakeMaker::VERSION;
delete $eumm_args{MIN_PERL_VERSION} if $eumm_ver < 6.48;
delete $eumm_args{META_ADD}         if $eumm_ver < 6.46;
delete $eumm_args{META_MERGE}       if $eumm_ver < 6.46;
delete $eumm_args{LICENSE}          if $eumm_ver < 6.31;

WriteMakefile(%eumm_args);

# ARFLAGS=\$(AR_STATIC_ARGS) RANLIB=\$(RANLIB) AR=\$(AR)

sub MY::postamble {
  my $myextlib = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) ARFLAGS="\$(AR_STATIC_ARGS)" RANLIB="\$(RANLIB)" AR="$myar" CC="\$(CC)" LIB_EXT=\$(LIB_EXT) OBJ_EXT=\$(OBJ_EXT) CFLAGS="$mycflags"
};

  $myextlib = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) -f Makefile.nmake CFLAGS="$mycflags"
} if $^O eq 'MSWin32' && $Config{make} =~ /nmake/ && $Config{cc} =~ /cl/;

  $myextlib = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) CC="$Config{cc}" CFLAGS="$mycflags"
} if $^O eq 'MSWin32' && $Config{cc} =~ /gcc/;

  my $version_patch = q{
versionsync:
	$(NOECHO) perl _generators/version_patch.pl sync

versioninc:
	$(NOECHO) perl _generators/version_patch.pl inc

versionincdev:
	$(NOECHO) perl _generators/version_patch.pl incdev

versiondec:
	$(NOECHO) perl _generators/version_patch.pl dec

versiondecdev:
	$(NOECHO) perl _generators/version_patch.pl decdev
};

  return "$myextlib\n$version_patch";
}
