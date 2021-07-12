use strict;
use warnings;
use ExtUtils::MakeMaker;
use Config;

my (@EUMM_INC_LIB, $myarflags, $mycflags);

if ($ENV{CRYPTX_CFLAGS} || $ENV{CRYPTX_LDFLAGS}) {
  # EXPERIMENTAL: use system libraries libtomcrypt + libtommath
  # e.g.
  # CRYPTX_LDFLAGS='-L/usr/local/lib -ltommath -ltomcrypt' CRYPTX_CFLAGS='-DLTM_DESC -I/usr/local/include' perl Makefile.PL
  print "CRYPTX_CFLAGS  = $ENV{CRYPTX_CFLAGS}\n"  if $ENV{CRYPTX_CFLAGS};
  print "CRYPTX_LDFLAGS = $ENV{CRYPTX_LDFLAGS}\n" if $ENV{CRYPTX_LDFLAGS};
  @EUMM_INC_LIB = (
    INC      => $ENV{CRYPTX_CFLAGS},
    LIBS     => [ $ENV{CRYPTX_LDFLAGS} ],
  );
}
else {
  # PREFERRED: use bundled libtomcrypt + libtommath (from ./src subdir)
  my @myobjs = map { s|.c$|$Config{obj_ext}|; $_ } grep { $_ !~ m|^src/ltc/\.*tab\.c$| } (
      glob('src/ltm/*.c'),
      glob('src/ltc/*/*.c'),
      glob('src/ltc/*/*/*.c'),
      glob('src/ltc/*/*/*/*.c'),
      glob('src/ltc/*/*/*/*/*.c'),
  );
  $mycflags = " $Config{ccflags} $Config{cccdlflags} $Config{optimize} "; # keep leading + trailing spaces

  #FIX: this is particularly useful for Debian https://github.com/DCIT/perl-CryptX/pull/39
  $mycflags .= " $ENV{CFLAGS} "   if $ENV{CFLAGS};
  $mycflags .= " $ENV{CPPFLAGS} " if $ENV{CPPFLAGS};

  #### remove all lto hacks - https://github.com/DCIT/perl-CryptX/issues/70
  ## #FIX: gcc with -flto is a trouble maker see https://github.com/DCIT/perl-CryptX/issues/32
  ## #FIX: another issue with "-flto=auto" see https://github.com/DCIT/perl-CryptX/pull/66
  ## $mycflags =~ s/\s-flto\S+\s/ /g; # -flto -flto=auto -flto=jobserver -flto=N ...

  #FIX: avoid -Wwrite-strings -Wcast-qual -pedantic -pedantic-errors -ansi -std=c89
  $mycflags =~ s/\s-pedantic-errors\s/ /g;
  $mycflags =~ s/\s-pedantic\s/ /g;
  $mycflags =~ s/\s-std=c89\s/ /g;
  $mycflags =~ s/\s-ansi\s/ /g;
  $mycflags =~ s/\s-Wwrite-strings\s/ /g;
  $mycflags =~ s/\s-Wcast-qual\s/ /g;

  #FIX: avoid "ar: fatal: Numeric group ID too large" see https://github.com/DCIT/perl-CryptX/issues/33
  $myarflags = '$(AR_STATIC_ARGS)';
  if ($^O ne 'MSWin32' && $Config{ar}) {
    # for ar's "deterministic mode" we need GNU binutils 2.20+ (2009-10-16)
    my $arver = `$Config{ar} --version 2>/dev/null`;
    my ($maj, $min) = $arver =~ /^GNU ar [^\d]*(\d)\.(\d+)\.\d+/s;
    $myarflags = 'rcD' if ($maj && $min && $maj >= 2 && $min >= 20) || $arver=~ /^BSD ar /;
  }

  # turn on extra warnings in AUTHOR_MODE (it is gcc only!!)
  $mycflags = "$mycflags -Wall -Werror -Wextra" if $ENV{AUTHOR_MODE};

  @EUMM_INC_LIB = (
    INC      => $ENV{AUTHOR_MODE} ? '-DLTM_DESC -Isrc/ltc/headers -Isrc/ltm -Wall -Werror -Wextra' #gcc only!!
                                  : '-DLTM_DESC -Isrc/ltc/headers -Isrc/ltm',
    MYEXTLIB => "src/liballinone$Config{lib_ext}",
    clean    => { 'FILES' => join(' ', @myobjs, "src/liballinone$Config{lib_ext}") },
  );
}

my %eumm_args = (
  NAME             => 'CryptX',
  VERSION_FROM     => 'lib/CryptX.pm',
  AUTHOR           => 'Karel Miko',
  ABSTRACT         => 'Cryptographic toolkit',
  MIN_PERL_VERSION => '5.006',
  LICENSE          => 'perl_5',
  PREREQ_PM        => { },
  TEST_REQUIRES    => { 'Test::More' => 0 },
  META_MERGE       => { resources  => { repository => 'https://github.com/DCIT/perl-CryptX', bugtracker => 'https://github.com/DCIT/perl-CryptX/issues' } },
  dist             => { PREOP => 'perldoc -u lib/CryptX.pm | pod2markdown > README.md', TARFLAGS => '--owner=0 --group=0 -cvf' },
  @EUMM_INC_LIB
);

my $eumm_ver = eval $ExtUtils::MakeMaker::VERSION;
delete $eumm_args{MIN_PERL_VERSION}   if $eumm_ver < 6.48;
delete $eumm_args{META_ADD}           if $eumm_ver < 6.46;
delete $eumm_args{META_MERGE}         if $eumm_ver < 6.46;
delete $eumm_args{LICENSE}            if $eumm_ver < 6.31;
delete $eumm_args{CONFIGURE_REQUIRES} if $eumm_ver < 6.52;
delete $eumm_args{BUILD_REQUIRES}     if $eumm_ver < 6.56;
delete $eumm_args{TEST_REQUIRES}      if $eumm_ver < 6.64;

WriteMakefile(%eumm_args);

sub MY::postamble {
  return "" unless $mycflags && $myarflags;

  my $extra_targets = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) ARFLAGS="$myarflags" RANLIB="\$(RANLIB)" AR="\$(AR)" CC="\$(CC)" LIB_EXT=\$(LIB_EXT) OBJ_EXT=\$(OBJ_EXT) CFLAGS="$mycflags"
};

  $extra_targets = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) -f Makefile.nmake CFLAGS="$mycflags"
} if $^O eq 'MSWin32' && $Config{make} =~ /nmake/ && $Config{cc} =~ /cl/;

  $extra_targets = qq{
\$(MYEXTLIB): src/Makefile
	cd src && \$(MAKE) CC="$Config{cc}" CFLAGS="$mycflags"
} if $^O eq 'MSWin32' && $Config{cc} =~ /gcc/;

  $extra_targets .= q{
update-libtom:
	$(NOECHO) perl src/update-libtom.pl
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
gencode:
	$(NOECHO) perl _generators/gen.pl gencode
gentest: all
	$(NOECHO) perl _generators/gen.pl gentest
openssltest: all
	$(NOECHO) perl -Mblib t/openssl/dsa-test.pl
	$(NOECHO) perl -Mblib t/openssl/ecc-test.pl
	$(NOECHO) perl -Mblib t/openssl/rsa-test.pl
rebuild-pre:
	$(RM_F) src/liballinone.a
	$(TOUCH) CryptX.xs
rebuild: rebuild-pre all

};

  return $extra_targets;
}
