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
my $mycflags = "$Config{ccflags} $Config{cccdlflags} $Config{optimize}";

#FIX: gcc with -flto is a trouble maker see https://github.com/DCIT/perl-CryptX/issues/32
$mycflags =~ s/-flto\b//g;

#FIX: avoid -Wwrite-strings -Wcast-qual -pedantic -pedantic-errors -ansi -std=c89
$mycflags =~ s/-pedantic\b//g;
$mycflags =~ s/-pedantic-errors\b//g;
$mycflags =~ s/-std=c89\b//g;
$mycflags =~ s/-ansi\b//g;
$mycflags =~ s/-Wwrite-strings\b//g;
$mycflags =~ s/-Wcast-qual\b//g;

#FIX: this is particularly useful for Debian https://github.com/DCIT/perl-CryptX/pull/39
$mycflags = "$ENV{CFLAGS} $ENV{CPPFLAGS}" if $ENV{CFLAGS} || $ENV{CPPFLAGS};

#FIX: avoid "ar: fatal: Numeric group ID too large" see https://github.com/DCIT/perl-CryptX/issues/33
my $myarflags = '$(AR_STATIC_ARGS)';
if ($^O ne 'MSWin32' && $Config{ar}) {
  # for ar's "deterministic mode" we need GNU binutils 2.20+ (2009-10-16)
  my $arver = `$Config{ar} --version 2>/dev/null`;
  my ($maj, $min) = $arver =~ /^GNU ar [^\d]*(\d)\.(\d+)\.\d+/s;
  $myarflags = 'rcD' if ($maj && $min && $maj >= 2 && $min >= 20) || $arver=~ /^BSD ar /;
}

my %eumm_args = (
  NAME             => 'CryptX',
  VERSION_FROM     => 'lib/CryptX.pm',
  AUTHOR           => 'Karel Miko',
  ABSTRACT         => 'Crypto toolkit',
  MIN_PERL_VERSION => '5.006',
  LICENSE          => 'perl_5',
  META_MERGE       => { resources  => { repository => 'https://github.com/DCIT/perl-CryptX', bugtracker => 'https://github.com/DCIT/perl-CryptX/issues' } },
  dist             => { 'PREOP' => 'perldoc -u lib/CryptX.pm | pod2markdown > README.md' },
  ($ENV{CRYPTX_CFLAGS} || $ENV{CRYPTX_LDFLAGS})
  ?
  (
    # e.g. CRYPTX_LDFLAGS='-L/usr/local/lib -ltommath -ltomcrypt' CRYPTX_CFLAGS='-DLTM_DESC -I/usr/local/include' perl Makefile.PL
    INC      => $ENV{CRYPTX_CFLAGS},
    LIBS     => [ $ENV{CRYPTX_LDFLAGS} ],
  )
  :
  (
    # bundled libtomcrypt + libtommath
    INC      => '-DLTM_DESC -Isrc/ltc/headers -Isrc/ltm',
    MYEXTLIB => $myextlib,
    clean    => { 'FILES' => join(' ', @myobjs, $myextlib) },
  )
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
	cd src && \$(MAKE) ARFLAGS="$myarflags" RANLIB="\$(RANLIB)" AR="\$(AR)" CC="\$(CC)" LIB_EXT=\$(LIB_EXT) OBJ_EXT=\$(OBJ_EXT) CFLAGS="$mycflags"
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
gencode:
	$(NOECHO) perl _generators/gen.pl gencode
gentest: all
	$(NOECHO) perl _generators/gen.pl gentest
openssltest: all
	$(NOECHO) perl -Mblib t/openssl/dsa-test.pl
	$(NOECHO) perl -Mblib t/openssl/ecc-test.pl
	$(NOECHO) perl -Mblib t/openssl/rsa-test.pl
};

  return "$myextlib\n$version_patch";
}
