use strict;
use warnings;
use Module::Build;

my $flags = '-Ilibtom-src/headers -Ilibtom-src -DLTC_SOURCE -DLTC_NO_TEST';
$flags .= ' -DLTC_NO_PK -DLTC_NO_PKCS -DLTC_NO_MATH'; # no public key crypto yet
$flags .= ' -DLTC_NO_MODES';            # no chaining modes yet
$flags .= ' -DLTC_NO_PRNGS';            # no pseudo random yet
$flags .= ' -DLTC_NO_PROTOTYPES';       # MSWin32/VC6
$flags .= ' -DLTC_NO_ASM';              # MSWin32/x64

Module::Build->new(
  module_name          => 'CryptX',
  dist_abstract        => 'Crypto toolkit',
  dist_author          => 'Karel Miko',
  dist_version_from    => 'lib/CryptX.pm',
  license              => 'perl',
  requires             => {
    'Carp'        => 0,
  },
  build_requires       => {
    'Carp'        => 0,
    'Test::More'  => 0,
  },
  c_source             => 'libtom-src',
  extra_compiler_flags => $flags,
)->create_build_script;
