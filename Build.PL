use strict;
use warnings;
use Module::Build;
use Config;

my $src = 'libtom-src';
my $flags = '-Ilibtom-src/headers -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -libtom-src -DLTM_DESC';

$flags   .= ' -DLTC_NO_ASM';

####-DLTC_SMALL_CODE #optimize for SIZE 
#unless ($ENV{CRYPTX_USE_ASM} || $Config{archname} =~ /MSWin32-x86/) {
#  # avoid on MSWin32/x64 + gcc
#  $flags .= ' -DLTC_NO_ASM';
#}

### DSA benchmark keygen(30,256)
# Win7/32bit fastmath + NO_ASM     7.4s
# Win7/32bit fastmath              2.8s
# Win7/32bit tommath + NO_ASM      5.6s
# Win7/32bit tommath               5.3s
# Win7/64bit tommath + NO_ASM      xx.4s

Module::Build->new(
  module_name          => 'CryptX',
  dist_abstract        => 'Crypto toolkit',
  dist_author          => 'Karel Miko',
  dist_version_from    => 'lib/CryptX.pm',
  license              => 'perl',
  extra_compiler_flags => $flags,
  c_source             => $src,
  requires             => {
    'MIME::Base64'  => 0,
  },
  build_requires       => {
    'MIME::Base64'  => 0,
    'Module::Build' => 0,
    'Test::More'    => '0.88', # done_testing available since 0.88
    'File::Find'    => 0,
  },
  configure_requires   => {
    'Module::Build' => 0,
  },
)->create_build_script;
