use strict;
use warnings;
use Module::Build;
use Config;

my $src = 'libtom-src';
my $flags = '-Ilibtom-src/headers -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -libtom-src -DLTM_DESC';

$flags   .= ' -DLTC_NO_ASM';

#unless ($ENV{CRYPTX_USE_ASM} || $Config{archname} =~ /MSWin32-x86/) {
#  $flags .= ' -DLTC_NO_ASM';
#}

my $class = Module::Build->subclass(
    class => 'My::Builder',
    code  => <<'CODE',
sub ACTION_gencode {
    my $self = shift;
    $self->depends_on(qw[touch]);
    system($^X, qw[_generators/tt_cipher.pl install_code]);
    system($^X, qw[_generators/tt_digest.pl install_code]);
    system($^X, qw[_generators/tt_mac.pl install_code]);
    system($^X, qw[_generators/tt_mode.pl install_code]);
    return;
}
sub ACTION_gentests {
    my $self = shift;
    $self->depends_on(qw[build]);
    system($^X, qw[-Mblib _generators/tt_cipher.pl install_tests]);
    system($^X, qw[-Mblib _generators/tt_digest.pl install_tests]);
    system($^X, qw[-Mblib _generators/tt_mac.pl install_tests]);
    system($^X, qw[-Mblib _generators/tt_mode.pl install_tests]);
    return;
}
sub ACTION_touch {
    my $self = shift;
    system($^X, qw[-MFile::Touch -e touch('lib/CryptX.xs')]);
    return;
}
sub ACTION_xs {
    my $self = shift;
    $self->depends_on(qw[touch build]);
}
CODE
);

my $builder = $class->new(
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
);

$builder->create_build_script;
