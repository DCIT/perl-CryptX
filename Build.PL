use 5.006;
use strict;
use warnings;
use Module::Build;
use Config;

my $flags = '-I. -Isrc/ltc/headers -Isrc/ltm -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -DLTM_DESC';
#$flags .= ' -Wall';
#$flags .= ' -DLTC_NO_FAST';
#$flags .= ' -DLTC_NO_ASM';

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
sub ACTION_libjumbo {
    my $self = shift;
    $self->depends_on(qw[build]);
    system($^X, '_generators/libjumbo.pl');
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
  module_name          => 'CryptX',                     #0.03
  dist_abstract        => 'Crypto toolkit',             #0.20
  dist_author          => 'Karel Miko',                 #0.20
  dist_version_from    => 'lib/CryptX.pm',              #0.11
  license              => 'perl',                       #0.07
  create_readme        => 1,                            #0.22
  extra_compiler_flags => $flags,                       #0.25
  c_source             => 'src',                        #0.04
  xs_files             => {'CryptX.xs'=>'CryptX.xs'},   #0.25
  requires             => {                             #0.21
    'perl'          => '5.006',
  },
  build_requires       => {                             #0.21
    'perl'          => '5.006',
    'Module::Build' => 0,
  },
  configure_requires   => {                             #0.30
    'perl'          => '5.006',
    'Module::Build' => 0,
  },
  meta_merge => {                                       #0.28
    resources  => {
      repository => 'https://github.com/DCIT/perl-CryptX',
    }
  },
);

$builder->create_build_script;
