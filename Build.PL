use 5.006;
use strict;
use warnings;
use Module::Build;
use Config;

my $flags = '-Isrc/ltc/headers -Isrc/ltm -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -DLTM_DESC -DLTM_NO_STDINT_H';
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
  module_name          => 'CryptX',
  dist_abstract        => 'Crypto toolkit',
  dist_author          => 'Karel Miko',
  dist_version_from    => 'lib/CryptX.pm',
  license              => 'perl',
  create_readme        => 1,
  extra_compiler_flags => $flags,
  c_source             => 'src',
  requires             => {
    'perl'          => '5.006',
    'JSON::PP'      => '2.27102',   # encode_json + decode_json
    'Exporter'      => '5.59',      # we need: use Exporter 'import';
  },
  build_requires       => {
    'perl'          => '5.006',
    'JSON::PP'      => '2.27102',   # encode_json + decode_json
    'Exporter'      => '5.59',      # we need: use Exporter 'import';
    'Module::Build' => 0,
    'Test::More'    => 0,
  },
  configure_requires   => {
    'perl'          => '5.006',
    'Module::Build' => 0,
  },
  meta_merge => {
    resources  => {
      repository => 'https://github.com/DCIT/perl-CryptX',
    }
  },
);

$builder->create_build_script;
