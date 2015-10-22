use 5.006;
use strict;
use warnings;
use Module::Build;
use Config;

my $flags = '-Isrc/ltc/headers -Isrc/ltm -DLTC_SOURCE -DLTC_NO_TEST -DLTC_NO_PROTOTYPES -DLTM_DESC';
#$flags .= ' -Wall';
#$flags .= ' -DLTC_NO_ASM' if $ENV{CRYPTX_NO_ASM} || $Config{archname} !~ /(MSWin32-(x86|x64)|(i.86|x86_64)-linux|(i.86|amd64)-(freebsd|openbsd)|cygwin|darwin)/;
#$flags .= ' -DLTC_NO_FAST' if $^O eq 'cygwin' && $Config{cc} =~ /gcc/ && $Config{gccversion} =~ /^3\./;

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
    'MIME::Base64'  => '3.11',      # (en|de)code_base64url
    'JSON::MaybeXS' => '1.003005',  # (en|de)code_json
    'Exporter'      => '5.59',      # we need: use Exporter 'import';
  },
  build_requires       => {
    'Module::Build' => 0,
    'MIME::Base64'  => '3.11',      # (en|de)code_base64url
    'JSON::MaybeXS' => '1.003005',  # (en|de)code_json
    'Test::More'    => '0.88',      # we need: done_testing
    'File::Find'    => 0,
  },
  configure_requires   => {
    'Module::Build' => 0,
  },
  meta_merge => {
    resources  => {
      repository => 'https://github.com/DCIT/perl-CryptX',
    }
  },
);

$builder->create_build_script;
