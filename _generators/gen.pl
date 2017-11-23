use strict;
use warnings;

if ($ARGV[0] && $ARGV[0] =~ /genco/) {
  system($^X, qw[_generators/tt_cipher.pl install_code]);
  system($^X, qw[_generators/tt_digest.pl install_code]);
  system($^X, qw[_generators/tt_mac.pl install_code]);
  system($^X, qw[_generators/tt_mode.pl install_code]);
}
elsif ($ARGV[0] && $ARGV[0] =~ /gente/) {
  die "blib dir not found, run 'make all'\n" unless -d 'blib';
  system($^X, qw[-Mblib _generators/tt_cipher.pl install_tests]);
  system($^X, qw[-Mblib _generators/tt_digest.pl install_tests]);
  system($^X, qw[-Mblib _generators/tt_mac.pl install_tests]);
  system($^X, qw[-Mblib _generators/tt_mode.pl install_tests]);
}
else {
  die "usage:\n $0 gencode\n $0 gentest\n";
}