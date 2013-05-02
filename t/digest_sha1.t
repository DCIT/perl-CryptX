### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 7*3 + 8*4 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_base64 digest_file digest_file_hex digest_file_base64 );
use Crypt::Digest::SHA1 qw( sha1 sha1_hex sha1_base64 sha1_file sha1_file_hex sha1_file_base64 );

is( Crypt::Digest::hashsize('SHA1'), 20, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA1'), 20, 'hashsize/2');
is( Crypt::Digest::SHA1::hashsize, 20, 'hashsize/3');
is( Crypt::Digest::SHA1->hashsize, 20, 'hashsize/4');
is( Crypt::Digest->new('SHA1')->hashsize, 20, 'hashsize/5');
is( Crypt::Digest::SHA1->new->hashsize, 20, 'hashsize/6');

is( sha1(""), pack("H*","da39a3ee5e6b4b0d3255bfef95601890afd80709"), 'sha1 (raw/1)');
is( sha1_hex(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709", 'sha1 (hex/1)');
is( sha1_base64(""), "2jmj7l5rSw0yVb/vlWAYkK/YBwk=", 'sha1 (base64/1)');
is( digest_data('SHA1', ""), pack("H*","da39a3ee5e6b4b0d3255bfef95601890afd80709"), 'sha1 (digest_data_raw/1)');
is( digest_data_hex('SHA1', ""), "da39a3ee5e6b4b0d3255bfef95601890afd80709", 'sha1 (digest_data_hex/1)');
is( digest_data_base64('SHA1', ""), "2jmj7l5rSw0yVb/vlWAYkK/YBwk=", 'sha1 (digest_data_base64/1)');
is( Crypt::Digest::SHA1->new->add("")->hexdigest, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 'sha1 (OO/1)');

is( sha1(123), pack("H*","40bd001563085fc35165329ea1ff5c5ecbdbbeef"), 'sha1 (raw/2)');
is( sha1_hex(123), "40bd001563085fc35165329ea1ff5c5ecbdbbeef", 'sha1 (hex/2)');
is( sha1_base64(123), "QL0AFWMIX8NRZTKeof9cXsvbvu8=", 'sha1 (base64/2)');
is( digest_data('SHA1', 123), pack("H*","40bd001563085fc35165329ea1ff5c5ecbdbbeef"), 'sha1 (digest_data_raw/2)');
is( digest_data_hex('SHA1', 123), "40bd001563085fc35165329ea1ff5c5ecbdbbeef", 'sha1 (digest_data_hex/2)');
is( digest_data_base64('SHA1', 123), "QL0AFWMIX8NRZTKeof9cXsvbvu8=", 'sha1 (digest_data_base64/2)');
is( Crypt::Digest::SHA1->new->add(123)->hexdigest, "40bd001563085fc35165329ea1ff5c5ecbdbbeef", 'sha1 (OO/2)');

is( sha1("test\0test\0test\n"), pack("H*","ea50a3b39d7337f9232e1a89d97919465592f1e2"), 'sha1 (raw/3)');
is( sha1_hex("test\0test\0test\n"), "ea50a3b39d7337f9232e1a89d97919465592f1e2", 'sha1 (hex/3)');
is( sha1_base64("test\0test\0test\n"), "6lCjs51zN/kjLhqJ2XkZRlWS8eI=", 'sha1 (base64/3)');
is( digest_data('SHA1', "test\0test\0test\n"), pack("H*","ea50a3b39d7337f9232e1a89d97919465592f1e2"), 'sha1 (digest_data_raw/3)');
is( digest_data_hex('SHA1', "test\0test\0test\n"), "ea50a3b39d7337f9232e1a89d97919465592f1e2", 'sha1 (digest_data_hex/3)');
is( digest_data_base64('SHA1', "test\0test\0test\n"), "6lCjs51zN/kjLhqJ2XkZRlWS8eI=", 'sha1 (digest_data_base64/3)');
is( Crypt::Digest::SHA1->new->add("test\0test\0test\n")->hexdigest, "ea50a3b39d7337f9232e1a89d97919465592f1e2", 'sha1 (OO/3)');


is( sha1_file('t/data/binary-test.file'), pack("H*","8fde043b787662863a83f0c55f2517ca6b947fdc"), 'sha1 (raw/file/1)');
is( sha1_file_hex('t/data/binary-test.file'), "8fde043b787662863a83f0c55f2517ca6b947fdc", 'sha1 (hex/file/1)');
is( sha1_file_base64('t/data/binary-test.file'), "j94EO3h2YoY6g/DFXyUXymuUf9w=", 'sha1 (base64/file/1)');
is( digest_file('SHA1', 't/data/binary-test.file'), pack("H*","8fde043b787662863a83f0c55f2517ca6b947fdc"), 'sha1 (digest_file_raw/file/1)');
is( digest_file_hex('SHA1', 't/data/binary-test.file'), "8fde043b787662863a83f0c55f2517ca6b947fdc", 'sha1 (digest_file_hex/file/1)');
is( digest_file_base64('SHA1', 't/data/binary-test.file'), "j94EO3h2YoY6g/DFXyUXymuUf9w=", 'sha1 (digest_file_base64/file/1)');
is( Crypt::Digest::SHA1->new->addfile('t/data/binary-test.file')->hexdigest, "8fde043b787662863a83f0c55f2517ca6b947fdc", 'sha1 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA1->new->addfile($fh)->hexdigest, "8fde043b787662863a83f0c55f2517ca6b947fdc", 'sha1 (OO/filehandle/1)');
  close($fh);
}

is( sha1_file('t/data/text-CR.file'), pack("H*","db44309786197ba6364b9c7559b6b9d4fea497f7"), 'sha1 (raw/file/2)');
is( sha1_file_hex('t/data/text-CR.file'), "db44309786197ba6364b9c7559b6b9d4fea497f7", 'sha1 (hex/file/2)');
is( sha1_file_base64('t/data/text-CR.file'), "20Qwl4YZe6Y2S5x1Wba51P6kl/c=", 'sha1 (base64/file/2)');
is( digest_file('SHA1', 't/data/text-CR.file'), pack("H*","db44309786197ba6364b9c7559b6b9d4fea497f7"), 'sha1 (digest_file_raw/file/2)');
is( digest_file_hex('SHA1', 't/data/text-CR.file'), "db44309786197ba6364b9c7559b6b9d4fea497f7", 'sha1 (digest_file_hex/file/2)');
is( digest_file_base64('SHA1', 't/data/text-CR.file'), "20Qwl4YZe6Y2S5x1Wba51P6kl/c=", 'sha1 (digest_file_base64/file/2)');
is( Crypt::Digest::SHA1->new->addfile('t/data/text-CR.file')->hexdigest, "db44309786197ba6364b9c7559b6b9d4fea497f7", 'sha1 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA1->new->addfile($fh)->hexdigest, "db44309786197ba6364b9c7559b6b9d4fea497f7", 'sha1 (OO/filehandle/2)');
  close($fh);
}

is( sha1_file('t/data/text-CRLF.file'), pack("H*","ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb"), 'sha1 (raw/file/3)');
is( sha1_file_hex('t/data/text-CRLF.file'), "ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb", 'sha1 (hex/file/3)');
is( sha1_file_base64('t/data/text-CRLF.file'), "7Ut/4G1uqBKpmPL6D0DhDFOhfrs=", 'sha1 (base64/file/3)');
is( digest_file('SHA1', 't/data/text-CRLF.file'), pack("H*","ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb"), 'sha1 (digest_file_raw/file/3)');
is( digest_file_hex('SHA1', 't/data/text-CRLF.file'), "ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb", 'sha1 (digest_file_hex/file/3)');
is( digest_file_base64('SHA1', 't/data/text-CRLF.file'), "7Ut/4G1uqBKpmPL6D0DhDFOhfrs=", 'sha1 (digest_file_base64/file/3)');
is( Crypt::Digest::SHA1->new->addfile('t/data/text-CRLF.file')->hexdigest, "ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb", 'sha1 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA1->new->addfile($fh)->hexdigest, "ed4b7fe06d6ea812a998f2fa0f40e10c53a17ebb", 'sha1 (OO/filehandle/3)');
  close($fh);
}

is( sha1_file('t/data/text-LF.file'), pack("H*","c12fb4decacf4617b6e9447770d6ef56c507d4ce"), 'sha1 (raw/file/4)');
is( sha1_file_hex('t/data/text-LF.file'), "c12fb4decacf4617b6e9447770d6ef56c507d4ce", 'sha1 (hex/file/4)');
is( sha1_file_base64('t/data/text-LF.file'), "wS+03srPRhe26UR3cNbvVsUH1M4=", 'sha1 (base64/file/4)');
is( digest_file('SHA1', 't/data/text-LF.file'), pack("H*","c12fb4decacf4617b6e9447770d6ef56c507d4ce"), 'sha1 (digest_file_raw/file/4)');
is( digest_file_hex('SHA1', 't/data/text-LF.file'), "c12fb4decacf4617b6e9447770d6ef56c507d4ce", 'sha1 (digest_file_hex/file/4)');
is( digest_file_base64('SHA1', 't/data/text-LF.file'), "wS+03srPRhe26UR3cNbvVsUH1M4=", 'sha1 (digest_file_base64/file/4)');
is( Crypt::Digest::SHA1->new->addfile('t/data/text-LF.file')->hexdigest, "c12fb4decacf4617b6e9447770d6ef56c507d4ce", 'sha1 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA1->new->addfile($fh)->hexdigest, "c12fb4decacf4617b6e9447770d6ef56c507d4ce", 'sha1 (OO/filehandle/4)');
  close($fh);
}
