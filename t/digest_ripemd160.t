### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::RIPEMD160 qw( ripemd160 ripemd160_hex ripemd160_b64 ripemd160_b64u ripemd160_file ripemd160_file_hex ripemd160_file_b64 ripemd160_file_b64u );

is( Crypt::Digest::hashsize('RIPEMD160'), 20, 'hashsize/1');
is( Crypt::Digest->hashsize('RIPEMD160'), 20, 'hashsize/2');
is( Crypt::Digest::RIPEMD160::hashsize, 20, 'hashsize/3');
is( Crypt::Digest::RIPEMD160->hashsize, 20, 'hashsize/4');
is( Crypt::Digest->new('RIPEMD160')->hashsize, 20, 'hashsize/5');
is( Crypt::Digest::RIPEMD160->new->hashsize, 20, 'hashsize/6');

is( ripemd160("A","A","A"), pack("H*","e4e130acc1d2a5a63c17efb1eedbd02be28443d1"), 'ripemd160 (raw/tripple_A)');
is( ripemd160_hex("A","A","A"), "e4e130acc1d2a5a63c17efb1eedbd02be28443d1", 'ripemd160 (hex/tripple_A)');
is( ripemd160_b64("A","A","A"), "5OEwrMHSpaY8F++x7tvQK+KEQ9E=", 'ripemd160 (base64/tripple_A)');
is( ripemd160_b64u("A","A","A"), "5OEwrMHSpaY8F--x7tvQK-KEQ9E", 'ripemd160 (base64url/tripple_A)');
is( digest_data('RIPEMD160', "A","A","A"), pack("H*","e4e130acc1d2a5a63c17efb1eedbd02be28443d1"), 'ripemd160 (digest_data_raw/tripple_A)');
is( digest_data_hex('RIPEMD160', "A","A","A"), "e4e130acc1d2a5a63c17efb1eedbd02be28443d1", 'ripemd160 (digest_data_hex/tripple_A)');
is( digest_data_b64('RIPEMD160', "A","A","A"), "5OEwrMHSpaY8F++x7tvQK+KEQ9E=", 'ripemd160 (digest_data_b64/tripple_A)');
is( digest_data_b64u('RIPEMD160', "A","A","A"), "5OEwrMHSpaY8F--x7tvQK-KEQ9E", 'ripemd160 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::RIPEMD160->new->add("A","A","A")->hexdigest, "e4e130acc1d2a5a63c17efb1eedbd02be28443d1", 'ripemd160 (OO/tripple_A)');
is( Crypt::Digest::RIPEMD160->new->add("A")->add("A")->add("A")->hexdigest, "e4e130acc1d2a5a63c17efb1eedbd02be28443d1", 'ripemd160 (OO3/tripple_A)');


is( ripemd160(""), pack("H*","9c1185a5c5e9fc54612808977ee8f548b2258d31"), 'ripemd160 (raw/1)');
is( ripemd160_hex(""), "9c1185a5c5e9fc54612808977ee8f548b2258d31", 'ripemd160 (hex/1)');
is( ripemd160_b64(""), "nBGFpcXp/FRhKAiXfuj1SLIljTE=", 'ripemd160 (base64/1)');
is( digest_data('RIPEMD160', ""), pack("H*","9c1185a5c5e9fc54612808977ee8f548b2258d31"), 'ripemd160 (digest_data_raw/1)');
is( digest_data_hex('RIPEMD160', ""), "9c1185a5c5e9fc54612808977ee8f548b2258d31", 'ripemd160 (digest_data_hex/1)');
is( digest_data_b64('RIPEMD160', ""), "nBGFpcXp/FRhKAiXfuj1SLIljTE=", 'ripemd160 (digest_data_b64/1)');
is( digest_data_b64u('RIPEMD160', ""), "nBGFpcXp_FRhKAiXfuj1SLIljTE", 'ripemd160 (digest_data_b64u/1)');
is( Crypt::Digest::RIPEMD160->new->add("")->hexdigest, "9c1185a5c5e9fc54612808977ee8f548b2258d31", 'ripemd160 (OO/1)');

is( ripemd160("123"), pack("H*","e3431a8e0adbf96fd140103dc6f63a3f8fa343ab"), 'ripemd160 (raw/2)');
is( ripemd160_hex("123"), "e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", 'ripemd160 (hex/2)');
is( ripemd160_b64("123"), "40Majgrb+W/RQBA9xvY6P4+jQ6s=", 'ripemd160 (base64/2)');
is( digest_data('RIPEMD160', "123"), pack("H*","e3431a8e0adbf96fd140103dc6f63a3f8fa343ab"), 'ripemd160 (digest_data_raw/2)');
is( digest_data_hex('RIPEMD160', "123"), "e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", 'ripemd160 (digest_data_hex/2)');
is( digest_data_b64('RIPEMD160', "123"), "40Majgrb+W/RQBA9xvY6P4+jQ6s=", 'ripemd160 (digest_data_b64/2)');
is( digest_data_b64u('RIPEMD160', "123"), "40Majgrb-W_RQBA9xvY6P4-jQ6s", 'ripemd160 (digest_data_b64u/2)');
is( Crypt::Digest::RIPEMD160->new->add("123")->hexdigest, "e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", 'ripemd160 (OO/2)');

is( ripemd160("test\0test\0test\n"), pack("H*","1d3537be9984c77527d16313decc87e376411c8c"), 'ripemd160 (raw/3)');
is( ripemd160_hex("test\0test\0test\n"), "1d3537be9984c77527d16313decc87e376411c8c", 'ripemd160 (hex/3)');
is( ripemd160_b64("test\0test\0test\n"), "HTU3vpmEx3Un0WMT3syH43ZBHIw=", 'ripemd160 (base64/3)');
is( digest_data('RIPEMD160', "test\0test\0test\n"), pack("H*","1d3537be9984c77527d16313decc87e376411c8c"), 'ripemd160 (digest_data_raw/3)');
is( digest_data_hex('RIPEMD160', "test\0test\0test\n"), "1d3537be9984c77527d16313decc87e376411c8c", 'ripemd160 (digest_data_hex/3)');
is( digest_data_b64('RIPEMD160', "test\0test\0test\n"), "HTU3vpmEx3Un0WMT3syH43ZBHIw=", 'ripemd160 (digest_data_b64/3)');
is( digest_data_b64u('RIPEMD160', "test\0test\0test\n"), "HTU3vpmEx3Un0WMT3syH43ZBHIw", 'ripemd160 (digest_data_b64u/3)');
is( Crypt::Digest::RIPEMD160->new->add("test\0test\0test\n")->hexdigest, "1d3537be9984c77527d16313decc87e376411c8c", 'ripemd160 (OO/3)');


is( ripemd160_file('t/data/binary-test.file'), pack("H*","0bf6636068ef6d6a2af93d8ce220e8324ecdac2f"), 'ripemd160 (raw/file/1)');
is( ripemd160_file_hex('t/data/binary-test.file'), "0bf6636068ef6d6a2af93d8ce220e8324ecdac2f", 'ripemd160 (hex/file/1)');
is( ripemd160_file_b64('t/data/binary-test.file'), "C/ZjYGjvbWoq+T2M4iDoMk7NrC8=", 'ripemd160 (base64/file/1)');
is( digest_file('RIPEMD160', 't/data/binary-test.file'), pack("H*","0bf6636068ef6d6a2af93d8ce220e8324ecdac2f"), 'ripemd160 (digest_file_raw/file/1)');
is( digest_file_hex('RIPEMD160', 't/data/binary-test.file'), "0bf6636068ef6d6a2af93d8ce220e8324ecdac2f", 'ripemd160 (digest_file_hex/file/1)');
is( digest_file_b64('RIPEMD160', 't/data/binary-test.file'), "C/ZjYGjvbWoq+T2M4iDoMk7NrC8=", 'ripemd160 (digest_file_b64/file/1)');
is( digest_file_b64u('RIPEMD160', 't/data/binary-test.file'), "C_ZjYGjvbWoq-T2M4iDoMk7NrC8", 'ripemd160 (digest_file_b64u/file/1)');
is( Crypt::Digest::RIPEMD160->new->addfile('t/data/binary-test.file')->hexdigest, "0bf6636068ef6d6a2af93d8ce220e8324ecdac2f", 'ripemd160 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD160->new->addfile($fh)->hexdigest, "0bf6636068ef6d6a2af93d8ce220e8324ecdac2f", 'ripemd160 (OO/filehandle/1)');
  close($fh);
}

is( ripemd160_file('t/data/text-CR.file'), pack("H*","156e131e5e5e8216cad97fa880a7a54273179853"), 'ripemd160 (raw/file/2)');
is( ripemd160_file_hex('t/data/text-CR.file'), "156e131e5e5e8216cad97fa880a7a54273179853", 'ripemd160 (hex/file/2)');
is( ripemd160_file_b64('t/data/text-CR.file'), "FW4THl5eghbK2X+ogKelQnMXmFM=", 'ripemd160 (base64/file/2)');
is( digest_file('RIPEMD160', 't/data/text-CR.file'), pack("H*","156e131e5e5e8216cad97fa880a7a54273179853"), 'ripemd160 (digest_file_raw/file/2)');
is( digest_file_hex('RIPEMD160', 't/data/text-CR.file'), "156e131e5e5e8216cad97fa880a7a54273179853", 'ripemd160 (digest_file_hex/file/2)');
is( digest_file_b64('RIPEMD160', 't/data/text-CR.file'), "FW4THl5eghbK2X+ogKelQnMXmFM=", 'ripemd160 (digest_file_b64/file/2)');
is( digest_file_b64u('RIPEMD160', 't/data/text-CR.file'), "FW4THl5eghbK2X-ogKelQnMXmFM", 'ripemd160 (digest_file_b64u/file/2)');
is( Crypt::Digest::RIPEMD160->new->addfile('t/data/text-CR.file')->hexdigest, "156e131e5e5e8216cad97fa880a7a54273179853", 'ripemd160 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD160->new->addfile($fh)->hexdigest, "156e131e5e5e8216cad97fa880a7a54273179853", 'ripemd160 (OO/filehandle/2)');
  close($fh);
}

is( ripemd160_file('t/data/text-CRLF.file'), pack("H*","cb374a83416fe4fc3ae04945b3a796f3b54c3b63"), 'ripemd160 (raw/file/3)');
is( ripemd160_file_hex('t/data/text-CRLF.file'), "cb374a83416fe4fc3ae04945b3a796f3b54c3b63", 'ripemd160 (hex/file/3)');
is( ripemd160_file_b64('t/data/text-CRLF.file'), "yzdKg0Fv5Pw64ElFs6eW87VMO2M=", 'ripemd160 (base64/file/3)');
is( digest_file('RIPEMD160', 't/data/text-CRLF.file'), pack("H*","cb374a83416fe4fc3ae04945b3a796f3b54c3b63"), 'ripemd160 (digest_file_raw/file/3)');
is( digest_file_hex('RIPEMD160', 't/data/text-CRLF.file'), "cb374a83416fe4fc3ae04945b3a796f3b54c3b63", 'ripemd160 (digest_file_hex/file/3)');
is( digest_file_b64('RIPEMD160', 't/data/text-CRLF.file'), "yzdKg0Fv5Pw64ElFs6eW87VMO2M=", 'ripemd160 (digest_file_b64/file/3)');
is( digest_file_b64u('RIPEMD160', 't/data/text-CRLF.file'), "yzdKg0Fv5Pw64ElFs6eW87VMO2M", 'ripemd160 (digest_file_b64u/file/3)');
is( Crypt::Digest::RIPEMD160->new->addfile('t/data/text-CRLF.file')->hexdigest, "cb374a83416fe4fc3ae04945b3a796f3b54c3b63", 'ripemd160 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD160->new->addfile($fh)->hexdigest, "cb374a83416fe4fc3ae04945b3a796f3b54c3b63", 'ripemd160 (OO/filehandle/3)');
  close($fh);
}

is( ripemd160_file('t/data/text-LF.file'), pack("H*","34913b1862982366520f5e29d8a0a2d6e3d9a812"), 'ripemd160 (raw/file/4)');
is( ripemd160_file_hex('t/data/text-LF.file'), "34913b1862982366520f5e29d8a0a2d6e3d9a812", 'ripemd160 (hex/file/4)');
is( ripemd160_file_b64('t/data/text-LF.file'), "NJE7GGKYI2ZSD14p2KCi1uPZqBI=", 'ripemd160 (base64/file/4)');
is( digest_file('RIPEMD160', 't/data/text-LF.file'), pack("H*","34913b1862982366520f5e29d8a0a2d6e3d9a812"), 'ripemd160 (digest_file_raw/file/4)');
is( digest_file_hex('RIPEMD160', 't/data/text-LF.file'), "34913b1862982366520f5e29d8a0a2d6e3d9a812", 'ripemd160 (digest_file_hex/file/4)');
is( digest_file_b64('RIPEMD160', 't/data/text-LF.file'), "NJE7GGKYI2ZSD14p2KCi1uPZqBI=", 'ripemd160 (digest_file_b64/file/4)');
is( digest_file_b64u('RIPEMD160', 't/data/text-LF.file'), "NJE7GGKYI2ZSD14p2KCi1uPZqBI", 'ripemd160 (digest_file_b64u/file/4)');
is( Crypt::Digest::RIPEMD160->new->addfile('t/data/text-LF.file')->hexdigest, "34913b1862982366520f5e29d8a0a2d6e3d9a812", 'ripemd160 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD160->new->addfile($fh)->hexdigest, "34913b1862982366520f5e29d8a0a2d6e3d9a812", 'ripemd160 (OO/filehandle/4)');
  close($fh);
}
