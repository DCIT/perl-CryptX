### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2s_160 qw( blake2s_160 blake2s_160_hex blake2s_160_b64 blake2s_160_b64u blake2s_160_file blake2s_160_file_hex blake2s_160_file_b64 blake2s_160_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2s_160'), 20, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2s_160'), 20, 'hashsize/2');
is( Crypt::Digest::BLAKE2s_160::hashsize, 20, 'hashsize/3');
is( Crypt::Digest::BLAKE2s_160->hashsize, 20, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2s_160')->hashsize, 20, 'hashsize/5');
is( Crypt::Digest::BLAKE2s_160->new->hashsize, 20, 'hashsize/6');

is( blake2s_160("A","A","A"), pack("H*","f44c709aebd62a7a13bd6ee5979981970a60e117"), 'blake2s_160 (raw/tripple_A)');
is( blake2s_160_hex("A","A","A"), "f44c709aebd62a7a13bd6ee5979981970a60e117", 'blake2s_160 (hex/tripple_A)');
is( blake2s_160_b64("A","A","A"), "9ExwmuvWKnoTvW7ll5mBlwpg4Rc=", 'blake2s_160 (base64/tripple_A)');
is( blake2s_160_b64u("A","A","A"), "9ExwmuvWKnoTvW7ll5mBlwpg4Rc", 'blake2s_160 (base64url/tripple_A)');
is( digest_data('BLAKE2s_160', "A","A","A"), pack("H*","f44c709aebd62a7a13bd6ee5979981970a60e117"), 'blake2s_160 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2s_160', "A","A","A"), "f44c709aebd62a7a13bd6ee5979981970a60e117", 'blake2s_160 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2s_160', "A","A","A"), "9ExwmuvWKnoTvW7ll5mBlwpg4Rc=", 'blake2s_160 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2s_160', "A","A","A"), "9ExwmuvWKnoTvW7ll5mBlwpg4Rc", 'blake2s_160 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2s_160->new->add("A","A","A")->hexdigest, "f44c709aebd62a7a13bd6ee5979981970a60e117", 'blake2s_160 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2s_160->new->add("A")->add("A")->add("A")->hexdigest, "f44c709aebd62a7a13bd6ee5979981970a60e117", 'blake2s_160 (OO3/tripple_A)');


is( blake2s_160(""), pack("H*","354c9c33f735962418bdacb9479873429c34916f"), 'blake2s_160 (raw/1)');
is( blake2s_160_hex(""), "354c9c33f735962418bdacb9479873429c34916f", 'blake2s_160 (hex/1)');
is( blake2s_160_b64(""), "NUycM/c1liQYvay5R5hzQpw0kW8=", 'blake2s_160 (base64/1)');
is( digest_data('BLAKE2s_160', ""), pack("H*","354c9c33f735962418bdacb9479873429c34916f"), 'blake2s_160 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2s_160', ""), "354c9c33f735962418bdacb9479873429c34916f", 'blake2s_160 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2s_160', ""), "NUycM/c1liQYvay5R5hzQpw0kW8=", 'blake2s_160 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2s_160', ""), "NUycM_c1liQYvay5R5hzQpw0kW8", 'blake2s_160 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2s_160->new->add("")->hexdigest, "354c9c33f735962418bdacb9479873429c34916f", 'blake2s_160 (OO/1)');

is( blake2s_160("123"), pack("H*","0acf4489ee7548f29fc6f6d58605f8399b69d664"), 'blake2s_160 (raw/2)');
is( blake2s_160_hex("123"), "0acf4489ee7548f29fc6f6d58605f8399b69d664", 'blake2s_160 (hex/2)');
is( blake2s_160_b64("123"), "Cs9Eie51SPKfxvbVhgX4OZtp1mQ=", 'blake2s_160 (base64/2)');
is( digest_data('BLAKE2s_160', "123"), pack("H*","0acf4489ee7548f29fc6f6d58605f8399b69d664"), 'blake2s_160 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2s_160', "123"), "0acf4489ee7548f29fc6f6d58605f8399b69d664", 'blake2s_160 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2s_160', "123"), "Cs9Eie51SPKfxvbVhgX4OZtp1mQ=", 'blake2s_160 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2s_160', "123"), "Cs9Eie51SPKfxvbVhgX4OZtp1mQ", 'blake2s_160 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2s_160->new->add("123")->hexdigest, "0acf4489ee7548f29fc6f6d58605f8399b69d664", 'blake2s_160 (OO/2)');

is( blake2s_160("test\0test\0test\n"), pack("H*","7e496917ea2fdbb95254bfc7e161144b6a106823"), 'blake2s_160 (raw/3)');
is( blake2s_160_hex("test\0test\0test\n"), "7e496917ea2fdbb95254bfc7e161144b6a106823", 'blake2s_160 (hex/3)');
is( blake2s_160_b64("test\0test\0test\n"), "fklpF+ov27lSVL/H4WEUS2oQaCM=", 'blake2s_160 (base64/3)');
is( digest_data('BLAKE2s_160', "test\0test\0test\n"), pack("H*","7e496917ea2fdbb95254bfc7e161144b6a106823"), 'blake2s_160 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2s_160', "test\0test\0test\n"), "7e496917ea2fdbb95254bfc7e161144b6a106823", 'blake2s_160 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2s_160', "test\0test\0test\n"), "fklpF+ov27lSVL/H4WEUS2oQaCM=", 'blake2s_160 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2s_160', "test\0test\0test\n"), "fklpF-ov27lSVL_H4WEUS2oQaCM", 'blake2s_160 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2s_160->new->add("test\0test\0test\n")->hexdigest, "7e496917ea2fdbb95254bfc7e161144b6a106823", 'blake2s_160 (OO/3)');


is( blake2s_160_file('t/data/binary-test.file'), pack("H*","079c2122db24abfcbb343a2fc4c579c64fb9e534"), 'blake2s_160 (raw/file/1)');
is( blake2s_160_file_hex('t/data/binary-test.file'), "079c2122db24abfcbb343a2fc4c579c64fb9e534", 'blake2s_160 (hex/file/1)');
is( blake2s_160_file_b64('t/data/binary-test.file'), "B5whItskq/y7NDovxMV5xk+55TQ=", 'blake2s_160 (base64/file/1)');
is( digest_file('BLAKE2s_160', 't/data/binary-test.file'), pack("H*","079c2122db24abfcbb343a2fc4c579c64fb9e534"), 'blake2s_160 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2s_160', 't/data/binary-test.file'), "079c2122db24abfcbb343a2fc4c579c64fb9e534", 'blake2s_160 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2s_160', 't/data/binary-test.file'), "B5whItskq/y7NDovxMV5xk+55TQ=", 'blake2s_160 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2s_160', 't/data/binary-test.file'), "B5whItskq_y7NDovxMV5xk-55TQ", 'blake2s_160 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2s_160->new->addfile('t/data/binary-test.file')->hexdigest, "079c2122db24abfcbb343a2fc4c579c64fb9e534", 'blake2s_160 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_160->new->addfile($fh)->hexdigest, "079c2122db24abfcbb343a2fc4c579c64fb9e534", 'blake2s_160 (OO/filehandle/1)');
  close($fh);
}

is( blake2s_160_file('t/data/text-CR.file'), pack("H*","99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de"), 'blake2s_160 (raw/file/2)');
is( blake2s_160_file_hex('t/data/text-CR.file'), "99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de", 'blake2s_160 (hex/file/2)');
is( blake2s_160_file_b64('t/data/text-CR.file'), "mey+MO1Gh+1tjIrL/GIFpKPOod4=", 'blake2s_160 (base64/file/2)');
is( digest_file('BLAKE2s_160', 't/data/text-CR.file'), pack("H*","99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de"), 'blake2s_160 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2s_160', 't/data/text-CR.file'), "99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de", 'blake2s_160 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2s_160', 't/data/text-CR.file'), "mey+MO1Gh+1tjIrL/GIFpKPOod4=", 'blake2s_160 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2s_160', 't/data/text-CR.file'), "mey-MO1Gh-1tjIrL_GIFpKPOod4", 'blake2s_160 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2s_160->new->addfile('t/data/text-CR.file')->hexdigest, "99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de", 'blake2s_160 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_160->new->addfile($fh)->hexdigest, "99ecbe30ed4687ed6d8c8acbfc6205a4a3cea1de", 'blake2s_160 (OO/filehandle/2)');
  close($fh);
}

is( blake2s_160_file('t/data/text-CRLF.file'), pack("H*","12fb04520b12fda25ac2845d5a7c8fb962811b0b"), 'blake2s_160 (raw/file/3)');
is( blake2s_160_file_hex('t/data/text-CRLF.file'), "12fb04520b12fda25ac2845d5a7c8fb962811b0b", 'blake2s_160 (hex/file/3)');
is( blake2s_160_file_b64('t/data/text-CRLF.file'), "EvsEUgsS/aJawoRdWnyPuWKBGws=", 'blake2s_160 (base64/file/3)');
is( digest_file('BLAKE2s_160', 't/data/text-CRLF.file'), pack("H*","12fb04520b12fda25ac2845d5a7c8fb962811b0b"), 'blake2s_160 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2s_160', 't/data/text-CRLF.file'), "12fb04520b12fda25ac2845d5a7c8fb962811b0b", 'blake2s_160 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2s_160', 't/data/text-CRLF.file'), "EvsEUgsS/aJawoRdWnyPuWKBGws=", 'blake2s_160 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2s_160', 't/data/text-CRLF.file'), "EvsEUgsS_aJawoRdWnyPuWKBGws", 'blake2s_160 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2s_160->new->addfile('t/data/text-CRLF.file')->hexdigest, "12fb04520b12fda25ac2845d5a7c8fb962811b0b", 'blake2s_160 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_160->new->addfile($fh)->hexdigest, "12fb04520b12fda25ac2845d5a7c8fb962811b0b", 'blake2s_160 (OO/filehandle/3)');
  close($fh);
}

is( blake2s_160_file('t/data/text-LF.file'), pack("H*","72f0b448af483431f552dcd4ba426209f2d0f4dc"), 'blake2s_160 (raw/file/4)');
is( blake2s_160_file_hex('t/data/text-LF.file'), "72f0b448af483431f552dcd4ba426209f2d0f4dc", 'blake2s_160 (hex/file/4)');
is( blake2s_160_file_b64('t/data/text-LF.file'), "cvC0SK9INDH1UtzUukJiCfLQ9Nw=", 'blake2s_160 (base64/file/4)');
is( digest_file('BLAKE2s_160', 't/data/text-LF.file'), pack("H*","72f0b448af483431f552dcd4ba426209f2d0f4dc"), 'blake2s_160 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2s_160', 't/data/text-LF.file'), "72f0b448af483431f552dcd4ba426209f2d0f4dc", 'blake2s_160 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2s_160', 't/data/text-LF.file'), "cvC0SK9INDH1UtzUukJiCfLQ9Nw=", 'blake2s_160 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2s_160', 't/data/text-LF.file'), "cvC0SK9INDH1UtzUukJiCfLQ9Nw", 'blake2s_160 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2s_160->new->addfile('t/data/text-LF.file')->hexdigest, "72f0b448af483431f552dcd4ba426209f2d0f4dc", 'blake2s_160 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_160->new->addfile($fh)->hexdigest, "72f0b448af483431f552dcd4ba426209f2d0f4dc", 'blake2s_160 (OO/filehandle/4)');
  close($fh);
}
