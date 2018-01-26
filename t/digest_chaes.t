### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::CHAES qw( chaes chaes_hex chaes_b64 chaes_b64u chaes_file chaes_file_hex chaes_file_b64 chaes_file_b64u );

is( Crypt::Digest::hashsize('CHAES'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('CHAES'), 16, 'hashsize/2');
is( Crypt::Digest::CHAES::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::CHAES->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('CHAES')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::CHAES->new->hashsize, 16, 'hashsize/6');

is( chaes("A","A","A"), pack("H*","f01416b4c3f6389816b2fcd0b4cf9e41"), 'chaes (raw/tripple_A)');
is( chaes_hex("A","A","A"), "f01416b4c3f6389816b2fcd0b4cf9e41", 'chaes (hex/tripple_A)');
is( chaes_b64("A","A","A"), "8BQWtMP2OJgWsvzQtM+eQQ==", 'chaes (base64/tripple_A)');
is( chaes_b64u("A","A","A"), "8BQWtMP2OJgWsvzQtM-eQQ", 'chaes (base64url/tripple_A)');
is( digest_data('CHAES', "A","A","A"), pack("H*","f01416b4c3f6389816b2fcd0b4cf9e41"), 'chaes (digest_data_raw/tripple_A)');
is( digest_data_hex('CHAES', "A","A","A"), "f01416b4c3f6389816b2fcd0b4cf9e41", 'chaes (digest_data_hex/tripple_A)');
is( digest_data_b64('CHAES', "A","A","A"), "8BQWtMP2OJgWsvzQtM+eQQ==", 'chaes (digest_data_b64/tripple_A)');
is( digest_data_b64u('CHAES', "A","A","A"), "8BQWtMP2OJgWsvzQtM-eQQ", 'chaes (digest_data_b64u/tripple_A)');
is( Crypt::Digest::CHAES->new->add("A","A","A")->hexdigest, "f01416b4c3f6389816b2fcd0b4cf9e41", 'chaes (OO/tripple_A)');
is( Crypt::Digest::CHAES->new->add("A")->add("A")->add("A")->hexdigest, "f01416b4c3f6389816b2fcd0b4cf9e41", 'chaes (OO3/tripple_A)');


is( chaes(""), pack("H*","4047929f1f572643b55f829eb3291d11"), 'chaes (raw/1)');
is( chaes_hex(""), "4047929f1f572643b55f829eb3291d11", 'chaes (hex/1)');
is( chaes_b64(""), "QEeSnx9XJkO1X4KesykdEQ==", 'chaes (base64/1)');
is( digest_data('CHAES', ""), pack("H*","4047929f1f572643b55f829eb3291d11"), 'chaes (digest_data_raw/1)');
is( digest_data_hex('CHAES', ""), "4047929f1f572643b55f829eb3291d11", 'chaes (digest_data_hex/1)');
is( digest_data_b64('CHAES', ""), "QEeSnx9XJkO1X4KesykdEQ==", 'chaes (digest_data_b64/1)');
is( digest_data_b64u('CHAES', ""), "QEeSnx9XJkO1X4KesykdEQ", 'chaes (digest_data_b64u/1)');
is( Crypt::Digest::CHAES->new->add("")->hexdigest, "4047929f1f572643b55f829eb3291d11", 'chaes (OO/1)');

is( chaes("123"), pack("H*","fc04dbd92bbb0311c6cfc6cb75d64a7c"), 'chaes (raw/2)');
is( chaes_hex("123"), "fc04dbd92bbb0311c6cfc6cb75d64a7c", 'chaes (hex/2)');
is( chaes_b64("123"), "/ATb2Su7AxHGz8bLddZKfA==", 'chaes (base64/2)');
is( digest_data('CHAES', "123"), pack("H*","fc04dbd92bbb0311c6cfc6cb75d64a7c"), 'chaes (digest_data_raw/2)');
is( digest_data_hex('CHAES', "123"), "fc04dbd92bbb0311c6cfc6cb75d64a7c", 'chaes (digest_data_hex/2)');
is( digest_data_b64('CHAES', "123"), "/ATb2Su7AxHGz8bLddZKfA==", 'chaes (digest_data_b64/2)');
is( digest_data_b64u('CHAES', "123"), "_ATb2Su7AxHGz8bLddZKfA", 'chaes (digest_data_b64u/2)');
is( Crypt::Digest::CHAES->new->add("123")->hexdigest, "fc04dbd92bbb0311c6cfc6cb75d64a7c", 'chaes (OO/2)');

is( chaes("test\0test\0test\n"), pack("H*","b01f0f1c3dbfb727f8e8a1775fcd9dbc"), 'chaes (raw/3)');
is( chaes_hex("test\0test\0test\n"), "b01f0f1c3dbfb727f8e8a1775fcd9dbc", 'chaes (hex/3)');
is( chaes_b64("test\0test\0test\n"), "sB8PHD2/tyf46KF3X82dvA==", 'chaes (base64/3)');
is( digest_data('CHAES', "test\0test\0test\n"), pack("H*","b01f0f1c3dbfb727f8e8a1775fcd9dbc"), 'chaes (digest_data_raw/3)');
is( digest_data_hex('CHAES', "test\0test\0test\n"), "b01f0f1c3dbfb727f8e8a1775fcd9dbc", 'chaes (digest_data_hex/3)');
is( digest_data_b64('CHAES', "test\0test\0test\n"), "sB8PHD2/tyf46KF3X82dvA==", 'chaes (digest_data_b64/3)');
is( digest_data_b64u('CHAES', "test\0test\0test\n"), "sB8PHD2_tyf46KF3X82dvA", 'chaes (digest_data_b64u/3)');
is( Crypt::Digest::CHAES->new->add("test\0test\0test\n")->hexdigest, "b01f0f1c3dbfb727f8e8a1775fcd9dbc", 'chaes (OO/3)');


is( chaes_file('t/data/binary-test.file'), pack("H*","50390a2472d0dffe0323360b28cf8060"), 'chaes (raw/file/1)');
is( chaes_file_hex('t/data/binary-test.file'), "50390a2472d0dffe0323360b28cf8060", 'chaes (hex/file/1)');
is( chaes_file_b64('t/data/binary-test.file'), "UDkKJHLQ3/4DIzYLKM+AYA==", 'chaes (base64/file/1)');
is( digest_file('CHAES', 't/data/binary-test.file'), pack("H*","50390a2472d0dffe0323360b28cf8060"), 'chaes (digest_file_raw/file/1)');
is( digest_file_hex('CHAES', 't/data/binary-test.file'), "50390a2472d0dffe0323360b28cf8060", 'chaes (digest_file_hex/file/1)');
is( digest_file_b64('CHAES', 't/data/binary-test.file'), "UDkKJHLQ3/4DIzYLKM+AYA==", 'chaes (digest_file_b64/file/1)');
is( digest_file_b64u('CHAES', 't/data/binary-test.file'), "UDkKJHLQ3_4DIzYLKM-AYA", 'chaes (digest_file_b64u/file/1)');
is( Crypt::Digest::CHAES->new->addfile('t/data/binary-test.file')->hexdigest, "50390a2472d0dffe0323360b28cf8060", 'chaes (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::CHAES->new->addfile($fh)->hexdigest, "50390a2472d0dffe0323360b28cf8060", 'chaes (OO/filehandle/1)');
  close($fh);
}

is( chaes_file('t/data/text-CR.file'), pack("H*","f08c7838baa3dbdc02b6ac290db47609"), 'chaes (raw/file/2)');
is( chaes_file_hex('t/data/text-CR.file'), "f08c7838baa3dbdc02b6ac290db47609", 'chaes (hex/file/2)');
is( chaes_file_b64('t/data/text-CR.file'), "8Ix4OLqj29wCtqwpDbR2CQ==", 'chaes (base64/file/2)');
is( digest_file('CHAES', 't/data/text-CR.file'), pack("H*","f08c7838baa3dbdc02b6ac290db47609"), 'chaes (digest_file_raw/file/2)');
is( digest_file_hex('CHAES', 't/data/text-CR.file'), "f08c7838baa3dbdc02b6ac290db47609", 'chaes (digest_file_hex/file/2)');
is( digest_file_b64('CHAES', 't/data/text-CR.file'), "8Ix4OLqj29wCtqwpDbR2CQ==", 'chaes (digest_file_b64/file/2)');
is( digest_file_b64u('CHAES', 't/data/text-CR.file'), "8Ix4OLqj29wCtqwpDbR2CQ", 'chaes (digest_file_b64u/file/2)');
is( Crypt::Digest::CHAES->new->addfile('t/data/text-CR.file')->hexdigest, "f08c7838baa3dbdc02b6ac290db47609", 'chaes (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::CHAES->new->addfile($fh)->hexdigest, "f08c7838baa3dbdc02b6ac290db47609", 'chaes (OO/filehandle/2)');
  close($fh);
}

is( chaes_file('t/data/text-CRLF.file'), pack("H*","b7874022b1a2558a2ffa384ca83bdd3f"), 'chaes (raw/file/3)');
is( chaes_file_hex('t/data/text-CRLF.file'), "b7874022b1a2558a2ffa384ca83bdd3f", 'chaes (hex/file/3)');
is( chaes_file_b64('t/data/text-CRLF.file'), "t4dAIrGiVYov+jhMqDvdPw==", 'chaes (base64/file/3)');
is( digest_file('CHAES', 't/data/text-CRLF.file'), pack("H*","b7874022b1a2558a2ffa384ca83bdd3f"), 'chaes (digest_file_raw/file/3)');
is( digest_file_hex('CHAES', 't/data/text-CRLF.file'), "b7874022b1a2558a2ffa384ca83bdd3f", 'chaes (digest_file_hex/file/3)');
is( digest_file_b64('CHAES', 't/data/text-CRLF.file'), "t4dAIrGiVYov+jhMqDvdPw==", 'chaes (digest_file_b64/file/3)');
is( digest_file_b64u('CHAES', 't/data/text-CRLF.file'), "t4dAIrGiVYov-jhMqDvdPw", 'chaes (digest_file_b64u/file/3)');
is( Crypt::Digest::CHAES->new->addfile('t/data/text-CRLF.file')->hexdigest, "b7874022b1a2558a2ffa384ca83bdd3f", 'chaes (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::CHAES->new->addfile($fh)->hexdigest, "b7874022b1a2558a2ffa384ca83bdd3f", 'chaes (OO/filehandle/3)');
  close($fh);
}

is( chaes_file('t/data/text-LF.file'), pack("H*","e4a2674dc4123b3fa38dc01414ba58aa"), 'chaes (raw/file/4)');
is( chaes_file_hex('t/data/text-LF.file'), "e4a2674dc4123b3fa38dc01414ba58aa", 'chaes (hex/file/4)');
is( chaes_file_b64('t/data/text-LF.file'), "5KJnTcQSOz+jjcAUFLpYqg==", 'chaes (base64/file/4)');
is( digest_file('CHAES', 't/data/text-LF.file'), pack("H*","e4a2674dc4123b3fa38dc01414ba58aa"), 'chaes (digest_file_raw/file/4)');
is( digest_file_hex('CHAES', 't/data/text-LF.file'), "e4a2674dc4123b3fa38dc01414ba58aa", 'chaes (digest_file_hex/file/4)');
is( digest_file_b64('CHAES', 't/data/text-LF.file'), "5KJnTcQSOz+jjcAUFLpYqg==", 'chaes (digest_file_b64/file/4)');
is( digest_file_b64u('CHAES', 't/data/text-LF.file'), "5KJnTcQSOz-jjcAUFLpYqg", 'chaes (digest_file_b64u/file/4)');
is( Crypt::Digest::CHAES->new->addfile('t/data/text-LF.file')->hexdigest, "e4a2674dc4123b3fa38dc01414ba58aa", 'chaes (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::CHAES->new->addfile($fh)->hexdigest, "e4a2674dc4123b3fa38dc01414ba58aa", 'chaes (OO/filehandle/4)');
  close($fh);
}
