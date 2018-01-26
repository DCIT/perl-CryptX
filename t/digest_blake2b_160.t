### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2b_160 qw( blake2b_160 blake2b_160_hex blake2b_160_b64 blake2b_160_b64u blake2b_160_file blake2b_160_file_hex blake2b_160_file_b64 blake2b_160_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2b_160'), 20, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2b_160'), 20, 'hashsize/2');
is( Crypt::Digest::BLAKE2b_160::hashsize, 20, 'hashsize/3');
is( Crypt::Digest::BLAKE2b_160->hashsize, 20, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2b_160')->hashsize, 20, 'hashsize/5');
is( Crypt::Digest::BLAKE2b_160->new->hashsize, 20, 'hashsize/6');

is( blake2b_160("A","A","A"), pack("H*","14517ce78b0c7e5e5b7f096f1f3c046f01c46901"), 'blake2b_160 (raw/tripple_A)');
is( blake2b_160_hex("A","A","A"), "14517ce78b0c7e5e5b7f096f1f3c046f01c46901", 'blake2b_160 (hex/tripple_A)');
is( blake2b_160_b64("A","A","A"), "FFF854sMfl5bfwlvHzwEbwHEaQE=", 'blake2b_160 (base64/tripple_A)');
is( blake2b_160_b64u("A","A","A"), "FFF854sMfl5bfwlvHzwEbwHEaQE", 'blake2b_160 (base64url/tripple_A)');
is( digest_data('BLAKE2b_160', "A","A","A"), pack("H*","14517ce78b0c7e5e5b7f096f1f3c046f01c46901"), 'blake2b_160 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2b_160', "A","A","A"), "14517ce78b0c7e5e5b7f096f1f3c046f01c46901", 'blake2b_160 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2b_160', "A","A","A"), "FFF854sMfl5bfwlvHzwEbwHEaQE=", 'blake2b_160 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2b_160', "A","A","A"), "FFF854sMfl5bfwlvHzwEbwHEaQE", 'blake2b_160 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2b_160->new->add("A","A","A")->hexdigest, "14517ce78b0c7e5e5b7f096f1f3c046f01c46901", 'blake2b_160 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2b_160->new->add("A")->add("A")->add("A")->hexdigest, "14517ce78b0c7e5e5b7f096f1f3c046f01c46901", 'blake2b_160 (OO3/tripple_A)');


is( blake2b_160(""), pack("H*","3345524abf6bbe1809449224b5972c41790b6cf2"), 'blake2b_160 (raw/1)');
is( blake2b_160_hex(""), "3345524abf6bbe1809449224b5972c41790b6cf2", 'blake2b_160 (hex/1)');
is( blake2b_160_b64(""), "M0VSSr9rvhgJRJIktZcsQXkLbPI=", 'blake2b_160 (base64/1)');
is( digest_data('BLAKE2b_160', ""), pack("H*","3345524abf6bbe1809449224b5972c41790b6cf2"), 'blake2b_160 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2b_160', ""), "3345524abf6bbe1809449224b5972c41790b6cf2", 'blake2b_160 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2b_160', ""), "M0VSSr9rvhgJRJIktZcsQXkLbPI=", 'blake2b_160 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2b_160', ""), "M0VSSr9rvhgJRJIktZcsQXkLbPI", 'blake2b_160 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2b_160->new->add("")->hexdigest, "3345524abf6bbe1809449224b5972c41790b6cf2", 'blake2b_160 (OO/1)');

is( blake2b_160("123"), pack("H*","c018e33a9cf2fea6a3bb41c4c079ea4fbc901d28"), 'blake2b_160 (raw/2)');
is( blake2b_160_hex("123"), "c018e33a9cf2fea6a3bb41c4c079ea4fbc901d28", 'blake2b_160 (hex/2)');
is( blake2b_160_b64("123"), "wBjjOpzy/qaju0HEwHnqT7yQHSg=", 'blake2b_160 (base64/2)');
is( digest_data('BLAKE2b_160', "123"), pack("H*","c018e33a9cf2fea6a3bb41c4c079ea4fbc901d28"), 'blake2b_160 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2b_160', "123"), "c018e33a9cf2fea6a3bb41c4c079ea4fbc901d28", 'blake2b_160 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2b_160', "123"), "wBjjOpzy/qaju0HEwHnqT7yQHSg=", 'blake2b_160 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2b_160', "123"), "wBjjOpzy_qaju0HEwHnqT7yQHSg", 'blake2b_160 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2b_160->new->add("123")->hexdigest, "c018e33a9cf2fea6a3bb41c4c079ea4fbc901d28", 'blake2b_160 (OO/2)');

is( blake2b_160("test\0test\0test\n"), pack("H*","1ccf96de0b2b8d65c6b5be215afc91c1c0526beb"), 'blake2b_160 (raw/3)');
is( blake2b_160_hex("test\0test\0test\n"), "1ccf96de0b2b8d65c6b5be215afc91c1c0526beb", 'blake2b_160 (hex/3)');
is( blake2b_160_b64("test\0test\0test\n"), "HM+W3gsrjWXGtb4hWvyRwcBSa+s=", 'blake2b_160 (base64/3)');
is( digest_data('BLAKE2b_160', "test\0test\0test\n"), pack("H*","1ccf96de0b2b8d65c6b5be215afc91c1c0526beb"), 'blake2b_160 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2b_160', "test\0test\0test\n"), "1ccf96de0b2b8d65c6b5be215afc91c1c0526beb", 'blake2b_160 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2b_160', "test\0test\0test\n"), "HM+W3gsrjWXGtb4hWvyRwcBSa+s=", 'blake2b_160 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2b_160', "test\0test\0test\n"), "HM-W3gsrjWXGtb4hWvyRwcBSa-s", 'blake2b_160 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2b_160->new->add("test\0test\0test\n")->hexdigest, "1ccf96de0b2b8d65c6b5be215afc91c1c0526beb", 'blake2b_160 (OO/3)');


is( blake2b_160_file('t/data/binary-test.file'), pack("H*","f3ccc92130e0028ebca9a3a50efb2a15578d1b64"), 'blake2b_160 (raw/file/1)');
is( blake2b_160_file_hex('t/data/binary-test.file'), "f3ccc92130e0028ebca9a3a50efb2a15578d1b64", 'blake2b_160 (hex/file/1)');
is( blake2b_160_file_b64('t/data/binary-test.file'), "88zJITDgAo68qaOlDvsqFVeNG2Q=", 'blake2b_160 (base64/file/1)');
is( digest_file('BLAKE2b_160', 't/data/binary-test.file'), pack("H*","f3ccc92130e0028ebca9a3a50efb2a15578d1b64"), 'blake2b_160 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2b_160', 't/data/binary-test.file'), "f3ccc92130e0028ebca9a3a50efb2a15578d1b64", 'blake2b_160 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2b_160', 't/data/binary-test.file'), "88zJITDgAo68qaOlDvsqFVeNG2Q=", 'blake2b_160 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2b_160', 't/data/binary-test.file'), "88zJITDgAo68qaOlDvsqFVeNG2Q", 'blake2b_160 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2b_160->new->addfile('t/data/binary-test.file')->hexdigest, "f3ccc92130e0028ebca9a3a50efb2a15578d1b64", 'blake2b_160 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_160->new->addfile($fh)->hexdigest, "f3ccc92130e0028ebca9a3a50efb2a15578d1b64", 'blake2b_160 (OO/filehandle/1)');
  close($fh);
}

is( blake2b_160_file('t/data/text-CR.file'), pack("H*","206fb81fb94a6738e2829111fbd3deabc34173a3"), 'blake2b_160 (raw/file/2)');
is( blake2b_160_file_hex('t/data/text-CR.file'), "206fb81fb94a6738e2829111fbd3deabc34173a3", 'blake2b_160 (hex/file/2)');
is( blake2b_160_file_b64('t/data/text-CR.file'), "IG+4H7lKZzjigpER+9Peq8NBc6M=", 'blake2b_160 (base64/file/2)');
is( digest_file('BLAKE2b_160', 't/data/text-CR.file'), pack("H*","206fb81fb94a6738e2829111fbd3deabc34173a3"), 'blake2b_160 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2b_160', 't/data/text-CR.file'), "206fb81fb94a6738e2829111fbd3deabc34173a3", 'blake2b_160 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2b_160', 't/data/text-CR.file'), "IG+4H7lKZzjigpER+9Peq8NBc6M=", 'blake2b_160 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2b_160', 't/data/text-CR.file'), "IG-4H7lKZzjigpER-9Peq8NBc6M", 'blake2b_160 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2b_160->new->addfile('t/data/text-CR.file')->hexdigest, "206fb81fb94a6738e2829111fbd3deabc34173a3", 'blake2b_160 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_160->new->addfile($fh)->hexdigest, "206fb81fb94a6738e2829111fbd3deabc34173a3", 'blake2b_160 (OO/filehandle/2)');
  close($fh);
}

is( blake2b_160_file('t/data/text-CRLF.file'), pack("H*","a5e956dde7e949f6467d21bf58f7b26891877805"), 'blake2b_160 (raw/file/3)');
is( blake2b_160_file_hex('t/data/text-CRLF.file'), "a5e956dde7e949f6467d21bf58f7b26891877805", 'blake2b_160 (hex/file/3)');
is( blake2b_160_file_b64('t/data/text-CRLF.file'), "pelW3efpSfZGfSG/WPeyaJGHeAU=", 'blake2b_160 (base64/file/3)');
is( digest_file('BLAKE2b_160', 't/data/text-CRLF.file'), pack("H*","a5e956dde7e949f6467d21bf58f7b26891877805"), 'blake2b_160 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2b_160', 't/data/text-CRLF.file'), "a5e956dde7e949f6467d21bf58f7b26891877805", 'blake2b_160 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2b_160', 't/data/text-CRLF.file'), "pelW3efpSfZGfSG/WPeyaJGHeAU=", 'blake2b_160 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2b_160', 't/data/text-CRLF.file'), "pelW3efpSfZGfSG_WPeyaJGHeAU", 'blake2b_160 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2b_160->new->addfile('t/data/text-CRLF.file')->hexdigest, "a5e956dde7e949f6467d21bf58f7b26891877805", 'blake2b_160 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_160->new->addfile($fh)->hexdigest, "a5e956dde7e949f6467d21bf58f7b26891877805", 'blake2b_160 (OO/filehandle/3)');
  close($fh);
}

is( blake2b_160_file('t/data/text-LF.file'), pack("H*","023cb935a71ee3bf04d1b8b9b7a1d93838826f9a"), 'blake2b_160 (raw/file/4)');
is( blake2b_160_file_hex('t/data/text-LF.file'), "023cb935a71ee3bf04d1b8b9b7a1d93838826f9a", 'blake2b_160 (hex/file/4)');
is( blake2b_160_file_b64('t/data/text-LF.file'), "Ajy5Nace478E0bi5t6HZODiCb5o=", 'blake2b_160 (base64/file/4)');
is( digest_file('BLAKE2b_160', 't/data/text-LF.file'), pack("H*","023cb935a71ee3bf04d1b8b9b7a1d93838826f9a"), 'blake2b_160 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2b_160', 't/data/text-LF.file'), "023cb935a71ee3bf04d1b8b9b7a1d93838826f9a", 'blake2b_160 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2b_160', 't/data/text-LF.file'), "Ajy5Nace478E0bi5t6HZODiCb5o=", 'blake2b_160 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2b_160', 't/data/text-LF.file'), "Ajy5Nace478E0bi5t6HZODiCb5o", 'blake2b_160 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2b_160->new->addfile('t/data/text-LF.file')->hexdigest, "023cb935a71ee3bf04d1b8b9b7a1d93838826f9a", 'blake2b_160 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_160->new->addfile($fh)->hexdigest, "023cb935a71ee3bf04d1b8b9b7a1d93838826f9a", 'blake2b_160 (OO/filehandle/4)');
  close($fh);
}
