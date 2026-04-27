### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 24 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2s_224 qw( blake2s_224 blake2s_224_hex blake2s_224_b64 blake2s_224_b64u blake2s_224_file blake2s_224_file_hex blake2s_224_file_b64 blake2s_224_file_b64u );

sub dies_like {
  my ($code, $re, $name) = @_;
  my $err = eval { $code->(); '' };
  $err = $@ if $@;
  like($err, $re, $name);
}

is( Crypt::Digest::hashsize('BLAKE2s_224'), 28, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2s_224'), 28, 'hashsize/2');
is( Crypt::Digest::BLAKE2s_224::hashsize, 28, 'hashsize/3');
is( Crypt::Digest::BLAKE2s_224->hashsize, 28, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2s_224')->hashsize, 28, 'hashsize/5');
is( Crypt::Digest::BLAKE2s_224->new->hashsize, 28, 'hashsize/6');
{
  my $d = Crypt::Digest::BLAKE2s_224->new;
  isa_ok($d, 'Crypt::Digest::BLAKE2s_224', 'new returns subclass instance');
  isa_ok($d->clone, 'Crypt::Digest::BLAKE2s_224', 'clone returns subclass instance');
}
{
  my $d = Crypt::Digest::BLAKE2s_224->new->add("abc");
  my $c = $d->clone;
  is($d->hexdigest, "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55", 'blake2s_224 (clone/original-first/original)');
  is($c->hexdigest, "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55", 'blake2s_224 (clone/original-first/clone)');
}
{
  my $d = Crypt::Digest::BLAKE2s_224->new->add("abc");
  my $c = $d->clone;
  is($c->hexdigest, "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55", 'blake2s_224 (clone/clone-first/clone)');
  is($d->hexdigest, "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55", 'blake2s_224 (clone/clone-first/original)');
}
{
  my $d = Crypt::Digest::BLAKE2s_224->new->add("AAA");
  is($d->digest, pack("H*","8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006"), 'blake2s_224 (OO/digest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'blake2s_224 (OO/hexdigest/after-digest-croaks)');
  dies_like(sub { $d->add("X") }, qr/already finalized/, 'blake2s_224 (OO/add-after-digest-croaks)');
  is($d->reset->add("AAA","X")->hexdigest, "770ae85c9bd90e8806ba668e6c8000fa89d54bc9d50b05f912682afb", 'blake2s_224 (OO/reset-after-digest)');
  $d = Crypt::Digest::BLAKE2s_224->new->add("AAA");
  is($d->hexdigest, "8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006", 'blake2s_224 (OO/hexdigest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'blake2s_224 (OO/hexdigest/repeat-croaks)');
  $d = Crypt::Digest::BLAKE2s_224->new->add("AAA");
  is($d->b64digest, "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg==", 'blake2s_224 (OO/b64digest/finalizes)');
  $d = Crypt::Digest::BLAKE2s_224->new->add("AAA");
  is($d->b64udigest, "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg", 'blake2s_224 (OO/b64udigest/finalizes)');
}

is( blake2s_224("A","A","A"), pack("H*","8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006"), 'blake2s_224 (raw/tripple_A)');
is( blake2s_224_hex("A","A","A"), "8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006", 'blake2s_224 (hex/tripple_A)');
is( blake2s_224_b64("A","A","A"), "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg==", 'blake2s_224 (base64/tripple_A)');
is( blake2s_224_b64u("A","A","A"), "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg", 'blake2s_224 (base64url/tripple_A)');
is( digest_data('BLAKE2s_224', "A","A","A"), pack("H*","8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006"), 'blake2s_224 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2s_224', "A","A","A"), "8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006", 'blake2s_224 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2s_224', "A","A","A"), "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg==", 'blake2s_224 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2s_224', "A","A","A"), "jCc44Y0LlkWHDX2ktSdWzvRsXz0YX06pPDYQBg", 'blake2s_224 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2s_224->new->add("A","A","A")->hexdigest, "8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006", 'blake2s_224 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2s_224->new->add("A")->add("A")->add("A")->hexdigest, "8c2738e18d0b9645870d7da4b52756cef46c5f3d185f4ea93c361006", 'blake2s_224 (OO3/tripple_A)');


is( blake2s_224(""), pack("H*","1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4"), 'blake2s_224 (raw/1)');
is( blake2s_224_hex(""), "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4", 'blake2s_224 (hex/1)');
is( blake2s_224_b64(""), "H6EpHmUkizezQzR1sqDdY9VKEezE4+A057we9A==", 'blake2s_224 (base64/1)');
is( digest_data('BLAKE2s_224', ""), pack("H*","1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4"), 'blake2s_224 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2s_224', ""), "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4", 'blake2s_224 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2s_224', ""), "H6EpHmUkizezQzR1sqDdY9VKEezE4+A057we9A==", 'blake2s_224 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2s_224', ""), "H6EpHmUkizezQzR1sqDdY9VKEezE4-A057we9A", 'blake2s_224 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2s_224->new->add("")->hexdigest, "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4", 'blake2s_224 (OO/1)');

is( blake2s_224("123"), pack("H*","8b49aa9362d8236d18b52acbcb3a62fa07d2eb9cf007a48d044d94f1"), 'blake2s_224 (raw/2)');
is( blake2s_224_hex("123"), "8b49aa9362d8236d18b52acbcb3a62fa07d2eb9cf007a48d044d94f1", 'blake2s_224 (hex/2)');
is( blake2s_224_b64("123"), "i0mqk2LYI20YtSrLyzpi+gfS65zwB6SNBE2U8Q==", 'blake2s_224 (base64/2)');
is( digest_data('BLAKE2s_224', "123"), pack("H*","8b49aa9362d8236d18b52acbcb3a62fa07d2eb9cf007a48d044d94f1"), 'blake2s_224 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2s_224', "123"), "8b49aa9362d8236d18b52acbcb3a62fa07d2eb9cf007a48d044d94f1", 'blake2s_224 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2s_224', "123"), "i0mqk2LYI20YtSrLyzpi+gfS65zwB6SNBE2U8Q==", 'blake2s_224 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2s_224', "123"), "i0mqk2LYI20YtSrLyzpi-gfS65zwB6SNBE2U8Q", 'blake2s_224 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2s_224->new->add("123")->hexdigest, "8b49aa9362d8236d18b52acbcb3a62fa07d2eb9cf007a48d044d94f1", 'blake2s_224 (OO/2)');

is( blake2s_224("test\0test\0test\n"), pack("H*","fdb36715bc01dc9575ad662a25add0601e8c73fb8b92fd35190c9f6b"), 'blake2s_224 (raw/3)');
is( blake2s_224_hex("test\0test\0test\n"), "fdb36715bc01dc9575ad662a25add0601e8c73fb8b92fd35190c9f6b", 'blake2s_224 (hex/3)');
is( blake2s_224_b64("test\0test\0test\n"), "/bNnFbwB3JV1rWYqJa3QYB6Mc/uLkv01GQyfaw==", 'blake2s_224 (base64/3)');
is( digest_data('BLAKE2s_224', "test\0test\0test\n"), pack("H*","fdb36715bc01dc9575ad662a25add0601e8c73fb8b92fd35190c9f6b"), 'blake2s_224 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2s_224', "test\0test\0test\n"), "fdb36715bc01dc9575ad662a25add0601e8c73fb8b92fd35190c9f6b", 'blake2s_224 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2s_224', "test\0test\0test\n"), "/bNnFbwB3JV1rWYqJa3QYB6Mc/uLkv01GQyfaw==", 'blake2s_224 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2s_224', "test\0test\0test\n"), "_bNnFbwB3JV1rWYqJa3QYB6Mc_uLkv01GQyfaw", 'blake2s_224 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2s_224->new->add("test\0test\0test\n")->hexdigest, "fdb36715bc01dc9575ad662a25add0601e8c73fb8b92fd35190c9f6b", 'blake2s_224 (OO/3)');


is( blake2s_224_file('t/data/binary-test.file'), pack("H*","1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04"), 'blake2s_224 (raw/file/1)');
is( blake2s_224_file_hex('t/data/binary-test.file'), "1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04", 'blake2s_224 (hex/file/1)');
is( blake2s_224_file_b64('t/data/binary-test.file'), "EITnlqP0THwGw8ieA3AcXJUib5KwFTigWgXrBA==", 'blake2s_224 (base64/file/1)');
is( digest_file('BLAKE2s_224', 't/data/binary-test.file'), pack("H*","1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04"), 'blake2s_224 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2s_224', 't/data/binary-test.file'), "1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04", 'blake2s_224 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2s_224', 't/data/binary-test.file'), "EITnlqP0THwGw8ieA3AcXJUib5KwFTigWgXrBA==", 'blake2s_224 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2s_224', 't/data/binary-test.file'), "EITnlqP0THwGw8ieA3AcXJUib5KwFTigWgXrBA", 'blake2s_224 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2s_224->new->addfile('t/data/binary-test.file')->hexdigest, "1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04", 'blake2s_224 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_224->new->addfile($fh)->hexdigest, "1084e796a3f44c7c06c3c89e03701c5c95226f92b01538a05a05eb04", 'blake2s_224 (OO/filehandle/1)');
  close($fh);
}
is( blake2s_224_file('t/data/text-CR.file'), pack("H*","d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c"), 'blake2s_224 (raw/file/2)');
is( blake2s_224_file_hex('t/data/text-CR.file'), "d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c", 'blake2s_224 (hex/file/2)');
is( blake2s_224_file_b64('t/data/text-CR.file'), "0VlgI8wzMETverheZoakNvANECTDzqmA6f1ALA==", 'blake2s_224 (base64/file/2)');
is( digest_file('BLAKE2s_224', 't/data/text-CR.file'), pack("H*","d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c"), 'blake2s_224 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2s_224', 't/data/text-CR.file'), "d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c", 'blake2s_224 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2s_224', 't/data/text-CR.file'), "0VlgI8wzMETverheZoakNvANECTDzqmA6f1ALA==", 'blake2s_224 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2s_224', 't/data/text-CR.file'), "0VlgI8wzMETverheZoakNvANECTDzqmA6f1ALA", 'blake2s_224 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2s_224->new->addfile('t/data/text-CR.file')->hexdigest, "d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c", 'blake2s_224 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_224->new->addfile($fh)->hexdigest, "d1596023cc333044ef7ab85e6686a436f00d1024c3cea980e9fd402c", 'blake2s_224 (OO/filehandle/2)');
  close($fh);
}
is( blake2s_224_file('t/data/text-CRLF.file'), pack("H*","c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796"), 'blake2s_224 (raw/file/3)');
is( blake2s_224_file_hex('t/data/text-CRLF.file'), "c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796", 'blake2s_224 (hex/file/3)');
is( blake2s_224_file_b64('t/data/text-CRLF.file'), "womECfo+o7jihZuUT4nPtCRM7SBjhy6+vVNnlg==", 'blake2s_224 (base64/file/3)');
is( digest_file('BLAKE2s_224', 't/data/text-CRLF.file'), pack("H*","c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796"), 'blake2s_224 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2s_224', 't/data/text-CRLF.file'), "c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796", 'blake2s_224 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2s_224', 't/data/text-CRLF.file'), "womECfo+o7jihZuUT4nPtCRM7SBjhy6+vVNnlg==", 'blake2s_224 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2s_224', 't/data/text-CRLF.file'), "womECfo-o7jihZuUT4nPtCRM7SBjhy6-vVNnlg", 'blake2s_224 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2s_224->new->addfile('t/data/text-CRLF.file')->hexdigest, "c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796", 'blake2s_224 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_224->new->addfile($fh)->hexdigest, "c2898409fa3ea3b8e2859b944f89cfb4244ced2063872ebebd536796", 'blake2s_224 (OO/filehandle/3)');
  close($fh);
}
is( blake2s_224_file('t/data/text-LF.file'), pack("H*","d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89"), 'blake2s_224 (raw/file/4)');
is( blake2s_224_file_hex('t/data/text-LF.file'), "d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89", 'blake2s_224 (hex/file/4)');
is( blake2s_224_file_b64('t/data/text-LF.file'), "2Po25u0megf4cdcfUPnbxIZhJgpeahzejIAriQ==", 'blake2s_224 (base64/file/4)');
is( digest_file('BLAKE2s_224', 't/data/text-LF.file'), pack("H*","d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89"), 'blake2s_224 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2s_224', 't/data/text-LF.file'), "d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89", 'blake2s_224 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2s_224', 't/data/text-LF.file'), "2Po25u0megf4cdcfUPnbxIZhJgpeahzejIAriQ==", 'blake2s_224 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2s_224', 't/data/text-LF.file'), "2Po25u0megf4cdcfUPnbxIZhJgpeahzejIAriQ", 'blake2s_224 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2s_224->new->addfile('t/data/text-LF.file')->hexdigest, "d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89", 'blake2s_224 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2s_224->new->addfile($fh)->hexdigest, "d8fa36e6ed267a07f871d71f50f9dbc48661260a5e6a1cde8c802b89", 'blake2s_224 (OO/filehandle/4)');
  close($fh);
}
