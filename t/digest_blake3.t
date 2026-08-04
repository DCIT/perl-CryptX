### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 24 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE3 qw( blake3 blake3_hex blake3_b64 blake3_b64u blake3_file blake3_file_hex blake3_file_b64 blake3_file_b64u );

sub dies_like {
  my ($code, $re, $name) = @_;
  my $err = eval { $code->(); '' };
  $err = $@ if $@;
  like($err, $re, $name);
}

is( Crypt::Digest::hashsize('BLAKE3'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE3'), 32, 'hashsize/2');
is( Crypt::Digest::BLAKE3::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::BLAKE3->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('BLAKE3')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::BLAKE3->new->hashsize, 32, 'hashsize/6');
{
  my $d = Crypt::Digest::BLAKE3->new;
  isa_ok($d, 'Crypt::Digest::BLAKE3', 'new returns subclass instance');
  isa_ok($d->clone, 'Crypt::Digest::BLAKE3', 'clone returns subclass instance');
}
{
  my $d = Crypt::Digest::BLAKE3->new->add("abc");
  my $c = $d->clone;
  is($d->hexdigest, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", 'blake3 (clone/original-first/original)');
  is($c->hexdigest, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", 'blake3 (clone/original-first/clone)');
}
{
  my $d = Crypt::Digest::BLAKE3->new->add("abc");
  my $c = $d->clone;
  is($c->hexdigest, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", 'blake3 (clone/clone-first/clone)');
  is($d->hexdigest, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", 'blake3 (clone/clone-first/original)');
}
{
  my $d = Crypt::Digest::BLAKE3->new->add("AAA");
  is($d->digest, pack("H*","a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b"), 'blake3 (OO/digest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'blake3 (OO/hexdigest/after-digest-croaks)');
  dies_like(sub { $d->add("X") }, qr/already finalized/, 'blake3 (OO/add-after-digest-croaks)');
  is($d->reset->add("AAA","X")->hexdigest, "4c1f5a619738ee386982aace0bb35ea48d0ac8de26751b7201956f9b2b80d2d2", 'blake3 (OO/reset-after-digest)');
  $d = Crypt::Digest::BLAKE3->new->add("AAA");
  is($d->hexdigest, "a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b", 'blake3 (OO/hexdigest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'blake3 (OO/hexdigest/repeat-croaks)');
  $d = Crypt::Digest::BLAKE3->new->add("AAA");
  is($d->b64digest, "ocPRP0g6NmvHznvUKlRmRv/1u8wRTEIczAOFlcMH0Us=", 'blake3 (OO/b64digest/finalizes)');
  $d = Crypt::Digest::BLAKE3->new->add("AAA");
  is($d->b64udigest, "ocPRP0g6NmvHznvUKlRmRv_1u8wRTEIczAOFlcMH0Us", 'blake3 (OO/b64udigest/finalizes)');
}

is( blake3("A","A","A"), pack("H*","a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b"), 'blake3 (raw/tripple_A)');
is( blake3_hex("A","A","A"), "a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b", 'blake3 (hex/tripple_A)');
is( blake3_b64("A","A","A"), "ocPRP0g6NmvHznvUKlRmRv/1u8wRTEIczAOFlcMH0Us=", 'blake3 (base64/tripple_A)');
is( blake3_b64u("A","A","A"), "ocPRP0g6NmvHznvUKlRmRv_1u8wRTEIczAOFlcMH0Us", 'blake3 (base64url/tripple_A)');
is( digest_data('BLAKE3', "A","A","A"), pack("H*","a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b"), 'blake3 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE3', "A","A","A"), "a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b", 'blake3 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE3', "A","A","A"), "ocPRP0g6NmvHznvUKlRmRv/1u8wRTEIczAOFlcMH0Us=", 'blake3 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE3', "A","A","A"), "ocPRP0g6NmvHznvUKlRmRv_1u8wRTEIczAOFlcMH0Us", 'blake3 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE3->new->add("A","A","A")->hexdigest, "a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b", 'blake3 (OO/tripple_A)');
is( Crypt::Digest::BLAKE3->new->add("A")->add("A")->add("A")->hexdigest, "a1c3d13f483a366bc7ce7bd42a546646fff5bbcc114c421ccc038595c307d14b", 'blake3 (OO3/tripple_A)');


is( blake3(""), pack("H*","af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"), 'blake3 (raw/1)');
is( blake3_hex(""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", 'blake3 (hex/1)');
is( blake3_b64(""), "rxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=", 'blake3 (base64/1)');
is( digest_data('BLAKE3', ""), pack("H*","af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"), 'blake3 (digest_data_raw/1)');
is( digest_data_hex('BLAKE3', ""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", 'blake3 (digest_data_hex/1)');
is( digest_data_b64('BLAKE3', ""), "rxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=", 'blake3 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE3', ""), "rxNJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI", 'blake3 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE3->new->add("")->hexdigest, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", 'blake3 (OO/1)');

is( blake3("123"), pack("H*","b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e"), 'blake3 (raw/2)');
is( blake3_hex("123"), "b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e", 'blake3 (hex/2)');
is( blake3_b64("123"), "s9T4gD9+JLjzibBy51R3zbz74HQID7XlAOU+JuBUFY4=", 'blake3 (base64/2)');
is( digest_data('BLAKE3', "123"), pack("H*","b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e"), 'blake3 (digest_data_raw/2)');
is( digest_data_hex('BLAKE3', "123"), "b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e", 'blake3 (digest_data_hex/2)');
is( digest_data_b64('BLAKE3', "123"), "s9T4gD9+JLjzibBy51R3zbz74HQID7XlAOU+JuBUFY4=", 'blake3 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE3', "123"), "s9T4gD9-JLjzibBy51R3zbz74HQID7XlAOU-JuBUFY4", 'blake3 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE3->new->add("123")->hexdigest, "b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e", 'blake3 (OO/2)');

is( blake3("test\0test\0test\n"), pack("H*","84acf89ef6367415c83d6364b600fbdc39478d0d6e9dd53e5aa125bdfa845b1d"), 'blake3 (raw/3)');
is( blake3_hex("test\0test\0test\n"), "84acf89ef6367415c83d6364b600fbdc39478d0d6e9dd53e5aa125bdfa845b1d", 'blake3 (hex/3)');
is( blake3_b64("test\0test\0test\n"), "hKz4nvY2dBXIPWNktgD73DlHjQ1undU+WqElvfqEWx0=", 'blake3 (base64/3)');
is( digest_data('BLAKE3', "test\0test\0test\n"), pack("H*","84acf89ef6367415c83d6364b600fbdc39478d0d6e9dd53e5aa125bdfa845b1d"), 'blake3 (digest_data_raw/3)');
is( digest_data_hex('BLAKE3', "test\0test\0test\n"), "84acf89ef6367415c83d6364b600fbdc39478d0d6e9dd53e5aa125bdfa845b1d", 'blake3 (digest_data_hex/3)');
is( digest_data_b64('BLAKE3', "test\0test\0test\n"), "hKz4nvY2dBXIPWNktgD73DlHjQ1undU+WqElvfqEWx0=", 'blake3 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE3', "test\0test\0test\n"), "hKz4nvY2dBXIPWNktgD73DlHjQ1undU-WqElvfqEWx0", 'blake3 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE3->new->add("test\0test\0test\n")->hexdigest, "84acf89ef6367415c83d6364b600fbdc39478d0d6e9dd53e5aa125bdfa845b1d", 'blake3 (OO/3)');


is( blake3_file('t/data/binary-test.file'), pack("H*","610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb"), 'blake3 (raw/file/1)');
is( blake3_file_hex('t/data/binary-test.file'), "610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb", 'blake3 (hex/file/1)');
is( blake3_file_b64('t/data/binary-test.file'), "YQMxxodQee8RSqOanSlFT2Bp++6PVcO2Sg7jb/FYP8s=", 'blake3 (base64/file/1)');
is( digest_file('BLAKE3', 't/data/binary-test.file'), pack("H*","610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb"), 'blake3 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE3', 't/data/binary-test.file'), "610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb", 'blake3 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE3', 't/data/binary-test.file'), "YQMxxodQee8RSqOanSlFT2Bp++6PVcO2Sg7jb/FYP8s=", 'blake3 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE3', 't/data/binary-test.file'), "YQMxxodQee8RSqOanSlFT2Bp--6PVcO2Sg7jb_FYP8s", 'blake3 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE3->new->addfile('t/data/binary-test.file')->hexdigest, "610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb", 'blake3 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE3->new->addfile($fh)->hexdigest, "610331c6875079ef114aa39a9d29454f6069fbee8f55c3b64a0ee36ff1583fcb", 'blake3 (OO/filehandle/1)');
  close($fh);
}
is( blake3_file('t/data/text-CR.file'), pack("H*","d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b"), 'blake3 (raw/file/2)');
is( blake3_file_hex('t/data/text-CR.file'), "d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b", 'blake3 (hex/file/2)');
is( blake3_file_b64('t/data/text-CR.file'), "2FPUacHbHP/HG1rlROYb3bCgXju1lKXljsJ2HOkvyWs=", 'blake3 (base64/file/2)');
is( digest_file('BLAKE3', 't/data/text-CR.file'), pack("H*","d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b"), 'blake3 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE3', 't/data/text-CR.file'), "d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b", 'blake3 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE3', 't/data/text-CR.file'), "2FPUacHbHP/HG1rlROYb3bCgXju1lKXljsJ2HOkvyWs=", 'blake3 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE3', 't/data/text-CR.file'), "2FPUacHbHP_HG1rlROYb3bCgXju1lKXljsJ2HOkvyWs", 'blake3 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE3->new->addfile('t/data/text-CR.file')->hexdigest, "d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b", 'blake3 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE3->new->addfile($fh)->hexdigest, "d853d469c1db1cffc71b5ae544e61bddb0a05e3bb594a5e58ec2761ce92fc96b", 'blake3 (OO/filehandle/2)');
  close($fh);
}
is( blake3_file('t/data/text-CRLF.file'), pack("H*","f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0"), 'blake3 (raw/file/3)');
is( blake3_file_hex('t/data/text-CRLF.file'), "f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0", 'blake3 (hex/file/3)');
is( blake3_file_b64('t/data/text-CRLF.file'), "9vYZFVqfb3ASrDwJ1lXgbFbP4Sb1CgclwpOKBnG4+cA=", 'blake3 (base64/file/3)');
is( digest_file('BLAKE3', 't/data/text-CRLF.file'), pack("H*","f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0"), 'blake3 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE3', 't/data/text-CRLF.file'), "f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0", 'blake3 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE3', 't/data/text-CRLF.file'), "9vYZFVqfb3ASrDwJ1lXgbFbP4Sb1CgclwpOKBnG4+cA=", 'blake3 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE3', 't/data/text-CRLF.file'), "9vYZFVqfb3ASrDwJ1lXgbFbP4Sb1CgclwpOKBnG4-cA", 'blake3 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE3->new->addfile('t/data/text-CRLF.file')->hexdigest, "f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0", 'blake3 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE3->new->addfile($fh)->hexdigest, "f6f619155a9f6f7012ac3c09d655e06c56cfe126f50a0725c2938a0671b8f9c0", 'blake3 (OO/filehandle/3)');
  close($fh);
}
is( blake3_file('t/data/text-LF.file'), pack("H*","0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f"), 'blake3 (raw/file/4)');
is( blake3_file_hex('t/data/text-LF.file'), "0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f", 'blake3 (hex/file/4)');
is( blake3_file_b64('t/data/text-LF.file'), "D6CaQQe04Qt/Zmon+hMWlKOEgmiLxVo9x8p0j07oG58=", 'blake3 (base64/file/4)');
is( digest_file('BLAKE3', 't/data/text-LF.file'), pack("H*","0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f"), 'blake3 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE3', 't/data/text-LF.file'), "0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f", 'blake3 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE3', 't/data/text-LF.file'), "D6CaQQe04Qt/Zmon+hMWlKOEgmiLxVo9x8p0j07oG58=", 'blake3 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE3', 't/data/text-LF.file'), "D6CaQQe04Qt_Zmon-hMWlKOEgmiLxVo9x8p0j07oG58", 'blake3 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE3->new->addfile('t/data/text-LF.file')->hexdigest, "0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f", 'blake3 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE3->new->addfile($fh)->hexdigest, "0fa09a4107b4e10b7f666a27fa131694a38482688bc55a3dc7ca748f4ee81b9f", 'blake3 (OO/filehandle/4)');
  close($fh);
}
