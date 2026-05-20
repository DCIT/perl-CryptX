### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 24 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SM3 qw( sm3 sm3_hex sm3_b64 sm3_b64u sm3_file sm3_file_hex sm3_file_b64 sm3_file_b64u );

sub dies_like {
  my ($code, $re, $name) = @_;
  my $err = eval { $code->(); '' };
  $err = $@ if $@;
  like($err, $re, $name);
}

is( Crypt::Digest::hashsize('SM3'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('SM3'), 32, 'hashsize/2');
is( Crypt::Digest::SM3::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::SM3->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('SM3')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::SM3->new->hashsize, 32, 'hashsize/6');
{
  my $d = Crypt::Digest::SM3->new;
  isa_ok($d, 'Crypt::Digest::SM3', 'new returns subclass instance');
  isa_ok($d->clone, 'Crypt::Digest::SM3', 'clone returns subclass instance');
}
{
  my $d = Crypt::Digest::SM3->new->add("abc");
  my $c = $d->clone;
  is($d->hexdigest, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 'sm3 (clone/original-first/original)');
  is($c->hexdigest, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 'sm3 (clone/original-first/clone)');
}
{
  my $d = Crypt::Digest::SM3->new->add("abc");
  my $c = $d->clone;
  is($c->hexdigest, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 'sm3 (clone/clone-first/clone)');
  is($d->hexdigest, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 'sm3 (clone/clone-first/original)');
}
{
  my $d = Crypt::Digest::SM3->new->add("AAA");
  is($d->digest, pack("H*","27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341"), 'sm3 (OO/digest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'sm3 (OO/hexdigest/after-digest-croaks)');
  dies_like(sub { $d->add("X") }, qr/already finalized/, 'sm3 (OO/add-after-digest-croaks)');
  is($d->reset->add("AAA","X")->hexdigest, "ae00cf88a549a1cff7f45c7080fd785779e3091b544915e82b609ed3880f4300", 'sm3 (OO/reset-after-digest)');
  $d = Crypt::Digest::SM3->new->add("AAA");
  is($d->hexdigest, "27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341", 'sm3 (OO/hexdigest/finalizes)');
  dies_like(sub { $d->hexdigest }, qr/already finalized/, 'sm3 (OO/hexdigest/repeat-croaks)');
  $d = Crypt::Digest::SM3->new->add("AAA");
  is($d->b64digest, "J8HinbFCjTfjwKbf7r0SL/24j6kNToMQK2m32dn0U0E=", 'sm3 (OO/b64digest/finalizes)');
  $d = Crypt::Digest::SM3->new->add("AAA");
  is($d->b64udigest, "J8HinbFCjTfjwKbf7r0SL_24j6kNToMQK2m32dn0U0E", 'sm3 (OO/b64udigest/finalizes)');
}

is( sm3("A","A","A"), pack("H*","27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341"), 'sm3 (raw/tripple_A)');
is( sm3_hex("A","A","A"), "27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341", 'sm3 (hex/tripple_A)');
is( sm3_b64("A","A","A"), "J8HinbFCjTfjwKbf7r0SL/24j6kNToMQK2m32dn0U0E=", 'sm3 (base64/tripple_A)');
is( sm3_b64u("A","A","A"), "J8HinbFCjTfjwKbf7r0SL_24j6kNToMQK2m32dn0U0E", 'sm3 (base64url/tripple_A)');
is( digest_data('SM3', "A","A","A"), pack("H*","27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341"), 'sm3 (digest_data_raw/tripple_A)');
is( digest_data_hex('SM3', "A","A","A"), "27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341", 'sm3 (digest_data_hex/tripple_A)');
is( digest_data_b64('SM3', "A","A","A"), "J8HinbFCjTfjwKbf7r0SL/24j6kNToMQK2m32dn0U0E=", 'sm3 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SM3', "A","A","A"), "J8HinbFCjTfjwKbf7r0SL_24j6kNToMQK2m32dn0U0E", 'sm3 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SM3->new->add("A","A","A")->hexdigest, "27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341", 'sm3 (OO/tripple_A)');
is( Crypt::Digest::SM3->new->add("A")->add("A")->add("A")->hexdigest, "27c1e29db1428d37e3c0a6dfeebd122ffdb88fa90d4e83102b69b7d9d9f45341", 'sm3 (OO3/tripple_A)');


is( sm3(""), pack("H*","1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"), 'sm3 (raw/1)');
is( sm3_hex(""), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", 'sm3 (hex/1)');
is( sm3_b64(""), "GrIdg1XPoX+OYRlIMegajyK+yMco/vt0ftA161CCqis=", 'sm3 (base64/1)');
is( digest_data('SM3', ""), pack("H*","1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"), 'sm3 (digest_data_raw/1)');
is( digest_data_hex('SM3', ""), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", 'sm3 (digest_data_hex/1)');
is( digest_data_b64('SM3', ""), "GrIdg1XPoX+OYRlIMegajyK+yMco/vt0ftA161CCqis=", 'sm3 (digest_data_b64/1)');
is( digest_data_b64u('SM3', ""), "GrIdg1XPoX-OYRlIMegajyK-yMco_vt0ftA161CCqis", 'sm3 (digest_data_b64u/1)');
is( Crypt::Digest::SM3->new->add("")->hexdigest, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", 'sm3 (OO/1)');

is( sm3("123"), pack("H*","6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957"), 'sm3 (raw/2)');
is( sm3_hex("123"), "6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957", 'sm3 (hex/2)');
is( sm3_b64("123"), "bg+eFDRMVAagz1o7TftmX4f0p3GjH37btccodKMrKVc=", 'sm3 (base64/2)');
is( digest_data('SM3', "123"), pack("H*","6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957"), 'sm3 (digest_data_raw/2)');
is( digest_data_hex('SM3', "123"), "6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957", 'sm3 (digest_data_hex/2)');
is( digest_data_b64('SM3', "123"), "bg+eFDRMVAagz1o7TftmX4f0p3GjH37btccodKMrKVc=", 'sm3 (digest_data_b64/2)');
is( digest_data_b64u('SM3', "123"), "bg-eFDRMVAagz1o7TftmX4f0p3GjH37btccodKMrKVc", 'sm3 (digest_data_b64u/2)');
is( Crypt::Digest::SM3->new->add("123")->hexdigest, "6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957", 'sm3 (OO/2)');

is( sm3("test\0test\0test\n"), pack("H*","59683694830a6cb81a5e946b0b7610c1cdaaee479a325f78c38e2f150057164b"), 'sm3 (raw/3)');
is( sm3_hex("test\0test\0test\n"), "59683694830a6cb81a5e946b0b7610c1cdaaee479a325f78c38e2f150057164b", 'sm3 (hex/3)');
is( sm3_b64("test\0test\0test\n"), "WWg2lIMKbLgaXpRrC3YQwc2q7keaMl94w44vFQBXFks=", 'sm3 (base64/3)');
is( digest_data('SM3', "test\0test\0test\n"), pack("H*","59683694830a6cb81a5e946b0b7610c1cdaaee479a325f78c38e2f150057164b"), 'sm3 (digest_data_raw/3)');
is( digest_data_hex('SM3', "test\0test\0test\n"), "59683694830a6cb81a5e946b0b7610c1cdaaee479a325f78c38e2f150057164b", 'sm3 (digest_data_hex/3)');
is( digest_data_b64('SM3', "test\0test\0test\n"), "WWg2lIMKbLgaXpRrC3YQwc2q7keaMl94w44vFQBXFks=", 'sm3 (digest_data_b64/3)');
is( digest_data_b64u('SM3', "test\0test\0test\n"), "WWg2lIMKbLgaXpRrC3YQwc2q7keaMl94w44vFQBXFks", 'sm3 (digest_data_b64u/3)');
is( Crypt::Digest::SM3->new->add("test\0test\0test\n")->hexdigest, "59683694830a6cb81a5e946b0b7610c1cdaaee479a325f78c38e2f150057164b", 'sm3 (OO/3)');


is( sm3_file('t/data/binary-test.file'), pack("H*","0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27"), 'sm3 (raw/file/1)');
is( sm3_file_hex('t/data/binary-test.file'), "0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27", 'sm3 (hex/file/1)');
is( sm3_file_b64('t/data/binary-test.file'), "DhkQo4nstE2svwRGvAjFuaUKiyJkoGGODyCQiCX7Sic=", 'sm3 (base64/file/1)');
is( digest_file('SM3', 't/data/binary-test.file'), pack("H*","0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27"), 'sm3 (digest_file_raw/file/1)');
is( digest_file_hex('SM3', 't/data/binary-test.file'), "0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27", 'sm3 (digest_file_hex/file/1)');
is( digest_file_b64('SM3', 't/data/binary-test.file'), "DhkQo4nstE2svwRGvAjFuaUKiyJkoGGODyCQiCX7Sic=", 'sm3 (digest_file_b64/file/1)');
is( digest_file_b64u('SM3', 't/data/binary-test.file'), "DhkQo4nstE2svwRGvAjFuaUKiyJkoGGODyCQiCX7Sic", 'sm3 (digest_file_b64u/file/1)');
is( Crypt::Digest::SM3->new->addfile('t/data/binary-test.file')->hexdigest, "0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27", 'sm3 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SM3->new->addfile($fh)->hexdigest, "0e1910a389ecb44dacbf0446bc08c5b9a50a8b2264a0618e0f20908825fb4a27", 'sm3 (OO/filehandle/1)');
  close($fh);
}
is( sm3_file('t/data/text-CR.file'), pack("H*","127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba"), 'sm3 (raw/file/2)');
is( sm3_file_hex('t/data/text-CR.file'), "127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba", 'sm3 (hex/file/2)');
is( sm3_file_b64('t/data/text-CR.file'), "En9gekB8T3DQcfhG6iJfBiGFsRXeJGIKFH6ummtzhLo=", 'sm3 (base64/file/2)');
is( digest_file('SM3', 't/data/text-CR.file'), pack("H*","127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba"), 'sm3 (digest_file_raw/file/2)');
is( digest_file_hex('SM3', 't/data/text-CR.file'), "127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba", 'sm3 (digest_file_hex/file/2)');
is( digest_file_b64('SM3', 't/data/text-CR.file'), "En9gekB8T3DQcfhG6iJfBiGFsRXeJGIKFH6ummtzhLo=", 'sm3 (digest_file_b64/file/2)');
is( digest_file_b64u('SM3', 't/data/text-CR.file'), "En9gekB8T3DQcfhG6iJfBiGFsRXeJGIKFH6ummtzhLo", 'sm3 (digest_file_b64u/file/2)');
is( Crypt::Digest::SM3->new->addfile('t/data/text-CR.file')->hexdigest, "127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba", 'sm3 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SM3->new->addfile($fh)->hexdigest, "127f607a407c4f70d071f846ea225f062185b115de24620a147eae9a6b7384ba", 'sm3 (OO/filehandle/2)');
  close($fh);
}
is( sm3_file('t/data/text-CRLF.file'), pack("H*","e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0"), 'sm3 (raw/file/3)');
is( sm3_file_hex('t/data/text-CRLF.file'), "e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0", 'sm3 (hex/file/3)');
is( sm3_file_b64('t/data/text-CRLF.file'), "5ISxHaoxR3AfGx0mk8zYOH/qunxvB9+mUH2gqG2Ra/A=", 'sm3 (base64/file/3)');
is( digest_file('SM3', 't/data/text-CRLF.file'), pack("H*","e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0"), 'sm3 (digest_file_raw/file/3)');
is( digest_file_hex('SM3', 't/data/text-CRLF.file'), "e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0", 'sm3 (digest_file_hex/file/3)');
is( digest_file_b64('SM3', 't/data/text-CRLF.file'), "5ISxHaoxR3AfGx0mk8zYOH/qunxvB9+mUH2gqG2Ra/A=", 'sm3 (digest_file_b64/file/3)');
is( digest_file_b64u('SM3', 't/data/text-CRLF.file'), "5ISxHaoxR3AfGx0mk8zYOH_qunxvB9-mUH2gqG2Ra_A", 'sm3 (digest_file_b64u/file/3)');
is( Crypt::Digest::SM3->new->addfile('t/data/text-CRLF.file')->hexdigest, "e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0", 'sm3 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SM3->new->addfile($fh)->hexdigest, "e484b11daa3147701f1b1d2693ccd8387feaba7c6f07dfa6507da0a86d916bf0", 'sm3 (OO/filehandle/3)');
  close($fh);
}
is( sm3_file('t/data/text-LF.file'), pack("H*","75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a"), 'sm3 (raw/file/4)');
is( sm3_file_hex('t/data/text-LF.file'), "75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a", 'sm3 (hex/file/4)');
is( sm3_file_b64('t/data/text-LF.file'), "dapvLhE+BCSM6Uuae/bFspaQZ8AtyI5BhrE5KAaUWko=", 'sm3 (base64/file/4)');
is( digest_file('SM3', 't/data/text-LF.file'), pack("H*","75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a"), 'sm3 (digest_file_raw/file/4)');
is( digest_file_hex('SM3', 't/data/text-LF.file'), "75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a", 'sm3 (digest_file_hex/file/4)');
is( digest_file_b64('SM3', 't/data/text-LF.file'), "dapvLhE+BCSM6Uuae/bFspaQZ8AtyI5BhrE5KAaUWko=", 'sm3 (digest_file_b64/file/4)');
is( digest_file_b64u('SM3', 't/data/text-LF.file'), "dapvLhE-BCSM6Uuae_bFspaQZ8AtyI5BhrE5KAaUWko", 'sm3 (digest_file_b64u/file/4)');
is( Crypt::Digest::SM3->new->addfile('t/data/text-LF.file')->hexdigest, "75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a", 'sm3 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SM3->new->addfile($fh)->hexdigest, "75aa6f2e113e04248ce94b9a7bf6c5b2969067c02dc88e4186b1392806945a4a", 'sm3 (OO/filehandle/4)');
  close($fh);
}
