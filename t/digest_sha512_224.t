### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA512_224 qw( sha512_224 sha512_224_hex sha512_224_b64 sha512_224_b64u sha512_224_file sha512_224_file_hex sha512_224_file_b64 sha512_224_file_b64u );

is( Crypt::Digest::hashsize('SHA512_224'), 28, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA512_224'), 28, 'hashsize/2');
is( Crypt::Digest::SHA512_224::hashsize, 28, 'hashsize/3');
is( Crypt::Digest::SHA512_224->hashsize, 28, 'hashsize/4');
is( Crypt::Digest->new('SHA512_224')->hashsize, 28, 'hashsize/5');
is( Crypt::Digest::SHA512_224->new->hashsize, 28, 'hashsize/6');

is( sha512_224("A","A","A"), pack("H*","3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3"), 'sha512_224 (raw/tripple_A)');
is( sha512_224_hex("A","A","A"), "3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3", 'sha512_224 (hex/tripple_A)');
is( sha512_224_b64("A","A","A"), "PVoLdC9MYdMVxs6GRXqfowkDiA0wVYxozkcTsw==", 'sha512_224 (base64/tripple_A)');
is( sha512_224_b64u("A","A","A"), "PVoLdC9MYdMVxs6GRXqfowkDiA0wVYxozkcTsw", 'sha512_224 (base64url/tripple_A)');
is( digest_data('SHA512_224', "A","A","A"), pack("H*","3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3"), 'sha512_224 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA512_224', "A","A","A"), "3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3", 'sha512_224 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA512_224', "A","A","A"), "PVoLdC9MYdMVxs6GRXqfowkDiA0wVYxozkcTsw==", 'sha512_224 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA512_224', "A","A","A"), "PVoLdC9MYdMVxs6GRXqfowkDiA0wVYxozkcTsw", 'sha512_224 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA512_224->new->add("A","A","A")->hexdigest, "3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3", 'sha512_224 (OO/tripple_A)');
is( Crypt::Digest::SHA512_224->new->add("A")->add("A")->add("A")->hexdigest, "3d5a0b742f4c61d315c6ce86457a9fa30903880d30558c68ce4713b3", 'sha512_224 (OO3/tripple_A)');


is( sha512_224(""), pack("H*","6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"), 'sha512_224 (raw/1)');
is( sha512_224_hex(""), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", 'sha512_224 (hex/1)');
is( sha512_224_b64(""), "btDdAoBvqJ4l3gYMGdOshsq7h9ag3dBcMzuE9A==", 'sha512_224 (base64/1)');
is( digest_data('SHA512_224', ""), pack("H*","6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"), 'sha512_224 (digest_data_raw/1)');
is( digest_data_hex('SHA512_224', ""), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", 'sha512_224 (digest_data_hex/1)');
is( digest_data_b64('SHA512_224', ""), "btDdAoBvqJ4l3gYMGdOshsq7h9ag3dBcMzuE9A==", 'sha512_224 (digest_data_b64/1)');
is( digest_data_b64u('SHA512_224', ""), "btDdAoBvqJ4l3gYMGdOshsq7h9ag3dBcMzuE9A", 'sha512_224 (digest_data_b64u/1)');
is( Crypt::Digest::SHA512_224->new->add("")->hexdigest, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", 'sha512_224 (OO/1)');

is( sha512_224("123"), pack("H*","10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a"), 'sha512_224 (raw/2)');
is( sha512_224_hex("123"), "10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a", 'sha512_224 (hex/2)');
is( sha512_224_b64("123"), "ELcGQXOgkNz2zfMKZoMf2KpBYtl9ChTYj2D5Wg==", 'sha512_224 (base64/2)');
is( digest_data('SHA512_224', "123"), pack("H*","10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a"), 'sha512_224 (digest_data_raw/2)');
is( digest_data_hex('SHA512_224', "123"), "10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a", 'sha512_224 (digest_data_hex/2)');
is( digest_data_b64('SHA512_224', "123"), "ELcGQXOgkNz2zfMKZoMf2KpBYtl9ChTYj2D5Wg==", 'sha512_224 (digest_data_b64/2)');
is( digest_data_b64u('SHA512_224', "123"), "ELcGQXOgkNz2zfMKZoMf2KpBYtl9ChTYj2D5Wg", 'sha512_224 (digest_data_b64u/2)');
is( Crypt::Digest::SHA512_224->new->add("123")->hexdigest, "10b7064173a090dcf6cdf30a66831fd8aa4162d97d0a14d88f60f95a", 'sha512_224 (OO/2)');

is( sha512_224("test\0test\0test\n"), pack("H*","41a0c9115afa481c3afef7b778aac6b647a966947b0e2e559b053caa"), 'sha512_224 (raw/3)');
is( sha512_224_hex("test\0test\0test\n"), "41a0c9115afa481c3afef7b778aac6b647a966947b0e2e559b053caa", 'sha512_224 (hex/3)');
is( sha512_224_b64("test\0test\0test\n"), "QaDJEVr6SBw6/ve3eKrGtkepZpR7Di5VmwU8qg==", 'sha512_224 (base64/3)');
is( digest_data('SHA512_224', "test\0test\0test\n"), pack("H*","41a0c9115afa481c3afef7b778aac6b647a966947b0e2e559b053caa"), 'sha512_224 (digest_data_raw/3)');
is( digest_data_hex('SHA512_224', "test\0test\0test\n"), "41a0c9115afa481c3afef7b778aac6b647a966947b0e2e559b053caa", 'sha512_224 (digest_data_hex/3)');
is( digest_data_b64('SHA512_224', "test\0test\0test\n"), "QaDJEVr6SBw6/ve3eKrGtkepZpR7Di5VmwU8qg==", 'sha512_224 (digest_data_b64/3)');
is( digest_data_b64u('SHA512_224', "test\0test\0test\n"), "QaDJEVr6SBw6_ve3eKrGtkepZpR7Di5VmwU8qg", 'sha512_224 (digest_data_b64u/3)');
is( Crypt::Digest::SHA512_224->new->add("test\0test\0test\n")->hexdigest, "41a0c9115afa481c3afef7b778aac6b647a966947b0e2e559b053caa", 'sha512_224 (OO/3)');


is( sha512_224_file('t/data/binary-test.file'), pack("H*","8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d"), 'sha512_224 (raw/file/1)');
is( sha512_224_file_hex('t/data/binary-test.file'), "8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d", 'sha512_224 (hex/file/1)');
is( sha512_224_file_b64('t/data/binary-test.file'), "gyfPkuBk64v+cRihb9v2CLXTswZL0/Jw3YddnQ==", 'sha512_224 (base64/file/1)');
is( digest_file('SHA512_224', 't/data/binary-test.file'), pack("H*","8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d"), 'sha512_224 (digest_file_raw/file/1)');
is( digest_file_hex('SHA512_224', 't/data/binary-test.file'), "8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d", 'sha512_224 (digest_file_hex/file/1)');
is( digest_file_b64('SHA512_224', 't/data/binary-test.file'), "gyfPkuBk64v+cRihb9v2CLXTswZL0/Jw3YddnQ==", 'sha512_224 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA512_224', 't/data/binary-test.file'), "gyfPkuBk64v-cRihb9v2CLXTswZL0_Jw3YddnQ", 'sha512_224 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA512_224->new->addfile('t/data/binary-test.file')->hexdigest, "8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d", 'sha512_224 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_224->new->addfile($fh)->hexdigest, "8327cf92e064eb8bfe7118a16fdbf608b5d3b3064bd3f270dd875d9d", 'sha512_224 (OO/filehandle/1)');
  close($fh);
}

is( sha512_224_file('t/data/text-CR.file'), pack("H*","c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b"), 'sha512_224 (raw/file/2)');
is( sha512_224_file_hex('t/data/text-CR.file'), "c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b", 'sha512_224 (hex/file/2)');
is( sha512_224_file_b64('t/data/text-CR.file'), "wC1HKASYCYJgrNHY4yzcdzzKPfMIg0GGWV91Kw==", 'sha512_224 (base64/file/2)');
is( digest_file('SHA512_224', 't/data/text-CR.file'), pack("H*","c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b"), 'sha512_224 (digest_file_raw/file/2)');
is( digest_file_hex('SHA512_224', 't/data/text-CR.file'), "c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b", 'sha512_224 (digest_file_hex/file/2)');
is( digest_file_b64('SHA512_224', 't/data/text-CR.file'), "wC1HKASYCYJgrNHY4yzcdzzKPfMIg0GGWV91Kw==", 'sha512_224 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA512_224', 't/data/text-CR.file'), "wC1HKASYCYJgrNHY4yzcdzzKPfMIg0GGWV91Kw", 'sha512_224 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA512_224->new->addfile('t/data/text-CR.file')->hexdigest, "c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b", 'sha512_224 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_224->new->addfile($fh)->hexdigest, "c02d47280498098260acd1d8e32cdc773cca3df308834186595f752b", 'sha512_224 (OO/filehandle/2)');
  close($fh);
}

is( sha512_224_file('t/data/text-CRLF.file'), pack("H*","b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60"), 'sha512_224 (raw/file/3)');
is( sha512_224_file_hex('t/data/text-CRLF.file'), "b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60", 'sha512_224 (hex/file/3)');
is( sha512_224_file_b64('t/data/text-CRLF.file'), "sKm588WwreXYyvUBqS4SkvwURzP/9tJ5nsT8YA==", 'sha512_224 (base64/file/3)');
is( digest_file('SHA512_224', 't/data/text-CRLF.file'), pack("H*","b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60"), 'sha512_224 (digest_file_raw/file/3)');
is( digest_file_hex('SHA512_224', 't/data/text-CRLF.file'), "b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60", 'sha512_224 (digest_file_hex/file/3)');
is( digest_file_b64('SHA512_224', 't/data/text-CRLF.file'), "sKm588WwreXYyvUBqS4SkvwURzP/9tJ5nsT8YA==", 'sha512_224 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA512_224', 't/data/text-CRLF.file'), "sKm588WwreXYyvUBqS4SkvwURzP_9tJ5nsT8YA", 'sha512_224 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA512_224->new->addfile('t/data/text-CRLF.file')->hexdigest, "b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60", 'sha512_224 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_224->new->addfile($fh)->hexdigest, "b0a9b9f3c5b0ade5d8caf501a92e1292fc144733fff6d2799ec4fc60", 'sha512_224 (OO/filehandle/3)');
  close($fh);
}

is( sha512_224_file('t/data/text-LF.file'), pack("H*","0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d"), 'sha512_224 (raw/file/4)');
is( sha512_224_file_hex('t/data/text-LF.file'), "0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d", 'sha512_224 (hex/file/4)');
is( sha512_224_file_b64('t/data/text-LF.file'), "DkArG57jzaDii5ehSq6R9dvichrkaQiZiKuQTQ==", 'sha512_224 (base64/file/4)');
is( digest_file('SHA512_224', 't/data/text-LF.file'), pack("H*","0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d"), 'sha512_224 (digest_file_raw/file/4)');
is( digest_file_hex('SHA512_224', 't/data/text-LF.file'), "0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d", 'sha512_224 (digest_file_hex/file/4)');
is( digest_file_b64('SHA512_224', 't/data/text-LF.file'), "DkArG57jzaDii5ehSq6R9dvichrkaQiZiKuQTQ==", 'sha512_224 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA512_224', 't/data/text-LF.file'), "DkArG57jzaDii5ehSq6R9dvichrkaQiZiKuQTQ", 'sha512_224 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA512_224->new->addfile('t/data/text-LF.file')->hexdigest, "0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d", 'sha512_224 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512_224->new->addfile($fh)->hexdigest, "0e402b1b9ee3cda0e28b97a14aae91f5dbe2721ae469089988ab904d", 'sha512_224 (OO/filehandle/4)');
  close($fh);
}
