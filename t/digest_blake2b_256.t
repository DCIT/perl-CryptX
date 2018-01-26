### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::BLAKE2b_256 qw( blake2b_256 blake2b_256_hex blake2b_256_b64 blake2b_256_b64u blake2b_256_file blake2b_256_file_hex blake2b_256_file_b64 blake2b_256_file_b64u );

is( Crypt::Digest::hashsize('BLAKE2b_256'), 32, 'hashsize/1');
is( Crypt::Digest->hashsize('BLAKE2b_256'), 32, 'hashsize/2');
is( Crypt::Digest::BLAKE2b_256::hashsize, 32, 'hashsize/3');
is( Crypt::Digest::BLAKE2b_256->hashsize, 32, 'hashsize/4');
is( Crypt::Digest->new('BLAKE2b_256')->hashsize, 32, 'hashsize/5');
is( Crypt::Digest::BLAKE2b_256->new->hashsize, 32, 'hashsize/6');

is( blake2b_256("A","A","A"), pack("H*","cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649"), 'blake2b_256 (raw/tripple_A)');
is( blake2b_256_hex("A","A","A"), "cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649", 'blake2b_256 (hex/tripple_A)');
is( blake2b_256_b64("A","A","A"), "zcQzkpZ1P5MKpFRwD9De1uHgh3LeqEmFnhfbvYXK5kk=", 'blake2b_256 (base64/tripple_A)');
is( blake2b_256_b64u("A","A","A"), "zcQzkpZ1P5MKpFRwD9De1uHgh3LeqEmFnhfbvYXK5kk", 'blake2b_256 (base64url/tripple_A)');
is( digest_data('BLAKE2b_256', "A","A","A"), pack("H*","cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649"), 'blake2b_256 (digest_data_raw/tripple_A)');
is( digest_data_hex('BLAKE2b_256', "A","A","A"), "cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649", 'blake2b_256 (digest_data_hex/tripple_A)');
is( digest_data_b64('BLAKE2b_256', "A","A","A"), "zcQzkpZ1P5MKpFRwD9De1uHgh3LeqEmFnhfbvYXK5kk=", 'blake2b_256 (digest_data_b64/tripple_A)');
is( digest_data_b64u('BLAKE2b_256', "A","A","A"), "zcQzkpZ1P5MKpFRwD9De1uHgh3LeqEmFnhfbvYXK5kk", 'blake2b_256 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::BLAKE2b_256->new->add("A","A","A")->hexdigest, "cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649", 'blake2b_256 (OO/tripple_A)');
is( Crypt::Digest::BLAKE2b_256->new->add("A")->add("A")->add("A")->hexdigest, "cdc4339296753f930aa454700fd0ded6e1e08772dea849859e17dbbd85cae649", 'blake2b_256 (OO3/tripple_A)');


is( blake2b_256(""), pack("H*","0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"), 'blake2b_256 (raw/1)');
is( blake2b_256_hex(""), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", 'blake2b_256 (hex/1)');
is( blake2b_256_b64(""), "DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g=", 'blake2b_256 (base64/1)');
is( digest_data('BLAKE2b_256', ""), pack("H*","0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"), 'blake2b_256 (digest_data_raw/1)');
is( digest_data_hex('BLAKE2b_256', ""), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", 'blake2b_256 (digest_data_hex/1)');
is( digest_data_b64('BLAKE2b_256', ""), "DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g=", 'blake2b_256 (digest_data_b64/1)');
is( digest_data_b64u('BLAKE2b_256', ""), "DldRwCblQ7Loqy6wYJnaodHl30d3j3eH-qtFzfEv46g", 'blake2b_256 (digest_data_b64u/1)');
is( Crypt::Digest::BLAKE2b_256->new->add("")->hexdigest, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", 'blake2b_256 (OO/1)');

is( blake2b_256("123"), pack("H*","f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf"), 'blake2b_256 (raw/2)');
is( blake2b_256_hex("123"), "f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf", 'blake2b_256 (hex/2)');
is( blake2b_256_b64("123"), "9dZ7rnOw4Q0N/TBDs/TxAK2gFMXDe9XOl4E7E/WrK88=", 'blake2b_256 (base64/2)');
is( digest_data('BLAKE2b_256', "123"), pack("H*","f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf"), 'blake2b_256 (digest_data_raw/2)');
is( digest_data_hex('BLAKE2b_256', "123"), "f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf", 'blake2b_256 (digest_data_hex/2)');
is( digest_data_b64('BLAKE2b_256', "123"), "9dZ7rnOw4Q0N/TBDs/TxAK2gFMXDe9XOl4E7E/WrK88=", 'blake2b_256 (digest_data_b64/2)');
is( digest_data_b64u('BLAKE2b_256', "123"), "9dZ7rnOw4Q0N_TBDs_TxAK2gFMXDe9XOl4E7E_WrK88", 'blake2b_256 (digest_data_b64u/2)');
is( Crypt::Digest::BLAKE2b_256->new->add("123")->hexdigest, "f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf", 'blake2b_256 (OO/2)');

is( blake2b_256("test\0test\0test\n"), pack("H*","22d4e56794002cce9ecc0b1c2a67d41a514024c76a626ba570a5ec0d6c572ee3"), 'blake2b_256 (raw/3)');
is( blake2b_256_hex("test\0test\0test\n"), "22d4e56794002cce9ecc0b1c2a67d41a514024c76a626ba570a5ec0d6c572ee3", 'blake2b_256 (hex/3)');
is( blake2b_256_b64("test\0test\0test\n"), "ItTlZ5QALM6ezAscKmfUGlFAJMdqYmulcKXsDWxXLuM=", 'blake2b_256 (base64/3)');
is( digest_data('BLAKE2b_256', "test\0test\0test\n"), pack("H*","22d4e56794002cce9ecc0b1c2a67d41a514024c76a626ba570a5ec0d6c572ee3"), 'blake2b_256 (digest_data_raw/3)');
is( digest_data_hex('BLAKE2b_256', "test\0test\0test\n"), "22d4e56794002cce9ecc0b1c2a67d41a514024c76a626ba570a5ec0d6c572ee3", 'blake2b_256 (digest_data_hex/3)');
is( digest_data_b64('BLAKE2b_256', "test\0test\0test\n"), "ItTlZ5QALM6ezAscKmfUGlFAJMdqYmulcKXsDWxXLuM=", 'blake2b_256 (digest_data_b64/3)');
is( digest_data_b64u('BLAKE2b_256', "test\0test\0test\n"), "ItTlZ5QALM6ezAscKmfUGlFAJMdqYmulcKXsDWxXLuM", 'blake2b_256 (digest_data_b64u/3)');
is( Crypt::Digest::BLAKE2b_256->new->add("test\0test\0test\n")->hexdigest, "22d4e56794002cce9ecc0b1c2a67d41a514024c76a626ba570a5ec0d6c572ee3", 'blake2b_256 (OO/3)');


is( blake2b_256_file('t/data/binary-test.file'), pack("H*","34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b"), 'blake2b_256 (raw/file/1)');
is( blake2b_256_file_hex('t/data/binary-test.file'), "34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b", 'blake2b_256 (hex/file/1)');
is( blake2b_256_file_b64('t/data/binary-test.file'), "NMsoezWbC+A3WrbP7vrJ+Hv1dwEXzKlQpfLWbkXbx3s=", 'blake2b_256 (base64/file/1)');
is( digest_file('BLAKE2b_256', 't/data/binary-test.file'), pack("H*","34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b"), 'blake2b_256 (digest_file_raw/file/1)');
is( digest_file_hex('BLAKE2b_256', 't/data/binary-test.file'), "34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b", 'blake2b_256 (digest_file_hex/file/1)');
is( digest_file_b64('BLAKE2b_256', 't/data/binary-test.file'), "NMsoezWbC+A3WrbP7vrJ+Hv1dwEXzKlQpfLWbkXbx3s=", 'blake2b_256 (digest_file_b64/file/1)');
is( digest_file_b64u('BLAKE2b_256', 't/data/binary-test.file'), "NMsoezWbC-A3WrbP7vrJ-Hv1dwEXzKlQpfLWbkXbx3s", 'blake2b_256 (digest_file_b64u/file/1)');
is( Crypt::Digest::BLAKE2b_256->new->addfile('t/data/binary-test.file')->hexdigest, "34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b", 'blake2b_256 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_256->new->addfile($fh)->hexdigest, "34cb287b359b0be0375ab6cfeefac9f87bf5770117cca950a5f2d66e45dbc77b", 'blake2b_256 (OO/filehandle/1)');
  close($fh);
}

is( blake2b_256_file('t/data/text-CR.file'), pack("H*","8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3"), 'blake2b_256 (raw/file/2)');
is( blake2b_256_file_hex('t/data/text-CR.file'), "8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3", 'blake2b_256 (hex/file/2)');
is( blake2b_256_file_b64('t/data/text-CR.file'), "jd5ODKdjNJnAkT19XG01JDB8TuOBkx9MwsPXAwq5erM=", 'blake2b_256 (base64/file/2)');
is( digest_file('BLAKE2b_256', 't/data/text-CR.file'), pack("H*","8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3"), 'blake2b_256 (digest_file_raw/file/2)');
is( digest_file_hex('BLAKE2b_256', 't/data/text-CR.file'), "8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3", 'blake2b_256 (digest_file_hex/file/2)');
is( digest_file_b64('BLAKE2b_256', 't/data/text-CR.file'), "jd5ODKdjNJnAkT19XG01JDB8TuOBkx9MwsPXAwq5erM=", 'blake2b_256 (digest_file_b64/file/2)');
is( digest_file_b64u('BLAKE2b_256', 't/data/text-CR.file'), "jd5ODKdjNJnAkT19XG01JDB8TuOBkx9MwsPXAwq5erM", 'blake2b_256 (digest_file_b64u/file/2)');
is( Crypt::Digest::BLAKE2b_256->new->addfile('t/data/text-CR.file')->hexdigest, "8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3", 'blake2b_256 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_256->new->addfile($fh)->hexdigest, "8dde4e0ca7633499c0913d7d5c6d3524307c4ee381931f4cc2c3d7030ab97ab3", 'blake2b_256 (OO/filehandle/2)');
  close($fh);
}

is( blake2b_256_file('t/data/text-CRLF.file'), pack("H*","3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22"), 'blake2b_256 (raw/file/3)');
is( blake2b_256_file_hex('t/data/text-CRLF.file'), "3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22", 'blake2b_256 (hex/file/3)');
is( blake2b_256_file_b64('t/data/text-CRLF.file'), "Pm3N25278eo51VyYDaAZccaxvSB24LvIyVykmDaSaiI=", 'blake2b_256 (base64/file/3)');
is( digest_file('BLAKE2b_256', 't/data/text-CRLF.file'), pack("H*","3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22"), 'blake2b_256 (digest_file_raw/file/3)');
is( digest_file_hex('BLAKE2b_256', 't/data/text-CRLF.file'), "3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22", 'blake2b_256 (digest_file_hex/file/3)');
is( digest_file_b64('BLAKE2b_256', 't/data/text-CRLF.file'), "Pm3N25278eo51VyYDaAZccaxvSB24LvIyVykmDaSaiI=", 'blake2b_256 (digest_file_b64/file/3)');
is( digest_file_b64u('BLAKE2b_256', 't/data/text-CRLF.file'), "Pm3N25278eo51VyYDaAZccaxvSB24LvIyVykmDaSaiI", 'blake2b_256 (digest_file_b64u/file/3)');
is( Crypt::Digest::BLAKE2b_256->new->addfile('t/data/text-CRLF.file')->hexdigest, "3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22", 'blake2b_256 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_256->new->addfile($fh)->hexdigest, "3e6dcddb9dbbf1ea39d55c980da01971c6b1bd2076e0bbc8c95ca49836926a22", 'blake2b_256 (OO/filehandle/3)');
  close($fh);
}

is( blake2b_256_file('t/data/text-LF.file'), pack("H*","2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e"), 'blake2b_256 (raw/file/4)');
is( blake2b_256_file_hex('t/data/text-LF.file'), "2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e", 'blake2b_256 (hex/file/4)');
is( blake2b_256_file_b64('t/data/text-LF.file'), "LxA4QDBGCaFryixzTjxgS3I/9RZFebaoCCX4ONfgxn4=", 'blake2b_256 (base64/file/4)');
is( digest_file('BLAKE2b_256', 't/data/text-LF.file'), pack("H*","2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e"), 'blake2b_256 (digest_file_raw/file/4)');
is( digest_file_hex('BLAKE2b_256', 't/data/text-LF.file'), "2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e", 'blake2b_256 (digest_file_hex/file/4)');
is( digest_file_b64('BLAKE2b_256', 't/data/text-LF.file'), "LxA4QDBGCaFryixzTjxgS3I/9RZFebaoCCX4ONfgxn4=", 'blake2b_256 (digest_file_b64/file/4)');
is( digest_file_b64u('BLAKE2b_256', 't/data/text-LF.file'), "LxA4QDBGCaFryixzTjxgS3I_9RZFebaoCCX4ONfgxn4", 'blake2b_256 (digest_file_b64u/file/4)');
is( Crypt::Digest::BLAKE2b_256->new->addfile('t/data/text-LF.file')->hexdigest, "2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e", 'blake2b_256 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::BLAKE2b_256->new->addfile($fh)->hexdigest, "2f103840304609a16bca2c734e3c604b723ff5164579b6a80825f838d7e0c67e", 'blake2b_256 (OO/filehandle/4)');
  close($fh);
}
