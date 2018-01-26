### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::RIPEMD320 qw( ripemd320 ripemd320_hex ripemd320_b64 ripemd320_b64u ripemd320_file ripemd320_file_hex ripemd320_file_b64 ripemd320_file_b64u );

is( Crypt::Digest::hashsize('RIPEMD320'), 40, 'hashsize/1');
is( Crypt::Digest->hashsize('RIPEMD320'), 40, 'hashsize/2');
is( Crypt::Digest::RIPEMD320::hashsize, 40, 'hashsize/3');
is( Crypt::Digest::RIPEMD320->hashsize, 40, 'hashsize/4');
is( Crypt::Digest->new('RIPEMD320')->hashsize, 40, 'hashsize/5');
is( Crypt::Digest::RIPEMD320->new->hashsize, 40, 'hashsize/6');

is( ripemd320("A","A","A"), pack("H*","4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60"), 'ripemd320 (raw/tripple_A)');
is( ripemd320_hex("A","A","A"), "4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60", 'ripemd320 (hex/tripple_A)');
is( ripemd320_b64("A","A","A"), "TPNLKIfx3RVD+wzpUL8VX7fJPGPWGtxn6FjBCD/VTkp+HasbmzO6YA==", 'ripemd320 (base64/tripple_A)');
is( ripemd320_b64u("A","A","A"), "TPNLKIfx3RVD-wzpUL8VX7fJPGPWGtxn6FjBCD_VTkp-HasbmzO6YA", 'ripemd320 (base64url/tripple_A)');
is( digest_data('RIPEMD320', "A","A","A"), pack("H*","4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60"), 'ripemd320 (digest_data_raw/tripple_A)');
is( digest_data_hex('RIPEMD320', "A","A","A"), "4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60", 'ripemd320 (digest_data_hex/tripple_A)');
is( digest_data_b64('RIPEMD320', "A","A","A"), "TPNLKIfx3RVD+wzpUL8VX7fJPGPWGtxn6FjBCD/VTkp+HasbmzO6YA==", 'ripemd320 (digest_data_b64/tripple_A)');
is( digest_data_b64u('RIPEMD320', "A","A","A"), "TPNLKIfx3RVD-wzpUL8VX7fJPGPWGtxn6FjBCD_VTkp-HasbmzO6YA", 'ripemd320 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::RIPEMD320->new->add("A","A","A")->hexdigest, "4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60", 'ripemd320 (OO/tripple_A)');
is( Crypt::Digest::RIPEMD320->new->add("A")->add("A")->add("A")->hexdigest, "4cf34b2887f1dd1543fb0ce950bf155fb7c93c63d61adc67e858c1083fd54e4a7e1dab1b9b33ba60", 'ripemd320 (OO3/tripple_A)');


is( ripemd320(""), pack("H*","22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"), 'ripemd320 (raw/1)');
is( ripemd320_hex(""), "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", 'ripemd320 (hex/1)');
is( ripemd320_b64(""), "ItZdVmFTbNx1wf31xt57QbnycyXrxh6FVxd9cFoOyIAVHDoyoAiZuA==", 'ripemd320 (base64/1)');
is( digest_data('RIPEMD320', ""), pack("H*","22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"), 'ripemd320 (digest_data_raw/1)');
is( digest_data_hex('RIPEMD320', ""), "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", 'ripemd320 (digest_data_hex/1)');
is( digest_data_b64('RIPEMD320', ""), "ItZdVmFTbNx1wf31xt57QbnycyXrxh6FVxd9cFoOyIAVHDoyoAiZuA==", 'ripemd320 (digest_data_b64/1)');
is( digest_data_b64u('RIPEMD320', ""), "ItZdVmFTbNx1wf31xt57QbnycyXrxh6FVxd9cFoOyIAVHDoyoAiZuA", 'ripemd320 (digest_data_b64u/1)');
is( Crypt::Digest::RIPEMD320->new->add("")->hexdigest, "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", 'ripemd320 (OO/1)');

is( ripemd320("123"), pack("H*","bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9"), 'ripemd320 (raw/2)');
is( ripemd320_hex("123"), "bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9", 'ripemd320 (hex/2)');
is( ripemd320_b64("123"), "v6Ebc61OZCGouloSI9nJ9Ypa1Fa+mL7lv80Zo+zcYUDOTHAL6GD9qQ==", 'ripemd320 (base64/2)');
is( digest_data('RIPEMD320', "123"), pack("H*","bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9"), 'ripemd320 (digest_data_raw/2)');
is( digest_data_hex('RIPEMD320', "123"), "bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9", 'ripemd320 (digest_data_hex/2)');
is( digest_data_b64('RIPEMD320', "123"), "v6Ebc61OZCGouloSI9nJ9Ypa1Fa+mL7lv80Zo+zcYUDOTHAL6GD9qQ==", 'ripemd320 (digest_data_b64/2)');
is( digest_data_b64u('RIPEMD320', "123"), "v6Ebc61OZCGouloSI9nJ9Ypa1Fa-mL7lv80Zo-zcYUDOTHAL6GD9qQ", 'ripemd320 (digest_data_b64u/2)');
is( Crypt::Digest::RIPEMD320->new->add("123")->hexdigest, "bfa11b73ad4e6421a8ba5a1223d9c9f58a5ad456be98bee5bfcd19a3ecdc6140ce4c700be860fda9", 'ripemd320 (OO/2)');

is( ripemd320("test\0test\0test\n"), pack("H*","efdfb0c3c74bdf938a4845638eb3622e2bdba11a68a4831b8517cb6b827e46a6026419b27003a044"), 'ripemd320 (raw/3)');
is( ripemd320_hex("test\0test\0test\n"), "efdfb0c3c74bdf938a4845638eb3622e2bdba11a68a4831b8517cb6b827e46a6026419b27003a044", 'ripemd320 (hex/3)');
is( ripemd320_b64("test\0test\0test\n"), "79+ww8dL35OKSEVjjrNiLivboRpopIMbhRfLa4J+RqYCZBmycAOgRA==", 'ripemd320 (base64/3)');
is( digest_data('RIPEMD320', "test\0test\0test\n"), pack("H*","efdfb0c3c74bdf938a4845638eb3622e2bdba11a68a4831b8517cb6b827e46a6026419b27003a044"), 'ripemd320 (digest_data_raw/3)');
is( digest_data_hex('RIPEMD320', "test\0test\0test\n"), "efdfb0c3c74bdf938a4845638eb3622e2bdba11a68a4831b8517cb6b827e46a6026419b27003a044", 'ripemd320 (digest_data_hex/3)');
is( digest_data_b64('RIPEMD320', "test\0test\0test\n"), "79+ww8dL35OKSEVjjrNiLivboRpopIMbhRfLa4J+RqYCZBmycAOgRA==", 'ripemd320 (digest_data_b64/3)');
is( digest_data_b64u('RIPEMD320', "test\0test\0test\n"), "79-ww8dL35OKSEVjjrNiLivboRpopIMbhRfLa4J-RqYCZBmycAOgRA", 'ripemd320 (digest_data_b64u/3)');
is( Crypt::Digest::RIPEMD320->new->add("test\0test\0test\n")->hexdigest, "efdfb0c3c74bdf938a4845638eb3622e2bdba11a68a4831b8517cb6b827e46a6026419b27003a044", 'ripemd320 (OO/3)');


is( ripemd320_file('t/data/binary-test.file'), pack("H*","115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198"), 'ripemd320 (raw/file/1)');
is( ripemd320_file_hex('t/data/binary-test.file'), "115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198", 'ripemd320 (hex/file/1)');
is( ripemd320_file_b64('t/data/binary-test.file'), "EVtO4pp6eBMj813h2WkNHDQPFiRjcm4bMgbBOccA1lyS3CBJcCahmA==", 'ripemd320 (base64/file/1)');
is( digest_file('RIPEMD320', 't/data/binary-test.file'), pack("H*","115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198"), 'ripemd320 (digest_file_raw/file/1)');
is( digest_file_hex('RIPEMD320', 't/data/binary-test.file'), "115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198", 'ripemd320 (digest_file_hex/file/1)');
is( digest_file_b64('RIPEMD320', 't/data/binary-test.file'), "EVtO4pp6eBMj813h2WkNHDQPFiRjcm4bMgbBOccA1lyS3CBJcCahmA==", 'ripemd320 (digest_file_b64/file/1)');
is( digest_file_b64u('RIPEMD320', 't/data/binary-test.file'), "EVtO4pp6eBMj813h2WkNHDQPFiRjcm4bMgbBOccA1lyS3CBJcCahmA", 'ripemd320 (digest_file_b64u/file/1)');
is( Crypt::Digest::RIPEMD320->new->addfile('t/data/binary-test.file')->hexdigest, "115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198", 'ripemd320 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD320->new->addfile($fh)->hexdigest, "115b4ee29a7a781323f35de1d9690d1c340f162463726e1b3206c139c700d65c92dc20497026a198", 'ripemd320 (OO/filehandle/1)');
  close($fh);
}

is( ripemd320_file('t/data/text-CR.file'), pack("H*","47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645"), 'ripemd320 (raw/file/2)');
is( ripemd320_file_hex('t/data/text-CR.file'), "47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645", 'ripemd320 (hex/file/2)');
is( ripemd320_file_b64('t/data/text-CR.file'), "R6/qrXyWXi1LLlefM7B509mvw8yRCxVAAv33tE8Gym68dGremSsmRQ==", 'ripemd320 (base64/file/2)');
is( digest_file('RIPEMD320', 't/data/text-CR.file'), pack("H*","47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645"), 'ripemd320 (digest_file_raw/file/2)');
is( digest_file_hex('RIPEMD320', 't/data/text-CR.file'), "47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645", 'ripemd320 (digest_file_hex/file/2)');
is( digest_file_b64('RIPEMD320', 't/data/text-CR.file'), "R6/qrXyWXi1LLlefM7B509mvw8yRCxVAAv33tE8Gym68dGremSsmRQ==", 'ripemd320 (digest_file_b64/file/2)');
is( digest_file_b64u('RIPEMD320', 't/data/text-CR.file'), "R6_qrXyWXi1LLlefM7B509mvw8yRCxVAAv33tE8Gym68dGremSsmRQ", 'ripemd320 (digest_file_b64u/file/2)');
is( Crypt::Digest::RIPEMD320->new->addfile('t/data/text-CR.file')->hexdigest, "47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645", 'ripemd320 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD320->new->addfile($fh)->hexdigest, "47afeaad7c965e2d4b2e579f33b079d3d9afc3cc910b154002fdf7b44f06ca6ebc746ade992b2645", 'ripemd320 (OO/filehandle/2)');
  close($fh);
}

is( ripemd320_file('t/data/text-CRLF.file'), pack("H*","d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26"), 'ripemd320 (raw/file/3)');
is( ripemd320_file_hex('t/data/text-CRLF.file'), "d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26", 'ripemd320 (hex/file/3)');
is( ripemd320_file_b64('t/data/text-CRLF.file'), "1ADS6iZ+o53TKzbbGYq6JGwg4gqlwxTVbWDvxYKhBISSVJf/Qo5rJg==", 'ripemd320 (base64/file/3)');
is( digest_file('RIPEMD320', 't/data/text-CRLF.file'), pack("H*","d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26"), 'ripemd320 (digest_file_raw/file/3)');
is( digest_file_hex('RIPEMD320', 't/data/text-CRLF.file'), "d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26", 'ripemd320 (digest_file_hex/file/3)');
is( digest_file_b64('RIPEMD320', 't/data/text-CRLF.file'), "1ADS6iZ+o53TKzbbGYq6JGwg4gqlwxTVbWDvxYKhBISSVJf/Qo5rJg==", 'ripemd320 (digest_file_b64/file/3)');
is( digest_file_b64u('RIPEMD320', 't/data/text-CRLF.file'), "1ADS6iZ-o53TKzbbGYq6JGwg4gqlwxTVbWDvxYKhBISSVJf_Qo5rJg", 'ripemd320 (digest_file_b64u/file/3)');
is( Crypt::Digest::RIPEMD320->new->addfile('t/data/text-CRLF.file')->hexdigest, "d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26", 'ripemd320 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD320->new->addfile($fh)->hexdigest, "d400d2ea267ea39dd32b36db198aba246c20e20aa5c314d56d60efc582a10484925497ff428e6b26", 'ripemd320 (OO/filehandle/3)');
  close($fh);
}

is( ripemd320_file('t/data/text-LF.file'), pack("H*","ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055"), 'ripemd320 (raw/file/4)');
is( ripemd320_file_hex('t/data/text-LF.file'), "ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055", 'ripemd320 (hex/file/4)');
is( ripemd320_file_b64('t/data/text-LF.file'), "71VpDS3dBKZ3Y7hxpszmIOsoRFg6RDMTeVnPS418usuV2CD3TnSAVQ==", 'ripemd320 (base64/file/4)');
is( digest_file('RIPEMD320', 't/data/text-LF.file'), pack("H*","ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055"), 'ripemd320 (digest_file_raw/file/4)');
is( digest_file_hex('RIPEMD320', 't/data/text-LF.file'), "ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055", 'ripemd320 (digest_file_hex/file/4)');
is( digest_file_b64('RIPEMD320', 't/data/text-LF.file'), "71VpDS3dBKZ3Y7hxpszmIOsoRFg6RDMTeVnPS418usuV2CD3TnSAVQ==", 'ripemd320 (digest_file_b64/file/4)');
is( digest_file_b64u('RIPEMD320', 't/data/text-LF.file'), "71VpDS3dBKZ3Y7hxpszmIOsoRFg6RDMTeVnPS418usuV2CD3TnSAVQ", 'ripemd320 (digest_file_b64u/file/4)');
is( Crypt::Digest::RIPEMD320->new->addfile('t/data/text-LF.file')->hexdigest, "ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055", 'ripemd320 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD320->new->addfile($fh)->hexdigest, "ef55690d2ddd04a67763b871a6cce620eb2844583a4433137959cf4b8d7cbacb95d820f74e748055", 'ripemd320 (OO/filehandle/4)');
  close($fh);
}
