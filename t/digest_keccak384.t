### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::Keccak384 qw( keccak384 keccak384_hex keccak384_b64 keccak384_b64u keccak384_file keccak384_file_hex keccak384_file_b64 keccak384_file_b64u );

is( Crypt::Digest::hashsize('Keccak384'), 48, 'hashsize/1');
is( Crypt::Digest->hashsize('Keccak384'), 48, 'hashsize/2');
is( Crypt::Digest::Keccak384::hashsize, 48, 'hashsize/3');
is( Crypt::Digest::Keccak384->hashsize, 48, 'hashsize/4');
is( Crypt::Digest->new('Keccak384')->hashsize, 48, 'hashsize/5');
is( Crypt::Digest::Keccak384->new->hashsize, 48, 'hashsize/6');

is( keccak384("A","A","A"), pack("H*","173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297"), 'keccak384 (raw/tripple_A)');
is( keccak384_hex("A","A","A"), "173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297", 'keccak384 (hex/tripple_A)');
is( keccak384_b64("A","A","A"), "FztUXg/YF4T4wCTKgDZBk2CC7vmlrOc/r3OtaOzeYCnMNFpcVJOE4Ndifcv1jQKX", 'keccak384 (base64/tripple_A)');
is( keccak384_b64u("A","A","A"), "FztUXg_YF4T4wCTKgDZBk2CC7vmlrOc_r3OtaOzeYCnMNFpcVJOE4Ndifcv1jQKX", 'keccak384 (base64url/tripple_A)');
is( digest_data('Keccak384', "A","A","A"), pack("H*","173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297"), 'keccak384 (digest_data_raw/tripple_A)');
is( digest_data_hex('Keccak384', "A","A","A"), "173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297", 'keccak384 (digest_data_hex/tripple_A)');
is( digest_data_b64('Keccak384', "A","A","A"), "FztUXg/YF4T4wCTKgDZBk2CC7vmlrOc/r3OtaOzeYCnMNFpcVJOE4Ndifcv1jQKX", 'keccak384 (digest_data_b64/tripple_A)');
is( digest_data_b64u('Keccak384', "A","A","A"), "FztUXg_YF4T4wCTKgDZBk2CC7vmlrOc_r3OtaOzeYCnMNFpcVJOE4Ndifcv1jQKX", 'keccak384 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::Keccak384->new->add("A","A","A")->hexdigest, "173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297", 'keccak384 (OO/tripple_A)');
is( Crypt::Digest::Keccak384->new->add("A")->add("A")->add("A")->hexdigest, "173b545e0fd81784f8c024ca803641936082eef9a5ace73faf73ad68ecde6029cc345a5c549384e0d7627dcbf58d0297", 'keccak384 (OO3/tripple_A)');


is( keccak384(""), pack("H*","2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"), 'keccak384 (raw/1)');
is( keccak384_hex(""), "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff", 'keccak384 (hex/1)');
is( keccak384_b64(""), "LCMUamOims+Z5zuI+MJOqn3GCqdxeAzMAGr7+o/iR5st0rITYjN0QawStRWRGVf/", 'keccak384 (base64/1)');
is( digest_data('Keccak384', ""), pack("H*","2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"), 'keccak384 (digest_data_raw/1)');
is( digest_data_hex('Keccak384', ""), "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff", 'keccak384 (digest_data_hex/1)');
is( digest_data_b64('Keccak384', ""), "LCMUamOims+Z5zuI+MJOqn3GCqdxeAzMAGr7+o/iR5st0rITYjN0QawStRWRGVf/", 'keccak384 (digest_data_b64/1)');
is( digest_data_b64u('Keccak384', ""), "LCMUamOims-Z5zuI-MJOqn3GCqdxeAzMAGr7-o_iR5st0rITYjN0QawStRWRGVf_", 'keccak384 (digest_data_b64u/1)');
is( Crypt::Digest::Keccak384->new->add("")->hexdigest, "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff", 'keccak384 (OO/1)');

is( keccak384("123"), pack("H*","7dd34ccaae92bfc7eb541056d200db23b6bbeefe95be0d2bb43625113361906f0afc701dbef1cfb615bf98b1535a84c1"), 'keccak384 (raw/2)');
is( keccak384_hex("123"), "7dd34ccaae92bfc7eb541056d200db23b6bbeefe95be0d2bb43625113361906f0afc701dbef1cfb615bf98b1535a84c1", 'keccak384 (hex/2)');
is( keccak384_b64("123"), "fdNMyq6Sv8frVBBW0gDbI7a77v6Vvg0rtDYlETNhkG8K/HAdvvHPthW/mLFTWoTB", 'keccak384 (base64/2)');
is( digest_data('Keccak384', "123"), pack("H*","7dd34ccaae92bfc7eb541056d200db23b6bbeefe95be0d2bb43625113361906f0afc701dbef1cfb615bf98b1535a84c1"), 'keccak384 (digest_data_raw/2)');
is( digest_data_hex('Keccak384', "123"), "7dd34ccaae92bfc7eb541056d200db23b6bbeefe95be0d2bb43625113361906f0afc701dbef1cfb615bf98b1535a84c1", 'keccak384 (digest_data_hex/2)');
is( digest_data_b64('Keccak384', "123"), "fdNMyq6Sv8frVBBW0gDbI7a77v6Vvg0rtDYlETNhkG8K/HAdvvHPthW/mLFTWoTB", 'keccak384 (digest_data_b64/2)');
is( digest_data_b64u('Keccak384', "123"), "fdNMyq6Sv8frVBBW0gDbI7a77v6Vvg0rtDYlETNhkG8K_HAdvvHPthW_mLFTWoTB", 'keccak384 (digest_data_b64u/2)');
is( Crypt::Digest::Keccak384->new->add("123")->hexdigest, "7dd34ccaae92bfc7eb541056d200db23b6bbeefe95be0d2bb43625113361906f0afc701dbef1cfb615bf98b1535a84c1", 'keccak384 (OO/2)');

is( keccak384("test\0test\0test\n"), pack("H*","d05c31062f5401c5d370cf84949937c52764626a61d2bbd5bf5c50f6f742ebcf9269691a3c70ef83dc49f4e186e5d908"), 'keccak384 (raw/3)');
is( keccak384_hex("test\0test\0test\n"), "d05c31062f5401c5d370cf84949937c52764626a61d2bbd5bf5c50f6f742ebcf9269691a3c70ef83dc49f4e186e5d908", 'keccak384 (hex/3)');
is( keccak384_b64("test\0test\0test\n"), "0FwxBi9UAcXTcM+ElJk3xSdkYmph0rvVv1xQ9vdC68+SaWkaPHDvg9xJ9OGG5dkI", 'keccak384 (base64/3)');
is( digest_data('Keccak384', "test\0test\0test\n"), pack("H*","d05c31062f5401c5d370cf84949937c52764626a61d2bbd5bf5c50f6f742ebcf9269691a3c70ef83dc49f4e186e5d908"), 'keccak384 (digest_data_raw/3)');
is( digest_data_hex('Keccak384', "test\0test\0test\n"), "d05c31062f5401c5d370cf84949937c52764626a61d2bbd5bf5c50f6f742ebcf9269691a3c70ef83dc49f4e186e5d908", 'keccak384 (digest_data_hex/3)');
is( digest_data_b64('Keccak384', "test\0test\0test\n"), "0FwxBi9UAcXTcM+ElJk3xSdkYmph0rvVv1xQ9vdC68+SaWkaPHDvg9xJ9OGG5dkI", 'keccak384 (digest_data_b64/3)');
is( digest_data_b64u('Keccak384', "test\0test\0test\n"), "0FwxBi9UAcXTcM-ElJk3xSdkYmph0rvVv1xQ9vdC68-SaWkaPHDvg9xJ9OGG5dkI", 'keccak384 (digest_data_b64u/3)');
is( Crypt::Digest::Keccak384->new->add("test\0test\0test\n")->hexdigest, "d05c31062f5401c5d370cf84949937c52764626a61d2bbd5bf5c50f6f742ebcf9269691a3c70ef83dc49f4e186e5d908", 'keccak384 (OO/3)');


is( keccak384_file('t/data/binary-test.file'), pack("H*","16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc"), 'keccak384 (raw/file/1)');
is( keccak384_file_hex('t/data/binary-test.file'), "16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc", 'keccak384 (hex/file/1)');
is( keccak384_file_b64('t/data/binary-test.file'), "FqWn2C3h7sHLu1HEA90PwCVg3fSIwbjGm5tM8VhedRQk38wGzwuvL/c9kxxvckC8", 'keccak384 (base64/file/1)');
is( digest_file('Keccak384', 't/data/binary-test.file'), pack("H*","16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc"), 'keccak384 (digest_file_raw/file/1)');
is( digest_file_hex('Keccak384', 't/data/binary-test.file'), "16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc", 'keccak384 (digest_file_hex/file/1)');
is( digest_file_b64('Keccak384', 't/data/binary-test.file'), "FqWn2C3h7sHLu1HEA90PwCVg3fSIwbjGm5tM8VhedRQk38wGzwuvL/c9kxxvckC8", 'keccak384 (digest_file_b64/file/1)');
is( digest_file_b64u('Keccak384', 't/data/binary-test.file'), "FqWn2C3h7sHLu1HEA90PwCVg3fSIwbjGm5tM8VhedRQk38wGzwuvL_c9kxxvckC8", 'keccak384 (digest_file_b64u/file/1)');
is( Crypt::Digest::Keccak384->new->addfile('t/data/binary-test.file')->hexdigest, "16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc", 'keccak384 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Keccak384->new->addfile($fh)->hexdigest, "16a5a7d82de1eec1cbbb51c403dd0fc02560ddf488c1b8c69b9b4cf1585e751424dfcc06cf0baf2ff73d931c6f7240bc", 'keccak384 (OO/filehandle/1)');
  close($fh);
}

is( keccak384_file('t/data/text-CR.file'), pack("H*","d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc"), 'keccak384 (raw/file/2)');
is( keccak384_file_hex('t/data/text-CR.file'), "d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc", 'keccak384 (hex/file/2)');
is( keccak384_file_b64('t/data/text-CR.file'), "1CoL+yqVu/66N1sUbr4375ly0lgJuToY/RdU+4atkTmsLKceXNFxMCTs2gYmOjnM", 'keccak384 (base64/file/2)');
is( digest_file('Keccak384', 't/data/text-CR.file'), pack("H*","d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc"), 'keccak384 (digest_file_raw/file/2)');
is( digest_file_hex('Keccak384', 't/data/text-CR.file'), "d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc", 'keccak384 (digest_file_hex/file/2)');
is( digest_file_b64('Keccak384', 't/data/text-CR.file'), "1CoL+yqVu/66N1sUbr4375ly0lgJuToY/RdU+4atkTmsLKceXNFxMCTs2gYmOjnM", 'keccak384 (digest_file_b64/file/2)');
is( digest_file_b64u('Keccak384', 't/data/text-CR.file'), "1CoL-yqVu_66N1sUbr4375ly0lgJuToY_RdU-4atkTmsLKceXNFxMCTs2gYmOjnM", 'keccak384 (digest_file_b64u/file/2)');
is( Crypt::Digest::Keccak384->new->addfile('t/data/text-CR.file')->hexdigest, "d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc", 'keccak384 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Keccak384->new->addfile($fh)->hexdigest, "d42a0bfb2a95bbfeba375b146ebe37ef9972d25809b93a18fd1754fb86ad9139ac2ca71e5cd1713024ecda06263a39cc", 'keccak384 (OO/filehandle/2)');
  close($fh);
}

is( keccak384_file('t/data/text-CRLF.file'), pack("H*","06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982"), 'keccak384 (raw/file/3)');
is( keccak384_file_hex('t/data/text-CRLF.file'), "06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982", 'keccak384 (hex/file/3)');
is( keccak384_file_b64('t/data/text-CRLF.file'), "BiiLNQblCArrvN+qulmFrInj5CJ/0yuKUyZABkyYv+qZGl6IzACzB/0N0tHIejmC", 'keccak384 (base64/file/3)');
is( digest_file('Keccak384', 't/data/text-CRLF.file'), pack("H*","06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982"), 'keccak384 (digest_file_raw/file/3)');
is( digest_file_hex('Keccak384', 't/data/text-CRLF.file'), "06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982", 'keccak384 (digest_file_hex/file/3)');
is( digest_file_b64('Keccak384', 't/data/text-CRLF.file'), "BiiLNQblCArrvN+qulmFrInj5CJ/0yuKUyZABkyYv+qZGl6IzACzB/0N0tHIejmC", 'keccak384 (digest_file_b64/file/3)');
is( digest_file_b64u('Keccak384', 't/data/text-CRLF.file'), "BiiLNQblCArrvN-qulmFrInj5CJ_0yuKUyZABkyYv-qZGl6IzACzB_0N0tHIejmC", 'keccak384 (digest_file_b64u/file/3)');
is( Crypt::Digest::Keccak384->new->addfile('t/data/text-CRLF.file')->hexdigest, "06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982", 'keccak384 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak384->new->addfile($fh)->hexdigest, "06288b3506e5080aebbcdfaaba5985ac89e3e4227fd32b8a532640064c98bfea991a5e88cc00b307fd0dd2d1c87a3982", 'keccak384 (OO/filehandle/3)');
  close($fh);
}

is( keccak384_file('t/data/text-LF.file'), pack("H*","14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71"), 'keccak384 (raw/file/4)');
is( keccak384_file_hex('t/data/text-LF.file'), "14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71", 'keccak384 (hex/file/4)');
is( keccak384_file_b64('t/data/text-LF.file'), "FLVNEYgVT3AX/3sz4h5C75PJHXnqa0SiIwAq3G2JuHXTvLJcGJrqgnVgVAr75c9x", 'keccak384 (base64/file/4)');
is( digest_file('Keccak384', 't/data/text-LF.file'), pack("H*","14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71"), 'keccak384 (digest_file_raw/file/4)');
is( digest_file_hex('Keccak384', 't/data/text-LF.file'), "14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71", 'keccak384 (digest_file_hex/file/4)');
is( digest_file_b64('Keccak384', 't/data/text-LF.file'), "FLVNEYgVT3AX/3sz4h5C75PJHXnqa0SiIwAq3G2JuHXTvLJcGJrqgnVgVAr75c9x", 'keccak384 (digest_file_b64/file/4)');
is( digest_file_b64u('Keccak384', 't/data/text-LF.file'), "FLVNEYgVT3AX_3sz4h5C75PJHXnqa0SiIwAq3G2JuHXTvLJcGJrqgnVgVAr75c9x", 'keccak384 (digest_file_b64u/file/4)');
is( Crypt::Digest::Keccak384->new->addfile('t/data/text-LF.file')->hexdigest, "14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71", 'keccak384 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak384->new->addfile($fh)->hexdigest, "14b54d1188154f7017ff7b33e21e42ef93c91d79ea6b44a223002adc6d89b875d3bcb25c189aea827560540afbe5cf71", 'keccak384 (OO/filehandle/4)');
  close($fh);
}
