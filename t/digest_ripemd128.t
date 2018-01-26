### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::RIPEMD128 qw( ripemd128 ripemd128_hex ripemd128_b64 ripemd128_b64u ripemd128_file ripemd128_file_hex ripemd128_file_b64 ripemd128_file_b64u );

is( Crypt::Digest::hashsize('RIPEMD128'), 16, 'hashsize/1');
is( Crypt::Digest->hashsize('RIPEMD128'), 16, 'hashsize/2');
is( Crypt::Digest::RIPEMD128::hashsize, 16, 'hashsize/3');
is( Crypt::Digest::RIPEMD128->hashsize, 16, 'hashsize/4');
is( Crypt::Digest->new('RIPEMD128')->hashsize, 16, 'hashsize/5');
is( Crypt::Digest::RIPEMD128->new->hashsize, 16, 'hashsize/6');

is( ripemd128("A","A","A"), pack("H*","c2750c6ca0c35d367de2993c3f55e1df"), 'ripemd128 (raw/tripple_A)');
is( ripemd128_hex("A","A","A"), "c2750c6ca0c35d367de2993c3f55e1df", 'ripemd128 (hex/tripple_A)');
is( ripemd128_b64("A","A","A"), "wnUMbKDDXTZ94pk8P1Xh3w==", 'ripemd128 (base64/tripple_A)');
is( ripemd128_b64u("A","A","A"), "wnUMbKDDXTZ94pk8P1Xh3w", 'ripemd128 (base64url/tripple_A)');
is( digest_data('RIPEMD128', "A","A","A"), pack("H*","c2750c6ca0c35d367de2993c3f55e1df"), 'ripemd128 (digest_data_raw/tripple_A)');
is( digest_data_hex('RIPEMD128', "A","A","A"), "c2750c6ca0c35d367de2993c3f55e1df", 'ripemd128 (digest_data_hex/tripple_A)');
is( digest_data_b64('RIPEMD128', "A","A","A"), "wnUMbKDDXTZ94pk8P1Xh3w==", 'ripemd128 (digest_data_b64/tripple_A)');
is( digest_data_b64u('RIPEMD128', "A","A","A"), "wnUMbKDDXTZ94pk8P1Xh3w", 'ripemd128 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::RIPEMD128->new->add("A","A","A")->hexdigest, "c2750c6ca0c35d367de2993c3f55e1df", 'ripemd128 (OO/tripple_A)');
is( Crypt::Digest::RIPEMD128->new->add("A")->add("A")->add("A")->hexdigest, "c2750c6ca0c35d367de2993c3f55e1df", 'ripemd128 (OO3/tripple_A)');


is( ripemd128(""), pack("H*","cdf26213a150dc3ecb610f18f6b38b46"), 'ripemd128 (raw/1)');
is( ripemd128_hex(""), "cdf26213a150dc3ecb610f18f6b38b46", 'ripemd128 (hex/1)');
is( ripemd128_b64(""), "zfJiE6FQ3D7LYQ8Y9rOLRg==", 'ripemd128 (base64/1)');
is( digest_data('RIPEMD128', ""), pack("H*","cdf26213a150dc3ecb610f18f6b38b46"), 'ripemd128 (digest_data_raw/1)');
is( digest_data_hex('RIPEMD128', ""), "cdf26213a150dc3ecb610f18f6b38b46", 'ripemd128 (digest_data_hex/1)');
is( digest_data_b64('RIPEMD128', ""), "zfJiE6FQ3D7LYQ8Y9rOLRg==", 'ripemd128 (digest_data_b64/1)');
is( digest_data_b64u('RIPEMD128', ""), "zfJiE6FQ3D7LYQ8Y9rOLRg", 'ripemd128 (digest_data_b64u/1)');
is( Crypt::Digest::RIPEMD128->new->add("")->hexdigest, "cdf26213a150dc3ecb610f18f6b38b46", 'ripemd128 (OO/1)');

is( ripemd128("123"), pack("H*","781f357c35df1fef3138f6d29670365a"), 'ripemd128 (raw/2)');
is( ripemd128_hex("123"), "781f357c35df1fef3138f6d29670365a", 'ripemd128 (hex/2)');
is( ripemd128_b64("123"), "eB81fDXfH+8xOPbSlnA2Wg==", 'ripemd128 (base64/2)');
is( digest_data('RIPEMD128', "123"), pack("H*","781f357c35df1fef3138f6d29670365a"), 'ripemd128 (digest_data_raw/2)');
is( digest_data_hex('RIPEMD128', "123"), "781f357c35df1fef3138f6d29670365a", 'ripemd128 (digest_data_hex/2)');
is( digest_data_b64('RIPEMD128', "123"), "eB81fDXfH+8xOPbSlnA2Wg==", 'ripemd128 (digest_data_b64/2)');
is( digest_data_b64u('RIPEMD128', "123"), "eB81fDXfH-8xOPbSlnA2Wg", 'ripemd128 (digest_data_b64u/2)');
is( Crypt::Digest::RIPEMD128->new->add("123")->hexdigest, "781f357c35df1fef3138f6d29670365a", 'ripemd128 (OO/2)');

is( ripemd128("test\0test\0test\n"), pack("H*","4910f92c00d56cedde3b8174c456ccbb"), 'ripemd128 (raw/3)');
is( ripemd128_hex("test\0test\0test\n"), "4910f92c00d56cedde3b8174c456ccbb", 'ripemd128 (hex/3)');
is( ripemd128_b64("test\0test\0test\n"), "SRD5LADVbO3eO4F0xFbMuw==", 'ripemd128 (base64/3)');
is( digest_data('RIPEMD128', "test\0test\0test\n"), pack("H*","4910f92c00d56cedde3b8174c456ccbb"), 'ripemd128 (digest_data_raw/3)');
is( digest_data_hex('RIPEMD128', "test\0test\0test\n"), "4910f92c00d56cedde3b8174c456ccbb", 'ripemd128 (digest_data_hex/3)');
is( digest_data_b64('RIPEMD128', "test\0test\0test\n"), "SRD5LADVbO3eO4F0xFbMuw==", 'ripemd128 (digest_data_b64/3)');
is( digest_data_b64u('RIPEMD128', "test\0test\0test\n"), "SRD5LADVbO3eO4F0xFbMuw", 'ripemd128 (digest_data_b64u/3)');
is( Crypt::Digest::RIPEMD128->new->add("test\0test\0test\n")->hexdigest, "4910f92c00d56cedde3b8174c456ccbb", 'ripemd128 (OO/3)');


is( ripemd128_file('t/data/binary-test.file'), pack("H*","55f625a0de3efa776e784340384bf671"), 'ripemd128 (raw/file/1)');
is( ripemd128_file_hex('t/data/binary-test.file'), "55f625a0de3efa776e784340384bf671", 'ripemd128 (hex/file/1)');
is( ripemd128_file_b64('t/data/binary-test.file'), "VfYloN4++ndueENAOEv2cQ==", 'ripemd128 (base64/file/1)');
is( digest_file('RIPEMD128', 't/data/binary-test.file'), pack("H*","55f625a0de3efa776e784340384bf671"), 'ripemd128 (digest_file_raw/file/1)');
is( digest_file_hex('RIPEMD128', 't/data/binary-test.file'), "55f625a0de3efa776e784340384bf671", 'ripemd128 (digest_file_hex/file/1)');
is( digest_file_b64('RIPEMD128', 't/data/binary-test.file'), "VfYloN4++ndueENAOEv2cQ==", 'ripemd128 (digest_file_b64/file/1)');
is( digest_file_b64u('RIPEMD128', 't/data/binary-test.file'), "VfYloN4--ndueENAOEv2cQ", 'ripemd128 (digest_file_b64u/file/1)');
is( Crypt::Digest::RIPEMD128->new->addfile('t/data/binary-test.file')->hexdigest, "55f625a0de3efa776e784340384bf671", 'ripemd128 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD128->new->addfile($fh)->hexdigest, "55f625a0de3efa776e784340384bf671", 'ripemd128 (OO/filehandle/1)');
  close($fh);
}

is( ripemd128_file('t/data/text-CR.file'), pack("H*","4c095a056f2fe18e00719a0209381054"), 'ripemd128 (raw/file/2)');
is( ripemd128_file_hex('t/data/text-CR.file'), "4c095a056f2fe18e00719a0209381054", 'ripemd128 (hex/file/2)');
is( ripemd128_file_b64('t/data/text-CR.file'), "TAlaBW8v4Y4AcZoCCTgQVA==", 'ripemd128 (base64/file/2)');
is( digest_file('RIPEMD128', 't/data/text-CR.file'), pack("H*","4c095a056f2fe18e00719a0209381054"), 'ripemd128 (digest_file_raw/file/2)');
is( digest_file_hex('RIPEMD128', 't/data/text-CR.file'), "4c095a056f2fe18e00719a0209381054", 'ripemd128 (digest_file_hex/file/2)');
is( digest_file_b64('RIPEMD128', 't/data/text-CR.file'), "TAlaBW8v4Y4AcZoCCTgQVA==", 'ripemd128 (digest_file_b64/file/2)');
is( digest_file_b64u('RIPEMD128', 't/data/text-CR.file'), "TAlaBW8v4Y4AcZoCCTgQVA", 'ripemd128 (digest_file_b64u/file/2)');
is( Crypt::Digest::RIPEMD128->new->addfile('t/data/text-CR.file')->hexdigest, "4c095a056f2fe18e00719a0209381054", 'ripemd128 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD128->new->addfile($fh)->hexdigest, "4c095a056f2fe18e00719a0209381054", 'ripemd128 (OO/filehandle/2)');
  close($fh);
}

is( ripemd128_file('t/data/text-CRLF.file'), pack("H*","eb35f79787dcd87b1fe02760922b0561"), 'ripemd128 (raw/file/3)');
is( ripemd128_file_hex('t/data/text-CRLF.file'), "eb35f79787dcd87b1fe02760922b0561", 'ripemd128 (hex/file/3)');
is( ripemd128_file_b64('t/data/text-CRLF.file'), "6zX3l4fc2Hsf4CdgkisFYQ==", 'ripemd128 (base64/file/3)');
is( digest_file('RIPEMD128', 't/data/text-CRLF.file'), pack("H*","eb35f79787dcd87b1fe02760922b0561"), 'ripemd128 (digest_file_raw/file/3)');
is( digest_file_hex('RIPEMD128', 't/data/text-CRLF.file'), "eb35f79787dcd87b1fe02760922b0561", 'ripemd128 (digest_file_hex/file/3)');
is( digest_file_b64('RIPEMD128', 't/data/text-CRLF.file'), "6zX3l4fc2Hsf4CdgkisFYQ==", 'ripemd128 (digest_file_b64/file/3)');
is( digest_file_b64u('RIPEMD128', 't/data/text-CRLF.file'), "6zX3l4fc2Hsf4CdgkisFYQ", 'ripemd128 (digest_file_b64u/file/3)');
is( Crypt::Digest::RIPEMD128->new->addfile('t/data/text-CRLF.file')->hexdigest, "eb35f79787dcd87b1fe02760922b0561", 'ripemd128 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD128->new->addfile($fh)->hexdigest, "eb35f79787dcd87b1fe02760922b0561", 'ripemd128 (OO/filehandle/3)');
  close($fh);
}

is( ripemd128_file('t/data/text-LF.file'), pack("H*","05863440dba144d5d0fdce73cbc27535"), 'ripemd128 (raw/file/4)');
is( ripemd128_file_hex('t/data/text-LF.file'), "05863440dba144d5d0fdce73cbc27535", 'ripemd128 (hex/file/4)');
is( ripemd128_file_b64('t/data/text-LF.file'), "BYY0QNuhRNXQ/c5zy8J1NQ==", 'ripemd128 (base64/file/4)');
is( digest_file('RIPEMD128', 't/data/text-LF.file'), pack("H*","05863440dba144d5d0fdce73cbc27535"), 'ripemd128 (digest_file_raw/file/4)');
is( digest_file_hex('RIPEMD128', 't/data/text-LF.file'), "05863440dba144d5d0fdce73cbc27535", 'ripemd128 (digest_file_hex/file/4)');
is( digest_file_b64('RIPEMD128', 't/data/text-LF.file'), "BYY0QNuhRNXQ/c5zy8J1NQ==", 'ripemd128 (digest_file_b64/file/4)');
is( digest_file_b64u('RIPEMD128', 't/data/text-LF.file'), "BYY0QNuhRNXQ_c5zy8J1NQ", 'ripemd128 (digest_file_b64u/file/4)');
is( Crypt::Digest::RIPEMD128->new->addfile('t/data/text-LF.file')->hexdigest, "05863440dba144d5d0fdce73cbc27535", 'ripemd128 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::RIPEMD128->new->addfile($fh)->hexdigest, "05863440dba144d5d0fdce73cbc27535", 'ripemd128 (OO/filehandle/4)');
  close($fh);
}
