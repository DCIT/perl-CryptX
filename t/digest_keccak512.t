### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::Keccak512 qw( keccak512 keccak512_hex keccak512_b64 keccak512_b64u keccak512_file keccak512_file_hex keccak512_file_b64 keccak512_file_b64u );

is( Crypt::Digest::hashsize('Keccak512'), 64, 'hashsize/1');
is( Crypt::Digest->hashsize('Keccak512'), 64, 'hashsize/2');
is( Crypt::Digest::Keccak512::hashsize, 64, 'hashsize/3');
is( Crypt::Digest::Keccak512->hashsize, 64, 'hashsize/4');
is( Crypt::Digest->new('Keccak512')->hashsize, 64, 'hashsize/5');
is( Crypt::Digest::Keccak512->new->hashsize, 64, 'hashsize/6');

is( keccak512("A","A","A"), pack("H*","a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391"), 'keccak512 (raw/tripple_A)');
is( keccak512_hex("A","A","A"), "a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391", 'keccak512 (hex/tripple_A)');
is( keccak512_b64("A","A","A"), "oCQ6iRWE9IrrWWd0WHBdIJwN79l3ZVy4pseCmKydWYFXFlnh01AkKF1xjdH2A4dq14X1nqgUuR7mGkQzhWxjkQ==", 'keccak512 (base64/tripple_A)');
is( keccak512_b64u("A","A","A"), "oCQ6iRWE9IrrWWd0WHBdIJwN79l3ZVy4pseCmKydWYFXFlnh01AkKF1xjdH2A4dq14X1nqgUuR7mGkQzhWxjkQ", 'keccak512 (base64url/tripple_A)');
is( digest_data('Keccak512', "A","A","A"), pack("H*","a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391"), 'keccak512 (digest_data_raw/tripple_A)');
is( digest_data_hex('Keccak512', "A","A","A"), "a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391", 'keccak512 (digest_data_hex/tripple_A)');
is( digest_data_b64('Keccak512', "A","A","A"), "oCQ6iRWE9IrrWWd0WHBdIJwN79l3ZVy4pseCmKydWYFXFlnh01AkKF1xjdH2A4dq14X1nqgUuR7mGkQzhWxjkQ==", 'keccak512 (digest_data_b64/tripple_A)');
is( digest_data_b64u('Keccak512', "A","A","A"), "oCQ6iRWE9IrrWWd0WHBdIJwN79l3ZVy4pseCmKydWYFXFlnh01AkKF1xjdH2A4dq14X1nqgUuR7mGkQzhWxjkQ", 'keccak512 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::Keccak512->new->add("A","A","A")->hexdigest, "a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391", 'keccak512 (OO/tripple_A)');
is( Crypt::Digest::Keccak512->new->add("A")->add("A")->add("A")->hexdigest, "a0243a891584f48aeb59677458705d209c0defd977655cb8a6c78298ac9d5981571659e1d35024285d718dd1f603876ad785f59ea814b91ee61a4433856c6391", 'keccak512 (OO3/tripple_A)');


is( keccak512(""), pack("H*","0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"), 'keccak512 (raw/1)');
is( keccak512_hex(""), "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", 'keccak512 (hex/1)');
is( keccak512_b64(""), "DqtC3kw865I1/JGs/+dGspwpqMNmt8YOTmfEZvNqQwTAD6nK+dh5drpGm8vgZxO0NfCR7ydp+xYM2rM9NnBoDg==", 'keccak512 (base64/1)');
is( digest_data('Keccak512', ""), pack("H*","0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"), 'keccak512 (digest_data_raw/1)');
is( digest_data_hex('Keccak512', ""), "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", 'keccak512 (digest_data_hex/1)');
is( digest_data_b64('Keccak512', ""), "DqtC3kw865I1/JGs/+dGspwpqMNmt8YOTmfEZvNqQwTAD6nK+dh5drpGm8vgZxO0NfCR7ydp+xYM2rM9NnBoDg==", 'keccak512 (digest_data_b64/1)');
is( digest_data_b64u('Keccak512', ""), "DqtC3kw865I1_JGs_-dGspwpqMNmt8YOTmfEZvNqQwTAD6nK-dh5drpGm8vgZxO0NfCR7ydp-xYM2rM9NnBoDg", 'keccak512 (digest_data_b64u/1)');
is( Crypt::Digest::Keccak512->new->add("")->hexdigest, "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", 'keccak512 (OO/1)');

is( keccak512("123"), pack("H*","8ca32d950873fd2b5b34a7d79c4a294b2fd805abe3261beb04fab61a3b4b75609afd6478aa8d34e03f262d68bb09a2ba9d655e228c96723b2854838a6e613b9d"), 'keccak512 (raw/2)');
is( keccak512_hex("123"), "8ca32d950873fd2b5b34a7d79c4a294b2fd805abe3261beb04fab61a3b4b75609afd6478aa8d34e03f262d68bb09a2ba9d655e228c96723b2854838a6e613b9d", 'keccak512 (hex/2)');
is( keccak512_b64("123"), "jKMtlQhz/StbNKfXnEopSy/YBavjJhvrBPq2GjtLdWCa/WR4qo004D8mLWi7CaK6nWVeIoyWcjsoVIOKbmE7nQ==", 'keccak512 (base64/2)');
is( digest_data('Keccak512', "123"), pack("H*","8ca32d950873fd2b5b34a7d79c4a294b2fd805abe3261beb04fab61a3b4b75609afd6478aa8d34e03f262d68bb09a2ba9d655e228c96723b2854838a6e613b9d"), 'keccak512 (digest_data_raw/2)');
is( digest_data_hex('Keccak512', "123"), "8ca32d950873fd2b5b34a7d79c4a294b2fd805abe3261beb04fab61a3b4b75609afd6478aa8d34e03f262d68bb09a2ba9d655e228c96723b2854838a6e613b9d", 'keccak512 (digest_data_hex/2)');
is( digest_data_b64('Keccak512', "123"), "jKMtlQhz/StbNKfXnEopSy/YBavjJhvrBPq2GjtLdWCa/WR4qo004D8mLWi7CaK6nWVeIoyWcjsoVIOKbmE7nQ==", 'keccak512 (digest_data_b64/2)');
is( digest_data_b64u('Keccak512', "123"), "jKMtlQhz_StbNKfXnEopSy_YBavjJhvrBPq2GjtLdWCa_WR4qo004D8mLWi7CaK6nWVeIoyWcjsoVIOKbmE7nQ", 'keccak512 (digest_data_b64u/2)');
is( Crypt::Digest::Keccak512->new->add("123")->hexdigest, "8ca32d950873fd2b5b34a7d79c4a294b2fd805abe3261beb04fab61a3b4b75609afd6478aa8d34e03f262d68bb09a2ba9d655e228c96723b2854838a6e613b9d", 'keccak512 (OO/2)');

is( keccak512("test\0test\0test\n"), pack("H*","32c764ac224dfa7a5c8205dada12006a56d15a6377b6fcd65b6e17be8759459ae847d9d7cadf335d4b477541db19883a4d4a7e2dae8f9f8504f4e36cc3417e00"), 'keccak512 (raw/3)');
is( keccak512_hex("test\0test\0test\n"), "32c764ac224dfa7a5c8205dada12006a56d15a6377b6fcd65b6e17be8759459ae847d9d7cadf335d4b477541db19883a4d4a7e2dae8f9f8504f4e36cc3417e00", 'keccak512 (hex/3)');
is( keccak512_b64("test\0test\0test\n"), "MsdkrCJN+npcggXa2hIAalbRWmN3tvzWW24XvodZRZroR9nXyt8zXUtHdUHbGYg6TUp+La6Pn4UE9ONsw0F+AA==", 'keccak512 (base64/3)');
is( digest_data('Keccak512', "test\0test\0test\n"), pack("H*","32c764ac224dfa7a5c8205dada12006a56d15a6377b6fcd65b6e17be8759459ae847d9d7cadf335d4b477541db19883a4d4a7e2dae8f9f8504f4e36cc3417e00"), 'keccak512 (digest_data_raw/3)');
is( digest_data_hex('Keccak512', "test\0test\0test\n"), "32c764ac224dfa7a5c8205dada12006a56d15a6377b6fcd65b6e17be8759459ae847d9d7cadf335d4b477541db19883a4d4a7e2dae8f9f8504f4e36cc3417e00", 'keccak512 (digest_data_hex/3)');
is( digest_data_b64('Keccak512', "test\0test\0test\n"), "MsdkrCJN+npcggXa2hIAalbRWmN3tvzWW24XvodZRZroR9nXyt8zXUtHdUHbGYg6TUp+La6Pn4UE9ONsw0F+AA==", 'keccak512 (digest_data_b64/3)');
is( digest_data_b64u('Keccak512', "test\0test\0test\n"), "MsdkrCJN-npcggXa2hIAalbRWmN3tvzWW24XvodZRZroR9nXyt8zXUtHdUHbGYg6TUp-La6Pn4UE9ONsw0F-AA", 'keccak512 (digest_data_b64u/3)');
is( Crypt::Digest::Keccak512->new->add("test\0test\0test\n")->hexdigest, "32c764ac224dfa7a5c8205dada12006a56d15a6377b6fcd65b6e17be8759459ae847d9d7cadf335d4b477541db19883a4d4a7e2dae8f9f8504f4e36cc3417e00", 'keccak512 (OO/3)');


is( keccak512_file('t/data/binary-test.file'), pack("H*","369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8"), 'keccak512 (raw/file/1)');
is( keccak512_file_hex('t/data/binary-test.file'), "369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8", 'keccak512 (hex/file/1)');
is( keccak512_file_b64('t/data/binary-test.file'), "Npt3nzT16yjLwE9WJOZIl6Y9xeVlLpQU+yTiUvkdTWQ1jR2DfDQ8XzOPav2IjwzMR3DKbDSoHgwPKINrfkBH+A==", 'keccak512 (base64/file/1)');
is( digest_file('Keccak512', 't/data/binary-test.file'), pack("H*","369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8"), 'keccak512 (digest_file_raw/file/1)');
is( digest_file_hex('Keccak512', 't/data/binary-test.file'), "369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8", 'keccak512 (digest_file_hex/file/1)');
is( digest_file_b64('Keccak512', 't/data/binary-test.file'), "Npt3nzT16yjLwE9WJOZIl6Y9xeVlLpQU+yTiUvkdTWQ1jR2DfDQ8XzOPav2IjwzMR3DKbDSoHgwPKINrfkBH+A==", 'keccak512 (digest_file_b64/file/1)');
is( digest_file_b64u('Keccak512', 't/data/binary-test.file'), "Npt3nzT16yjLwE9WJOZIl6Y9xeVlLpQU-yTiUvkdTWQ1jR2DfDQ8XzOPav2IjwzMR3DKbDSoHgwPKINrfkBH-A", 'keccak512 (digest_file_b64u/file/1)');
is( Crypt::Digest::Keccak512->new->addfile('t/data/binary-test.file')->hexdigest, "369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8", 'keccak512 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Keccak512->new->addfile($fh)->hexdigest, "369b779f34f5eb28cbc04f5624e64897a63dc5e5652e9414fb24e252f91d4d64358d1d837c343c5f338f6afd888f0ccc4770ca6c34a81e0c0f28836b7e4047f8", 'keccak512 (OO/filehandle/1)');
  close($fh);
}

is( keccak512_file('t/data/text-CR.file'), pack("H*","6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793"), 'keccak512 (raw/file/2)');
is( keccak512_file_hex('t/data/text-CR.file'), "6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793", 'keccak512 (hex/file/2)');
is( keccak512_file_b64('t/data/text-CR.file'), "bsa1r5uKNatJkQAChvhbLiU/4A9ZBK1LmZhZxhxQscjyMFD2rZf4e+vY4Oa4J3iWtRI74qP5YetZR1mVLEm3kw==", 'keccak512 (base64/file/2)');
is( digest_file('Keccak512', 't/data/text-CR.file'), pack("H*","6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793"), 'keccak512 (digest_file_raw/file/2)');
is( digest_file_hex('Keccak512', 't/data/text-CR.file'), "6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793", 'keccak512 (digest_file_hex/file/2)');
is( digest_file_b64('Keccak512', 't/data/text-CR.file'), "bsa1r5uKNatJkQAChvhbLiU/4A9ZBK1LmZhZxhxQscjyMFD2rZf4e+vY4Oa4J3iWtRI74qP5YetZR1mVLEm3kw==", 'keccak512 (digest_file_b64/file/2)');
is( digest_file_b64u('Keccak512', 't/data/text-CR.file'), "bsa1r5uKNatJkQAChvhbLiU_4A9ZBK1LmZhZxhxQscjyMFD2rZf4e-vY4Oa4J3iWtRI74qP5YetZR1mVLEm3kw", 'keccak512 (digest_file_b64u/file/2)');
is( Crypt::Digest::Keccak512->new->addfile('t/data/text-CR.file')->hexdigest, "6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793", 'keccak512 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Keccak512->new->addfile($fh)->hexdigest, "6ec6b5af9b8a35ab4991000286f85b2e253fe00f5904ad4b999859c61c50b1c8f23050f6ad97f87bebd8e0e6b8277896b5123be2a3f961eb594759952c49b793", 'keccak512 (OO/filehandle/2)');
  close($fh);
}

is( keccak512_file('t/data/text-CRLF.file'), pack("H*","f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf"), 'keccak512 (raw/file/3)');
is( keccak512_file_hex('t/data/text-CRLF.file'), "f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf", 'keccak512 (hex/file/3)');
is( keccak512_file_b64('t/data/text-CRLF.file'), "9oYHpqDJhFeAui45xBdI/1cYjZPdm4FAVz8KNVjdT3eo4sg0ipNuQ2APK7L98qc7uicET7UbbBF4f0U75Af7rw==", 'keccak512 (base64/file/3)');
is( digest_file('Keccak512', 't/data/text-CRLF.file'), pack("H*","f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf"), 'keccak512 (digest_file_raw/file/3)');
is( digest_file_hex('Keccak512', 't/data/text-CRLF.file'), "f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf", 'keccak512 (digest_file_hex/file/3)');
is( digest_file_b64('Keccak512', 't/data/text-CRLF.file'), "9oYHpqDJhFeAui45xBdI/1cYjZPdm4FAVz8KNVjdT3eo4sg0ipNuQ2APK7L98qc7uicET7UbbBF4f0U75Af7rw==", 'keccak512 (digest_file_b64/file/3)');
is( digest_file_b64u('Keccak512', 't/data/text-CRLF.file'), "9oYHpqDJhFeAui45xBdI_1cYjZPdm4FAVz8KNVjdT3eo4sg0ipNuQ2APK7L98qc7uicET7UbbBF4f0U75Af7rw", 'keccak512 (digest_file_b64u/file/3)');
is( Crypt::Digest::Keccak512->new->addfile('t/data/text-CRLF.file')->hexdigest, "f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf", 'keccak512 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak512->new->addfile($fh)->hexdigest, "f68607a6a0c9845780ba2e39c41748ff57188d93dd9b8140573f0a3558dd4f77a8e2c8348a936e43600f2bb2fdf2a73bba27044fb51b6c11787f453be407fbaf", 'keccak512 (OO/filehandle/3)');
  close($fh);
}

is( keccak512_file('t/data/text-LF.file'), pack("H*","241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446"), 'keccak512 (raw/file/4)');
is( keccak512_file_hex('t/data/text-LF.file'), "241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446", 'keccak512 (hex/file/4)');
is( keccak512_file_b64('t/data/text-LF.file'), "JB6sQnTNdsYmP6Z5EdP3aK+3kcKA8Dx1f1wtBn6wIOUsSsk04nEs01C/y+ARFOCCTexyFA8DVbYV8SayDFfERg==", 'keccak512 (base64/file/4)');
is( digest_file('Keccak512', 't/data/text-LF.file'), pack("H*","241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446"), 'keccak512 (digest_file_raw/file/4)');
is( digest_file_hex('Keccak512', 't/data/text-LF.file'), "241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446", 'keccak512 (digest_file_hex/file/4)');
is( digest_file_b64('Keccak512', 't/data/text-LF.file'), "JB6sQnTNdsYmP6Z5EdP3aK+3kcKA8Dx1f1wtBn6wIOUsSsk04nEs01C/y+ARFOCCTexyFA8DVbYV8SayDFfERg==", 'keccak512 (digest_file_b64/file/4)');
is( digest_file_b64u('Keccak512', 't/data/text-LF.file'), "JB6sQnTNdsYmP6Z5EdP3aK-3kcKA8Dx1f1wtBn6wIOUsSsk04nEs01C_y-ARFOCCTexyFA8DVbYV8SayDFfERg", 'keccak512 (digest_file_b64u/file/4)');
is( Crypt::Digest::Keccak512->new->addfile('t/data/text-LF.file')->hexdigest, "241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446", 'keccak512 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Keccak512->new->addfile($fh)->hexdigest, "241eac4274cd76c6263fa67911d3f768afb791c280f03c757f5c2d067eb020e52c4ac934e2712cd350bfcbe01114e0824dec72140f0355b615f126b20c57c446", 'keccak512 (OO/filehandle/4)');
  close($fh);
}
