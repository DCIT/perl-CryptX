### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA384 qw( sha384 sha384_hex sha384_b64 sha384_b64u sha384_file sha384_file_hex sha384_file_b64 sha384_file_b64u );

is( Crypt::Digest::hashsize('SHA384'), 48, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA384'), 48, 'hashsize/2');
is( Crypt::Digest::SHA384::hashsize, 48, 'hashsize/3');
is( Crypt::Digest::SHA384->hashsize, 48, 'hashsize/4');
is( Crypt::Digest->new('SHA384')->hashsize, 48, 'hashsize/5');
is( Crypt::Digest::SHA384->new->hashsize, 48, 'hashsize/6');

is( sha384("A","A","A"), pack("H*","8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe"), 'sha384 (raw/tripple_A)');
is( sha384_hex("A","A","A"), "8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe", 'sha384 (hex/tripple_A)');
is( sha384_b64("A","A","A"), "ilt8GbzRcE1SH4a5YY2G3g7Uj6KXEa1NFiMPfSazYRG+r3/v6LO+ehfODhQMoAL+", 'sha384 (base64/tripple_A)');
is( sha384_b64u("A","A","A"), "ilt8GbzRcE1SH4a5YY2G3g7Uj6KXEa1NFiMPfSazYRG-r3_v6LO-ehfODhQMoAL-", 'sha384 (base64url/tripple_A)');
is( digest_data('SHA384', "A","A","A"), pack("H*","8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe"), 'sha384 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA384', "A","A","A"), "8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe", 'sha384 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA384', "A","A","A"), "ilt8GbzRcE1SH4a5YY2G3g7Uj6KXEa1NFiMPfSazYRG+r3/v6LO+ehfODhQMoAL+", 'sha384 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA384', "A","A","A"), "ilt8GbzRcE1SH4a5YY2G3g7Uj6KXEa1NFiMPfSazYRG-r3_v6LO-ehfODhQMoAL-", 'sha384 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA384->new->add("A","A","A")->hexdigest, "8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe", 'sha384 (OO/tripple_A)');
is( Crypt::Digest::SHA384->new->add("A")->add("A")->add("A")->hexdigest, "8a5b7c19bcd1704d521f86b9618d86de0ed48fa29711ad4d16230f7d26b36111beaf7fefe8b3be7a17ce0e140ca002fe", 'sha384 (OO3/tripple_A)');


is( sha384(""), pack("H*","38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"), 'sha384 (raw/1)');
is( sha384_hex(""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", 'sha384 (hex/1)');
is( sha384_b64(""), "OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb", 'sha384 (base64/1)');
is( digest_data('SHA384', ""), pack("H*","38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"), 'sha384 (digest_data_raw/1)');
is( digest_data_hex('SHA384', ""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", 'sha384 (digest_data_hex/1)');
is( digest_data_b64('SHA384', ""), "OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb", 'sha384 (digest_data_b64/1)');
is( digest_data_b64u('SHA384', ""), "OLBgp1GsljhM2TJ-sbHjaiH9txEUvgdDTAzHv2P24donTt6_529l-9Ua0vFImLlb", 'sha384 (digest_data_b64u/1)');
is( Crypt::Digest::SHA384->new->add("")->hexdigest, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", 'sha384 (OO/1)');

is( sha384("123"), pack("H*","9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f"), 'sha384 (raw/2)');
is( sha384_hex("123"), "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", 'sha384 (hex/2)');
is( sha384_b64("123"), "mgqC8MDPMUcNev/t40BsyaqEEGcVILcnBE7aFbTCVTKptc2Kr5zsSRnXYlW2v7AP", 'sha384 (base64/2)');
is( digest_data('SHA384', "123"), pack("H*","9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f"), 'sha384 (digest_data_raw/2)');
is( digest_data_hex('SHA384', "123"), "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", 'sha384 (digest_data_hex/2)');
is( digest_data_b64('SHA384', "123"), "mgqC8MDPMUcNev/t40BsyaqEEGcVILcnBE7aFbTCVTKptc2Kr5zsSRnXYlW2v7AP", 'sha384 (digest_data_b64/2)');
is( digest_data_b64u('SHA384', "123"), "mgqC8MDPMUcNev_t40BsyaqEEGcVILcnBE7aFbTCVTKptc2Kr5zsSRnXYlW2v7AP", 'sha384 (digest_data_b64u/2)');
is( Crypt::Digest::SHA384->new->add("123")->hexdigest, "9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", 'sha384 (OO/2)');

is( sha384("test\0test\0test\n"), pack("H*","3339da627d4b92fd5af59ce0bdabdbdfea3895d2e698322ee49a37b5bd47245fa015d716921ff689dd9e8c02ba02cea8"), 'sha384 (raw/3)');
is( sha384_hex("test\0test\0test\n"), "3339da627d4b92fd5af59ce0bdabdbdfea3895d2e698322ee49a37b5bd47245fa015d716921ff689dd9e8c02ba02cea8", 'sha384 (hex/3)');
is( sha384_b64("test\0test\0test\n"), "MznaYn1Lkv1a9Zzgvavb3+o4ldLmmDIu5Jo3tb1HJF+gFdcWkh/2id2ejAK6As6o", 'sha384 (base64/3)');
is( digest_data('SHA384', "test\0test\0test\n"), pack("H*","3339da627d4b92fd5af59ce0bdabdbdfea3895d2e698322ee49a37b5bd47245fa015d716921ff689dd9e8c02ba02cea8"), 'sha384 (digest_data_raw/3)');
is( digest_data_hex('SHA384', "test\0test\0test\n"), "3339da627d4b92fd5af59ce0bdabdbdfea3895d2e698322ee49a37b5bd47245fa015d716921ff689dd9e8c02ba02cea8", 'sha384 (digest_data_hex/3)');
is( digest_data_b64('SHA384', "test\0test\0test\n"), "MznaYn1Lkv1a9Zzgvavb3+o4ldLmmDIu5Jo3tb1HJF+gFdcWkh/2id2ejAK6As6o", 'sha384 (digest_data_b64/3)');
is( digest_data_b64u('SHA384', "test\0test\0test\n"), "MznaYn1Lkv1a9Zzgvavb3-o4ldLmmDIu5Jo3tb1HJF-gFdcWkh_2id2ejAK6As6o", 'sha384 (digest_data_b64u/3)');
is( Crypt::Digest::SHA384->new->add("test\0test\0test\n")->hexdigest, "3339da627d4b92fd5af59ce0bdabdbdfea3895d2e698322ee49a37b5bd47245fa015d716921ff689dd9e8c02ba02cea8", 'sha384 (OO/3)');


is( sha384_file('t/data/binary-test.file'), pack("H*","aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49"), 'sha384 (raw/file/1)');
is( sha384_file_hex('t/data/binary-test.file'), "aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49", 'sha384 (hex/file/1)');
is( sha384_file_b64('t/data/binary-test.file'), "rsVq1y2H9ibyw/3sqTioP/T1GExOq93MZM7uwxMNBibFiA7Bpqf9GoyIx5laRfxJ", 'sha384 (base64/file/1)');
is( digest_file('SHA384', 't/data/binary-test.file'), pack("H*","aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49"), 'sha384 (digest_file_raw/file/1)');
is( digest_file_hex('SHA384', 't/data/binary-test.file'), "aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49", 'sha384 (digest_file_hex/file/1)');
is( digest_file_b64('SHA384', 't/data/binary-test.file'), "rsVq1y2H9ibyw/3sqTioP/T1GExOq93MZM7uwxMNBibFiA7Bpqf9GoyIx5laRfxJ", 'sha384 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA384', 't/data/binary-test.file'), "rsVq1y2H9ibyw_3sqTioP_T1GExOq93MZM7uwxMNBibFiA7Bpqf9GoyIx5laRfxJ", 'sha384 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA384->new->addfile('t/data/binary-test.file')->hexdigest, "aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49", 'sha384 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA384->new->addfile($fh)->hexdigest, "aec56ad72d87f626f2c3fdeca938a83ff4f5184c4eabddcc64ceeec3130d0626c5880ec1a6a7fd1a8c88c7995a45fc49", 'sha384 (OO/filehandle/1)');
  close($fh);
}

is( sha384_file('t/data/text-CR.file'), pack("H*","fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6"), 'sha384 (raw/file/2)');
is( sha384_file_hex('t/data/text-CR.file'), "fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6", 'sha384 (hex/file/2)');
is( sha384_file_b64('t/data/text-CR.file'), "/RQIdlwLQtPYNulF4h7pL+F7x/aLI8z72q8//W9ugXMr2DQNFBixir0nRe8aBUTm", 'sha384 (base64/file/2)');
is( digest_file('SHA384', 't/data/text-CR.file'), pack("H*","fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6"), 'sha384 (digest_file_raw/file/2)');
is( digest_file_hex('SHA384', 't/data/text-CR.file'), "fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6", 'sha384 (digest_file_hex/file/2)');
is( digest_file_b64('SHA384', 't/data/text-CR.file'), "/RQIdlwLQtPYNulF4h7pL+F7x/aLI8z72q8//W9ugXMr2DQNFBixir0nRe8aBUTm", 'sha384 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA384', 't/data/text-CR.file'), "_RQIdlwLQtPYNulF4h7pL-F7x_aLI8z72q8__W9ugXMr2DQNFBixir0nRe8aBUTm", 'sha384 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA384->new->addfile('t/data/text-CR.file')->hexdigest, "fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6", 'sha384 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA384->new->addfile($fh)->hexdigest, "fd1408765c0b42d3d836e945e21ee92fe17bc7f68b23ccfbdaaf3ffd6f6e81732bd8340d1418b18abd2745ef1a0544e6", 'sha384 (OO/filehandle/2)');
  close($fh);
}

is( sha384_file('t/data/text-CRLF.file'), pack("H*","f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373"), 'sha384 (raw/file/3)');
is( sha384_file_hex('t/data/text-CRLF.file'), "f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373", 'sha384 (hex/file/3)');
is( sha384_file_b64('t/data/text-CRLF.file'), "8NZDoiwvJf2jbz+DSwW1ySAcUTmzdMSlgTKM5S3Zurq8xwF/lrdO/49mwJfJFWNz", 'sha384 (base64/file/3)');
is( digest_file('SHA384', 't/data/text-CRLF.file'), pack("H*","f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373"), 'sha384 (digest_file_raw/file/3)');
is( digest_file_hex('SHA384', 't/data/text-CRLF.file'), "f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373", 'sha384 (digest_file_hex/file/3)');
is( digest_file_b64('SHA384', 't/data/text-CRLF.file'), "8NZDoiwvJf2jbz+DSwW1ySAcUTmzdMSlgTKM5S3Zurq8xwF/lrdO/49mwJfJFWNz", 'sha384 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA384', 't/data/text-CRLF.file'), "8NZDoiwvJf2jbz-DSwW1ySAcUTmzdMSlgTKM5S3Zurq8xwF_lrdO_49mwJfJFWNz", 'sha384 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA384->new->addfile('t/data/text-CRLF.file')->hexdigest, "f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373", 'sha384 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA384->new->addfile($fh)->hexdigest, "f0d643a22c2f25fda36f3f834b05b5c9201c5139b374c4a581328ce52dd9bababcc7017f96b74eff8f66c097c9156373", 'sha384 (OO/filehandle/3)');
  close($fh);
}

is( sha384_file('t/data/text-LF.file'), pack("H*","042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e"), 'sha384 (raw/file/4)');
is( sha384_file_hex('t/data/text-LF.file'), "042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e", 'sha384 (hex/file/4)');
is( sha384_file_b64('t/data/text-LF.file'), "BC6PNhyfvbG/X5vCVJUdymZWYZbsry33hQxUODOOLAbqcY2M80Fbd61WKAulo8oe", 'sha384 (base64/file/4)');
is( digest_file('SHA384', 't/data/text-LF.file'), pack("H*","042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e"), 'sha384 (digest_file_raw/file/4)');
is( digest_file_hex('SHA384', 't/data/text-LF.file'), "042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e", 'sha384 (digest_file_hex/file/4)');
is( digest_file_b64('SHA384', 't/data/text-LF.file'), "BC6PNhyfvbG/X5vCVJUdymZWYZbsry33hQxUODOOLAbqcY2M80Fbd61WKAulo8oe", 'sha384 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA384', 't/data/text-LF.file'), "BC6PNhyfvbG_X5vCVJUdymZWYZbsry33hQxUODOOLAbqcY2M80Fbd61WKAulo8oe", 'sha384 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA384->new->addfile('t/data/text-LF.file')->hexdigest, "042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e", 'sha384 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA384->new->addfile($fh)->hexdigest, "042e8f361c9fbdb1bf5f9bc254951dca66566196ecaf2df7850c5438338e2c06ea718d8cf3415b77ad56280ba5a3ca1e", 'sha384 (OO/filehandle/4)');
  close($fh);
}
