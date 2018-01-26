### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::SHA512 qw( sha512 sha512_hex sha512_b64 sha512_b64u sha512_file sha512_file_hex sha512_file_b64 sha512_file_b64u );

is( Crypt::Digest::hashsize('SHA512'), 64, 'hashsize/1');
is( Crypt::Digest->hashsize('SHA512'), 64, 'hashsize/2');
is( Crypt::Digest::SHA512::hashsize, 64, 'hashsize/3');
is( Crypt::Digest::SHA512->hashsize, 64, 'hashsize/4');
is( Crypt::Digest->new('SHA512')->hashsize, 64, 'hashsize/5');
is( Crypt::Digest::SHA512->new->hashsize, 64, 'hashsize/6');

is( sha512("A","A","A"), pack("H*","8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385"), 'sha512 (raw/tripple_A)');
is( sha512_hex("A","A","A"), "8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385", 'sha512 (hex/tripple_A)');
is( sha512_b64("A","A","A"), "jXCNGLVN85YtaW8GmtQtrXditdTTyX7l+i2uBnPtRlRRZMB4uNs9WcS5YCDkMW8Xuz2Rvx9rwIlrvnVBbrjDhQ==", 'sha512 (base64/tripple_A)');
is( sha512_b64u("A","A","A"), "jXCNGLVN85YtaW8GmtQtrXditdTTyX7l-i2uBnPtRlRRZMB4uNs9WcS5YCDkMW8Xuz2Rvx9rwIlrvnVBbrjDhQ", 'sha512 (base64url/tripple_A)');
is( digest_data('SHA512', "A","A","A"), pack("H*","8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385"), 'sha512 (digest_data_raw/tripple_A)');
is( digest_data_hex('SHA512', "A","A","A"), "8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385", 'sha512 (digest_data_hex/tripple_A)');
is( digest_data_b64('SHA512', "A","A","A"), "jXCNGLVN85YtaW8GmtQtrXditdTTyX7l+i2uBnPtRlRRZMB4uNs9WcS5YCDkMW8Xuz2Rvx9rwIlrvnVBbrjDhQ==", 'sha512 (digest_data_b64/tripple_A)');
is( digest_data_b64u('SHA512', "A","A","A"), "jXCNGLVN85YtaW8GmtQtrXditdTTyX7l-i2uBnPtRlRRZMB4uNs9WcS5YCDkMW8Xuz2Rvx9rwIlrvnVBbrjDhQ", 'sha512 (digest_data_b64u/tripple_A)');
is( Crypt::Digest::SHA512->new->add("A","A","A")->hexdigest, "8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385", 'sha512 (OO/tripple_A)');
is( Crypt::Digest::SHA512->new->add("A")->add("A")->add("A")->hexdigest, "8d708d18b54df3962d696f069ad42dad7762b5d4d3c97ee5fa2dae0673ed46545164c078b8db3d59c4b96020e4316f17bb3d91bf1f6bc0896bbe75416eb8c385", 'sha512 (OO3/tripple_A)');


is( sha512(""), pack("H*","cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"), 'sha512 (raw/1)');
is( sha512_hex(""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 'sha512 (hex/1)');
is( sha512_b64(""), "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", 'sha512 (base64/1)');
is( digest_data('SHA512', ""), pack("H*","cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"), 'sha512 (digest_data_raw/1)');
is( digest_data_hex('SHA512', ""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 'sha512 (digest_data_hex/1)');
is( digest_data_b64('SHA512', ""), "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==", 'sha512 (digest_data_b64/1)');
is( digest_data_b64u('SHA512', ""), "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg_SpIdNs6c5H0NE8XYXysP-DGNKHfuwvY7kxvUdBeoGlODJ6-SfaPg", 'sha512 (digest_data_b64u/1)');
is( Crypt::Digest::SHA512->new->add("")->hexdigest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 'sha512 (OO/1)');

is( sha512("123"), pack("H*","3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"), 'sha512 (raw/2)');
is( sha512_hex("123"), "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2", 'sha512 (hex/2)');
is( sha512_b64("123"), "PJkJr+wlNU1VHa4hWQuybjjVPyFzuNPcPu5MBH56scHri4UQPjvnumE7MbtcnDYhTcnxSkL9ei/bhIVrylxEwg==", 'sha512 (base64/2)');
is( digest_data('SHA512', "123"), pack("H*","3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"), 'sha512 (digest_data_raw/2)');
is( digest_data_hex('SHA512', "123"), "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2", 'sha512 (digest_data_hex/2)');
is( digest_data_b64('SHA512', "123"), "PJkJr+wlNU1VHa4hWQuybjjVPyFzuNPcPu5MBH56scHri4UQPjvnumE7MbtcnDYhTcnxSkL9ei/bhIVrylxEwg==", 'sha512 (digest_data_b64/2)');
is( digest_data_b64u('SHA512', "123"), "PJkJr-wlNU1VHa4hWQuybjjVPyFzuNPcPu5MBH56scHri4UQPjvnumE7MbtcnDYhTcnxSkL9ei_bhIVrylxEwg", 'sha512 (digest_data_b64u/2)');
is( Crypt::Digest::SHA512->new->add("123")->hexdigest, "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2", 'sha512 (OO/2)');

is( sha512("test\0test\0test\n"), pack("H*","23f26f65ca7b6ba3d254f1e218586d43d5349e1a9c33168a9c3a97d70cd7bc924b28d3ccc41df7939b29ea6807e04d34beed2a89c7c38c2276a47a4c45755699"), 'sha512 (raw/3)');
is( sha512_hex("test\0test\0test\n"), "23f26f65ca7b6ba3d254f1e218586d43d5349e1a9c33168a9c3a97d70cd7bc924b28d3ccc41df7939b29ea6807e04d34beed2a89c7c38c2276a47a4c45755699", 'sha512 (hex/3)');
is( sha512_b64("test\0test\0test\n"), "I/JvZcp7a6PSVPHiGFhtQ9U0nhqcMxaKnDqX1wzXvJJLKNPMxB33k5sp6mgH4E00vu0qicfDjCJ2pHpMRXVWmQ==", 'sha512 (base64/3)');
is( digest_data('SHA512', "test\0test\0test\n"), pack("H*","23f26f65ca7b6ba3d254f1e218586d43d5349e1a9c33168a9c3a97d70cd7bc924b28d3ccc41df7939b29ea6807e04d34beed2a89c7c38c2276a47a4c45755699"), 'sha512 (digest_data_raw/3)');
is( digest_data_hex('SHA512', "test\0test\0test\n"), "23f26f65ca7b6ba3d254f1e218586d43d5349e1a9c33168a9c3a97d70cd7bc924b28d3ccc41df7939b29ea6807e04d34beed2a89c7c38c2276a47a4c45755699", 'sha512 (digest_data_hex/3)');
is( digest_data_b64('SHA512', "test\0test\0test\n"), "I/JvZcp7a6PSVPHiGFhtQ9U0nhqcMxaKnDqX1wzXvJJLKNPMxB33k5sp6mgH4E00vu0qicfDjCJ2pHpMRXVWmQ==", 'sha512 (digest_data_b64/3)');
is( digest_data_b64u('SHA512', "test\0test\0test\n"), "I_JvZcp7a6PSVPHiGFhtQ9U0nhqcMxaKnDqX1wzXvJJLKNPMxB33k5sp6mgH4E00vu0qicfDjCJ2pHpMRXVWmQ", 'sha512 (digest_data_b64u/3)');
is( Crypt::Digest::SHA512->new->add("test\0test\0test\n")->hexdigest, "23f26f65ca7b6ba3d254f1e218586d43d5349e1a9c33168a9c3a97d70cd7bc924b28d3ccc41df7939b29ea6807e04d34beed2a89c7c38c2276a47a4c45755699", 'sha512 (OO/3)');


is( sha512_file('t/data/binary-test.file'), pack("H*","f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a"), 'sha512 (raw/file/1)');
is( sha512_file_hex('t/data/binary-test.file'), "f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a", 'sha512 (hex/file/1)');
is( sha512_file_b64('t/data/binary-test.file'), "9jFlKYLwBVYyTR+5B42Bjv7eD2o+BCxzaXlUPisOTUTikjj9DUQdSywtFvhZffSRLtdS8JQ4sd1k78cjIE0zeg==", 'sha512 (base64/file/1)');
is( digest_file('SHA512', 't/data/binary-test.file'), pack("H*","f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a"), 'sha512 (digest_file_raw/file/1)');
is( digest_file_hex('SHA512', 't/data/binary-test.file'), "f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a", 'sha512 (digest_file_hex/file/1)');
is( digest_file_b64('SHA512', 't/data/binary-test.file'), "9jFlKYLwBVYyTR+5B42Bjv7eD2o+BCxzaXlUPisOTUTikjj9DUQdSywtFvhZffSRLtdS8JQ4sd1k78cjIE0zeg==", 'sha512 (digest_file_b64/file/1)');
is( digest_file_b64u('SHA512', 't/data/binary-test.file'), "9jFlKYLwBVYyTR-5B42Bjv7eD2o-BCxzaXlUPisOTUTikjj9DUQdSywtFvhZffSRLtdS8JQ4sd1k78cjIE0zeg", 'sha512 (digest_file_b64u/file/1)');
is( Crypt::Digest::SHA512->new->addfile('t/data/binary-test.file')->hexdigest, "f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a", 'sha512 (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::SHA512->new->addfile($fh)->hexdigest, "f631652982f00556324d1fb9078d818efede0f6a3e042c736979543e2b0e4d44e29238fd0d441d4b2c2d16f8597df4912ed752f09438b1dd64efc723204d337a", 'sha512 (OO/filehandle/1)');
  close($fh);
}

is( sha512_file('t/data/text-CR.file'), pack("H*","cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06"), 'sha512 (raw/file/2)');
is( sha512_file_hex('t/data/text-CR.file'), "cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06", 'sha512 (hex/file/2)');
is( sha512_file_b64('t/data/text-CR.file'), "z+p6GsNWgwpOk4+QjinefvzqsrhR9wcipGQISsgxSN5g8ZsOmd5YGy+7Pal7FM0F8GQx1/oS/jg2nz/6EJRKBg==", 'sha512 (base64/file/2)');
is( digest_file('SHA512', 't/data/text-CR.file'), pack("H*","cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06"), 'sha512 (digest_file_raw/file/2)');
is( digest_file_hex('SHA512', 't/data/text-CR.file'), "cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06", 'sha512 (digest_file_hex/file/2)');
is( digest_file_b64('SHA512', 't/data/text-CR.file'), "z+p6GsNWgwpOk4+QjinefvzqsrhR9wcipGQISsgxSN5g8ZsOmd5YGy+7Pal7FM0F8GQx1/oS/jg2nz/6EJRKBg==", 'sha512 (digest_file_b64/file/2)');
is( digest_file_b64u('SHA512', 't/data/text-CR.file'), "z-p6GsNWgwpOk4-QjinefvzqsrhR9wcipGQISsgxSN5g8ZsOmd5YGy-7Pal7FM0F8GQx1_oS_jg2nz_6EJRKBg", 'sha512 (digest_file_b64u/file/2)');
is( Crypt::Digest::SHA512->new->addfile('t/data/text-CR.file')->hexdigest, "cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06", 'sha512 (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::SHA512->new->addfile($fh)->hexdigest, "cfea7a1ac356830a4e938f908e29de7efceab2b851f70722a464084ac83148de60f19b0e99de581b2fbb3da97b14cd05f06431d7fa12fe38369f3ffa10944a06", 'sha512 (OO/filehandle/2)');
  close($fh);
}

is( sha512_file('t/data/text-CRLF.file'), pack("H*","158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923"), 'sha512 (raw/file/3)');
is( sha512_file_hex('t/data/text-CRLF.file'), "158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923", 'sha512 (hex/file/3)');
is( sha512_file_b64('t/data/text-CRLF.file'), "FY8l0BXgKV3Bl44KXd+YH2+Z5i61x7fF7p7GPx4oadJohedg2pE+9giXSVSueOqfu+6ozjkhYhmLD9zdqYmpIw==", 'sha512 (base64/file/3)');
is( digest_file('SHA512', 't/data/text-CRLF.file'), pack("H*","158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923"), 'sha512 (digest_file_raw/file/3)');
is( digest_file_hex('SHA512', 't/data/text-CRLF.file'), "158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923", 'sha512 (digest_file_hex/file/3)');
is( digest_file_b64('SHA512', 't/data/text-CRLF.file'), "FY8l0BXgKV3Bl44KXd+YH2+Z5i61x7fF7p7GPx4oadJohedg2pE+9giXSVSueOqfu+6ozjkhYhmLD9zdqYmpIw==", 'sha512 (digest_file_b64/file/3)');
is( digest_file_b64u('SHA512', 't/data/text-CRLF.file'), "FY8l0BXgKV3Bl44KXd-YH2-Z5i61x7fF7p7GPx4oadJohedg2pE-9giXSVSueOqfu-6ozjkhYhmLD9zdqYmpIw", 'sha512 (digest_file_b64u/file/3)');
is( Crypt::Digest::SHA512->new->addfile('t/data/text-CRLF.file')->hexdigest, "158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923", 'sha512 (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512->new->addfile($fh)->hexdigest, "158f25d015e0295dc1978e0a5ddf981f6f99e62eb5c7b7c5ee9ec63f1e2869d26885e760da913ef608974954ae78ea9fbbeea8ce392162198b0fdcdda989a923", 'sha512 (OO/filehandle/3)');
  close($fh);
}

is( sha512_file('t/data/text-LF.file'), pack("H*","e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a"), 'sha512 (raw/file/4)');
is( sha512_file_hex('t/data/text-LF.file'), "e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a", 'sha512 (hex/file/4)');
is( sha512_file_b64('t/data/text-LF.file'), "4Sf8EjBZ8FVNwZF67QdqnIidFx3Jzb39cFZB+jaP3mavhuD40Up9PnJXHSv9JaBg73DkqEwdO7HQ11JMqL+qeg==", 'sha512 (base64/file/4)');
is( digest_file('SHA512', 't/data/text-LF.file'), pack("H*","e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a"), 'sha512 (digest_file_raw/file/4)');
is( digest_file_hex('SHA512', 't/data/text-LF.file'), "e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a", 'sha512 (digest_file_hex/file/4)');
is( digest_file_b64('SHA512', 't/data/text-LF.file'), "4Sf8EjBZ8FVNwZF67QdqnIidFx3Jzb39cFZB+jaP3mavhuD40Up9PnJXHSv9JaBg73DkqEwdO7HQ11JMqL+qeg==", 'sha512 (digest_file_b64/file/4)');
is( digest_file_b64u('SHA512', 't/data/text-LF.file'), "4Sf8EjBZ8FVNwZF67QdqnIidFx3Jzb39cFZB-jaP3mavhuD40Up9PnJXHSv9JaBg73DkqEwdO7HQ11JMqL-qeg", 'sha512 (digest_file_b64u/file/4)');
is( Crypt::Digest::SHA512->new->addfile('t/data/text-LF.file')->hexdigest, "e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a", 'sha512 (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::SHA512->new->addfile($fh)->hexdigest, "e127fc123059f0554dc1917aed076a9c889d171dc9cdbdfd705641fa368fde66af86e0f8d14a7d3e72571d2bfd25a060ef70e4a84c1d3bb1d0d7524ca8bfaa7a", 'sha512 (OO/filehandle/4)');
  close($fh);
}
