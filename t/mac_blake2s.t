### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 36 + 8;

use Crypt::Mac::BLAKE2s qw( blake2s blake2s_hex blake2s_b64 blake2s_b64u );

is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add("")->mac), '6a0915e97a27e1119f10c6991e8c6218fbaaab516a099399fda92803ea24aed8', 'BLAKE2s/oo+raw/1');
is( Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add("")->hexmac, '6a0915e97a27e1119f10c6991e8c6218fbaaab516a099399fda92803ea24aed8', 'BLAKE2s/oo+hex/1');
is( unpack('H*', blake2s(32,'12345678901234561234567890123456',"")), '6a0915e97a27e1119f10c6991e8c6218fbaaab516a099399fda92803ea24aed8', 'BLAKE2s/func+raw/1');
is( blake2s_hex(32,'12345678901234561234567890123456',""), '6a0915e97a27e1119f10c6991e8c6218fbaaab516a099399fda92803ea24aed8', 'BLAKE2s/func+hex/1');
is( blake2s_b64(32,'12345678901234561234567890123456',""), 'agkV6Xon4RGfEMaZHoxiGPuqq1FqCZOZ/akoA+okrtg=', 'BLAKE2s/func+b64/1');
is( blake2s_b64u(32,'12345678901234561234567890123456',""), 'agkV6Xon4RGfEMaZHoxiGPuqq1FqCZOZ_akoA-okrtg', 'BLAKE2s/func+b64u/1');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->mac), '18e3ce19987ba50b30dd144c16f22655eba31409d66210bc38bbc14b5dab0519', 'BLAKE2s/oo+raw/2');
is( Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->hexmac, '18e3ce19987ba50b30dd144c16f22655eba31409d66210bc38bbc14b5dab0519', 'BLAKE2s/oo+hex/2');
is( unpack('H*', blake2s(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"")), '18e3ce19987ba50b30dd144c16f22655eba31409d66210bc38bbc14b5dab0519', 'BLAKE2s/func+raw/2');
is( blake2s_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), '18e3ce19987ba50b30dd144c16f22655eba31409d66210bc38bbc14b5dab0519', 'BLAKE2s/func+hex/2');
is( blake2s_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'GOPOGZh7pQsw3RRMFvImVeujFAnWYhC8OLvBS12rBRk=', 'BLAKE2s/func+b64/2');
is( blake2s_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'GOPOGZh7pQsw3RRMFvImVeujFAnWYhC8OLvBS12rBRk', 'BLAKE2s/func+b64u/2');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add(123)->mac), '5612150160e1943e36f569d635a452eca1d745f959ca9c8dae004e8c69c66ff4', 'BLAKE2s/oo+raw/3');
is( Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add(123)->hexmac, '5612150160e1943e36f569d635a452eca1d745f959ca9c8dae004e8c69c66ff4', 'BLAKE2s/oo+hex/3');
is( unpack('H*', blake2s(32,'12345678901234561234567890123456',123)), '5612150160e1943e36f569d635a452eca1d745f959ca9c8dae004e8c69c66ff4', 'BLAKE2s/func+raw/3');
is( blake2s_hex(32,'12345678901234561234567890123456',123), '5612150160e1943e36f569d635a452eca1d745f959ca9c8dae004e8c69c66ff4', 'BLAKE2s/func+hex/3');
is( blake2s_b64(32,'12345678901234561234567890123456',123), 'VhIVAWDhlD429WnWNaRS7KHXRflZypyNrgBOjGnGb/Q=', 'BLAKE2s/func+b64/3');
is( blake2s_b64u(32,'12345678901234561234567890123456',123), 'VhIVAWDhlD429WnWNaRS7KHXRflZypyNrgBOjGnGb_Q', 'BLAKE2s/func+b64u/3');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->mac), 'a76d7d9b3388d0e4f878634d7912ee9646f9f90089c44ee7fa70c6dc55321881', 'BLAKE2s/oo+raw/4');
is( Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->hexmac, 'a76d7d9b3388d0e4f878634d7912ee9646f9f90089c44ee7fa70c6dc55321881', 'BLAKE2s/oo+hex/4');
is( unpack('H*', blake2s(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123)), 'a76d7d9b3388d0e4f878634d7912ee9646f9f90089c44ee7fa70c6dc55321881', 'BLAKE2s/func+raw/4');
is( blake2s_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'a76d7d9b3388d0e4f878634d7912ee9646f9f90089c44ee7fa70c6dc55321881', 'BLAKE2s/func+hex/4');
is( blake2s_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'p219mzOI0OT4eGNNeRLulkb5+QCJxE7n+nDG3FUyGIE=', 'BLAKE2s/func+b64/4');
is( blake2s_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'p219mzOI0OT4eGNNeRLulkb5-QCJxE7n-nDG3FUyGIE', 'BLAKE2s/func+b64u/4');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add("test\0test\0test\n")->mac), 'ad7aab35edfaab1bdd4cf1f4fea1a7a5002b7f19892b8431961aea301c57ed8b', 'BLAKE2s/oo+raw/5');
is( Crypt::Mac::BLAKE2s->new(32,'12345678901234561234567890123456')->add("test\0test\0test\n")->hexmac, 'ad7aab35edfaab1bdd4cf1f4fea1a7a5002b7f19892b8431961aea301c57ed8b', 'BLAKE2s/oo+hex/5');
is( unpack('H*', blake2s(32,'12345678901234561234567890123456',"test\0test\0test\n")), 'ad7aab35edfaab1bdd4cf1f4fea1a7a5002b7f19892b8431961aea301c57ed8b', 'BLAKE2s/func+raw/5');
is( blake2s_hex(32,'12345678901234561234567890123456',"test\0test\0test\n"), 'ad7aab35edfaab1bdd4cf1f4fea1a7a5002b7f19892b8431961aea301c57ed8b', 'BLAKE2s/func+hex/5');
is( blake2s_b64(32,'12345678901234561234567890123456',"test\0test\0test\n"), 'rXqrNe36qxvdTPH0/qGnpQArfxmJK4QxlhrqMBxX7Ys=', 'BLAKE2s/func+b64/5');
is( blake2s_b64u(32,'12345678901234561234567890123456',"test\0test\0test\n"), 'rXqrNe36qxvdTPH0_qGnpQArfxmJK4QxlhrqMBxX7Ys', 'BLAKE2s/func+b64u/5');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->mac), 'a31f0e2ba5e73a3aab7e14503690515662758279075d7b68512709824923e65c', 'BLAKE2s/oo+raw/6');
is( Crypt::Mac::BLAKE2s->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->hexmac, 'a31f0e2ba5e73a3aab7e14503690515662758279075d7b68512709824923e65c', 'BLAKE2s/oo+hex/6');
is( unpack('H*', blake2s(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n")), 'a31f0e2ba5e73a3aab7e14503690515662758279075d7b68512709824923e65c', 'BLAKE2s/func+raw/6');
is( blake2s_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'a31f0e2ba5e73a3aab7e14503690515662758279075d7b68512709824923e65c', 'BLAKE2s/func+hex/6');
is( blake2s_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'ox8OK6XnOjqrfhRQNpBRVmJ1gnkHXXtoUScJgkkj5lw=', 'BLAKE2s/func+b64/6');
is( blake2s_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'ox8OK6XnOjqrfhRQNpBRVmJ1gnkHXXtoUScJgkkj5lw', 'BLAKE2s/func+b64u/6');

is( unpack('H*', Crypt::Mac::BLAKE2s->new(32, '12345678901234561234567890123456')->add("A","A","A")->mac), '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725', 'BLAKE2s/oo+raw/tripple_A');
is( unpack('H*', Crypt::Mac::BLAKE2s->new(32, '12345678901234561234567890123456')->add("A")->add("A")->add("A")->mac), '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725', 'BLAKE2s/oo3+raw/tripple_A');
is( Crypt::Mac::BLAKE2s->new(32, '12345678901234561234567890123456')->add("A","A","A")->hexmac, '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725', 'BLAKE2s/oo+hex/tripple_A');
is( Crypt::Mac::BLAKE2s->new(32, '12345678901234561234567890123456')->add("A")->add("A")->add("A")->hexmac, '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725', 'BLAKE2s/oo3+hex/tripple_A');
is( unpack('H*', blake2s(32, '12345678901234561234567890123456',"A","A","A")), '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725', 'BLAKE2s/func+raw/tripple_A');
is( blake2s_hex (32, '12345678901234561234567890123456',"A","A","A"), '8acd7813fe7251676d1cf2817c09a25840fa9a1df7143536448a5dfdf7365725',  'BLAKE2s/func+hex/tripple_A');
is( blake2s_b64 (32, '12345678901234561234567890123456',"A","A","A"), 'is14E/5yUWdtHPKBfAmiWED6mh33FDU2RIpd/fc2VyU=',  'BLAKE2s/func+b64/tripple_A');
is( blake2s_b64u(32, '12345678901234561234567890123456',"A","A","A"), 'is14E_5yUWdtHPKBfAmiWED6mh33FDU2RIpd_fc2VyU', 'BLAKE2s/func+b64u/tripple_A');
