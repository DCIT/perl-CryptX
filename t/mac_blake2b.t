### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 36 + 8;

use Crypt::Mac::BLAKE2b qw( blake2b blake2b_hex blake2b_b64 blake2b_b64u );

is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add("")->mac), '171e61c46e5eb96bfe44b8167f72112fa3dacff54ff9b938c92a988b7b65a550', 'BLAKE2b/oo+raw/1');
is( Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add("")->hexmac, '171e61c46e5eb96bfe44b8167f72112fa3dacff54ff9b938c92a988b7b65a550', 'BLAKE2b/oo+hex/1');
is( unpack('H*', blake2b(32,'12345678901234561234567890123456',"")), '171e61c46e5eb96bfe44b8167f72112fa3dacff54ff9b938c92a988b7b65a550', 'BLAKE2b/func+raw/1');
is( blake2b_hex(32,'12345678901234561234567890123456',""), '171e61c46e5eb96bfe44b8167f72112fa3dacff54ff9b938c92a988b7b65a550', 'BLAKE2b/func+hex/1');
is( blake2b_b64(32,'12345678901234561234567890123456',""), 'Fx5hxG5euWv+RLgWf3IRL6Paz/VP+bk4ySqYi3tlpVA=', 'BLAKE2b/func+b64/1');
is( blake2b_b64u(32,'12345678901234561234567890123456',""), 'Fx5hxG5euWv-RLgWf3IRL6Paz_VP-bk4ySqYi3tlpVA', 'BLAKE2b/func+b64u/1');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->mac), 'a9c114765666cf3e313253110efcc3b844739fe14bf1b32bf69316c6716978f0', 'BLAKE2b/oo+raw/2');
is( Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("")->hexmac, 'a9c114765666cf3e313253110efcc3b844739fe14bf1b32bf69316c6716978f0', 'BLAKE2b/oo+hex/2');
is( unpack('H*', blake2b(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"")), 'a9c114765666cf3e313253110efcc3b844739fe14bf1b32bf69316c6716978f0', 'BLAKE2b/func+raw/2');
is( blake2b_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'a9c114765666cf3e313253110efcc3b844739fe14bf1b32bf69316c6716978f0', 'BLAKE2b/func+hex/2');
is( blake2b_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'qcEUdlZmzz4xMlMRDvzDuERzn+FL8bMr9pMWxnFpePA=', 'BLAKE2b/func+b64/2');
is( blake2b_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',""), 'qcEUdlZmzz4xMlMRDvzDuERzn-FL8bMr9pMWxnFpePA', 'BLAKE2b/func+b64u/2');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add(123)->mac), '17391b8e492e7994b958bcbf7ab2c4fe807749e8c5401d84b8dff226e0d56369', 'BLAKE2b/oo+raw/3');
is( Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add(123)->hexmac, '17391b8e492e7994b958bcbf7ab2c4fe807749e8c5401d84b8dff226e0d56369', 'BLAKE2b/oo+hex/3');
is( unpack('H*', blake2b(32,'12345678901234561234567890123456',123)), '17391b8e492e7994b958bcbf7ab2c4fe807749e8c5401d84b8dff226e0d56369', 'BLAKE2b/func+raw/3');
is( blake2b_hex(32,'12345678901234561234567890123456',123), '17391b8e492e7994b958bcbf7ab2c4fe807749e8c5401d84b8dff226e0d56369', 'BLAKE2b/func+hex/3');
is( blake2b_b64(32,'12345678901234561234567890123456',123), 'FzkbjkkueZS5WLy/erLE/oB3SejFQB2EuN/yJuDVY2k=', 'BLAKE2b/func+b64/3');
is( blake2b_b64u(32,'12345678901234561234567890123456',123), 'FzkbjkkueZS5WLy_erLE_oB3SejFQB2EuN_yJuDVY2k', 'BLAKE2b/func+b64u/3');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->mac), '3a246b8de4f0957420dea4fbeb84f3e8f60bc79f04c08f98610008a1e814e963', 'BLAKE2b/oo+raw/4');
is( Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add(123)->hexmac, '3a246b8de4f0957420dea4fbeb84f3e8f60bc79f04c08f98610008a1e814e963', 'BLAKE2b/oo+hex/4');
is( unpack('H*', blake2b(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123)), '3a246b8de4f0957420dea4fbeb84f3e8f60bc79f04c08f98610008a1e814e963', 'BLAKE2b/func+raw/4');
is( blake2b_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), '3a246b8de4f0957420dea4fbeb84f3e8f60bc79f04c08f98610008a1e814e963', 'BLAKE2b/func+hex/4');
is( blake2b_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'OiRrjeTwlXQg3qT764Tz6PYLx58EwI+YYQAIoegU6WM=', 'BLAKE2b/func+b64/4');
is( blake2b_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',123), 'OiRrjeTwlXQg3qT764Tz6PYLx58EwI-YYQAIoegU6WM', 'BLAKE2b/func+b64u/4');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add("test\0test\0test\n")->mac), 'd24786aeea8e412a8a8ad4609c5b2244f01af0d40da2f4ae27f21171cf9bf77d', 'BLAKE2b/oo+raw/5');
is( Crypt::Mac::BLAKE2b->new(32,'12345678901234561234567890123456')->add("test\0test\0test\n")->hexmac, 'd24786aeea8e412a8a8ad4609c5b2244f01af0d40da2f4ae27f21171cf9bf77d', 'BLAKE2b/oo+hex/5');
is( unpack('H*', blake2b(32,'12345678901234561234567890123456',"test\0test\0test\n")), 'd24786aeea8e412a8a8ad4609c5b2244f01af0d40da2f4ae27f21171cf9bf77d', 'BLAKE2b/func+raw/5');
is( blake2b_hex(32,'12345678901234561234567890123456',"test\0test\0test\n"), 'd24786aeea8e412a8a8ad4609c5b2244f01af0d40da2f4ae27f21171cf9bf77d', 'BLAKE2b/func+hex/5');
is( blake2b_b64(32,'12345678901234561234567890123456',"test\0test\0test\n"), '0keGruqOQSqKitRgnFsiRPAa8NQNovSuJ/IRcc+b930=', 'BLAKE2b/func+b64/5');
is( blake2b_b64u(32,'12345678901234561234567890123456',"test\0test\0test\n"), '0keGruqOQSqKitRgnFsiRPAa8NQNovSuJ_IRcc-b930', 'BLAKE2b/func+b64u/5');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->mac), 'dc29010f123a4cd59c91da5fc494375962502ca2179021ebca2f6dd41befa8d2', 'BLAKE2b/oo+raw/6');
is( Crypt::Mac::BLAKE2b->new(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')->add("test\0test\0test\n")->hexmac, 'dc29010f123a4cd59c91da5fc494375962502ca2179021ebca2f6dd41befa8d2', 'BLAKE2b/oo+hex/6');
is( unpack('H*', blake2b(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n")), 'dc29010f123a4cd59c91da5fc494375962502ca2179021ebca2f6dd41befa8d2', 'BLAKE2b/func+raw/6');
is( blake2b_hex(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), 'dc29010f123a4cd59c91da5fc494375962502ca2179021ebca2f6dd41befa8d2', 'BLAKE2b/func+hex/6');
is( blake2b_b64(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), '3CkBDxI6TNWckdpfxJQ3WWJQLKIXkCHryi9t1BvvqNI=', 'BLAKE2b/func+b64/6');
is( blake2b_b64u(32,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"test\0test\0test\n"), '3CkBDxI6TNWckdpfxJQ3WWJQLKIXkCHryi9t1BvvqNI', 'BLAKE2b/func+b64u/6');

is( unpack('H*', Crypt::Mac::BLAKE2b->new(32, '12345678901234561234567890123456')->add("A","A","A")->mac), '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f', 'BLAKE2b/oo+raw/tripple_A');
is( unpack('H*', Crypt::Mac::BLAKE2b->new(32, '12345678901234561234567890123456')->add("A")->add("A")->add("A")->mac), '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f', 'BLAKE2b/oo3+raw/tripple_A');
is( Crypt::Mac::BLAKE2b->new(32, '12345678901234561234567890123456')->add("A","A","A")->hexmac, '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f', 'BLAKE2b/oo+hex/tripple_A');
is( Crypt::Mac::BLAKE2b->new(32, '12345678901234561234567890123456')->add("A")->add("A")->add("A")->hexmac, '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f', 'BLAKE2b/oo3+hex/tripple_A');
is( unpack('H*', blake2b(32, '12345678901234561234567890123456',"A","A","A")), '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f', 'BLAKE2b/func+raw/tripple_A');
is( blake2b_hex (32, '12345678901234561234567890123456',"A","A","A"), '794a20cc22c1f9f278aa1219ded10105cc9cfd264e66a327f32fbc309b2d404f',  'BLAKE2b/func+hex/tripple_A');
is( blake2b_b64 (32, '12345678901234561234567890123456',"A","A","A"), 'eUogzCLB+fJ4qhIZ3tEBBcyc/SZOZqMn8y+8MJstQE8=',  'BLAKE2b/func+b64/tripple_A');
is( blake2b_b64u(32, '12345678901234561234567890123456',"A","A","A"), 'eUogzCLB-fJ4qhIZ3tEBBcyc_SZOZqMn8y-8MJstQE8', 'BLAKE2b/func+b64u/tripple_A');
