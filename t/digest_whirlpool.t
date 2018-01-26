### BEWARE - GENERATED FILE, DO NOT EDIT MANUALLY!

use strict;
use warnings;

use Test::More tests => 8*3 + 9*4 + 10 + 6;

use Crypt::Digest qw( digest_data digest_data_hex digest_data_b64 digest_data_b64u digest_file digest_file_hex digest_file_b64 digest_file_b64u );
use Crypt::Digest::Whirlpool qw( whirlpool whirlpool_hex whirlpool_b64 whirlpool_b64u whirlpool_file whirlpool_file_hex whirlpool_file_b64 whirlpool_file_b64u );

is( Crypt::Digest::hashsize('Whirlpool'), 64, 'hashsize/1');
is( Crypt::Digest->hashsize('Whirlpool'), 64, 'hashsize/2');
is( Crypt::Digest::Whirlpool::hashsize, 64, 'hashsize/3');
is( Crypt::Digest::Whirlpool->hashsize, 64, 'hashsize/4');
is( Crypt::Digest->new('Whirlpool')->hashsize, 64, 'hashsize/5');
is( Crypt::Digest::Whirlpool->new->hashsize, 64, 'hashsize/6');

is( whirlpool("A","A","A"), pack("H*","a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64"), 'whirlpool (raw/tripple_A)');
is( whirlpool_hex("A","A","A"), "a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64", 'whirlpool (hex/tripple_A)');
is( whirlpool_b64("A","A","A"), "pN6jjHQ/MY23Fp4orCev8XOUK2e1b5iB2kZL2sSPR8xIHuKXRlV88BPRxUx6dpEsE4CxaCUd9xGCk1Ef2JqaZA==", 'whirlpool (base64/tripple_A)');
is( whirlpool_b64u("A","A","A"), "pN6jjHQ_MY23Fp4orCev8XOUK2e1b5iB2kZL2sSPR8xIHuKXRlV88BPRxUx6dpEsE4CxaCUd9xGCk1Ef2JqaZA", 'whirlpool (base64url/tripple_A)');
is( digest_data('Whirlpool', "A","A","A"), pack("H*","a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64"), 'whirlpool (digest_data_raw/tripple_A)');
is( digest_data_hex('Whirlpool', "A","A","A"), "a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64", 'whirlpool (digest_data_hex/tripple_A)');
is( digest_data_b64('Whirlpool', "A","A","A"), "pN6jjHQ/MY23Fp4orCev8XOUK2e1b5iB2kZL2sSPR8xIHuKXRlV88BPRxUx6dpEsE4CxaCUd9xGCk1Ef2JqaZA==", 'whirlpool (digest_data_b64/tripple_A)');
is( digest_data_b64u('Whirlpool', "A","A","A"), "pN6jjHQ_MY23Fp4orCev8XOUK2e1b5iB2kZL2sSPR8xIHuKXRlV88BPRxUx6dpEsE4CxaCUd9xGCk1Ef2JqaZA", 'whirlpool (digest_data_b64u/tripple_A)');
is( Crypt::Digest::Whirlpool->new->add("A","A","A")->hexdigest, "a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64", 'whirlpool (OO/tripple_A)');
is( Crypt::Digest::Whirlpool->new->add("A")->add("A")->add("A")->hexdigest, "a4dea38c743f318db7169e28ac27aff173942b67b56f9881da464bdac48f47cc481ee29746557cf013d1c54c7a76912c1380b168251df7118293511fd89a9a64", 'whirlpool (OO3/tripple_A)');


is( whirlpool(""), pack("H*","19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"), 'whirlpool (raw/1)');
is( whirlpool_hex(""), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", 'whirlpool (hex/1)');
is( whirlpool_b64(""), "Gfph11UipGabROOcHS4XJsUwIyEw1Af4mv7glkmX96c+g75piyiP68+I4+A8TwdX6olk5Ztj2TcIsTjMQqZusw==", 'whirlpool (base64/1)');
is( digest_data('Whirlpool', ""), pack("H*","19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"), 'whirlpool (digest_data_raw/1)');
is( digest_data_hex('Whirlpool', ""), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", 'whirlpool (digest_data_hex/1)');
is( digest_data_b64('Whirlpool', ""), "Gfph11UipGabROOcHS4XJsUwIyEw1Af4mv7glkmX96c+g75piyiP68+I4+A8TwdX6olk5Ztj2TcIsTjMQqZusw==", 'whirlpool (digest_data_b64/1)');
is( digest_data_b64u('Whirlpool', ""), "Gfph11UipGabROOcHS4XJsUwIyEw1Af4mv7glkmX96c-g75piyiP68-I4-A8TwdX6olk5Ztj2TcIsTjMQqZusw", 'whirlpool (digest_data_b64u/1)');
is( Crypt::Digest::Whirlpool->new->add("")->hexdigest, "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3", 'whirlpool (OO/1)');

is( whirlpool("123"), pack("H*","344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f"), 'whirlpool (raw/2)');
is( whirlpool_hex("123"), "344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f", 'whirlpool (hex/2)');
is( whirlpool_b64("123"), "NEkH6JuYHK8iHQX1l+tXpq9AjxX03XiVu9G5aik47CSn3PI6y5Ts4LbXsGQDWLxWvbRIGUuTBTEa/wOKg0oHnw==", 'whirlpool (base64/2)');
is( digest_data('Whirlpool', "123"), pack("H*","344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f"), 'whirlpool (digest_data_raw/2)');
is( digest_data_hex('Whirlpool', "123"), "344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f", 'whirlpool (digest_data_hex/2)');
is( digest_data_b64('Whirlpool', "123"), "NEkH6JuYHK8iHQX1l+tXpq9AjxX03XiVu9G5aik47CSn3PI6y5Ts4LbXsGQDWLxWvbRIGUuTBTEa/wOKg0oHnw==", 'whirlpool (digest_data_b64/2)');
is( digest_data_b64u('Whirlpool', "123"), "NEkH6JuYHK8iHQX1l-tXpq9AjxX03XiVu9G5aik47CSn3PI6y5Ts4LbXsGQDWLxWvbRIGUuTBTEa_wOKg0oHnw", 'whirlpool (digest_data_b64u/2)');
is( Crypt::Digest::Whirlpool->new->add("123")->hexdigest, "344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f", 'whirlpool (OO/2)');

is( whirlpool("test\0test\0test\n"), pack("H*","3dbd3f37a844611382f9fc757b3ba299d1c250fa1f2fdd69f06b113f28e1c3756f5cc551996932dd8802f335db6789002f06e3ff11eb19c8715113e588bc39c7"), 'whirlpool (raw/3)');
is( whirlpool_hex("test\0test\0test\n"), "3dbd3f37a844611382f9fc757b3ba299d1c250fa1f2fdd69f06b113f28e1c3756f5cc551996932dd8802f335db6789002f06e3ff11eb19c8715113e588bc39c7", 'whirlpool (hex/3)');
is( whirlpool_b64("test\0test\0test\n"), "Pb0/N6hEYROC+fx1ezuimdHCUPofL91p8GsRPyjhw3VvXMVRmWky3YgC8zXbZ4kALwbj/xHrGchxURPliLw5xw==", 'whirlpool (base64/3)');
is( digest_data('Whirlpool', "test\0test\0test\n"), pack("H*","3dbd3f37a844611382f9fc757b3ba299d1c250fa1f2fdd69f06b113f28e1c3756f5cc551996932dd8802f335db6789002f06e3ff11eb19c8715113e588bc39c7"), 'whirlpool (digest_data_raw/3)');
is( digest_data_hex('Whirlpool', "test\0test\0test\n"), "3dbd3f37a844611382f9fc757b3ba299d1c250fa1f2fdd69f06b113f28e1c3756f5cc551996932dd8802f335db6789002f06e3ff11eb19c8715113e588bc39c7", 'whirlpool (digest_data_hex/3)');
is( digest_data_b64('Whirlpool', "test\0test\0test\n"), "Pb0/N6hEYROC+fx1ezuimdHCUPofL91p8GsRPyjhw3VvXMVRmWky3YgC8zXbZ4kALwbj/xHrGchxURPliLw5xw==", 'whirlpool (digest_data_b64/3)');
is( digest_data_b64u('Whirlpool', "test\0test\0test\n"), "Pb0_N6hEYROC-fx1ezuimdHCUPofL91p8GsRPyjhw3VvXMVRmWky3YgC8zXbZ4kALwbj_xHrGchxURPliLw5xw", 'whirlpool (digest_data_b64u/3)');
is( Crypt::Digest::Whirlpool->new->add("test\0test\0test\n")->hexdigest, "3dbd3f37a844611382f9fc757b3ba299d1c250fa1f2fdd69f06b113f28e1c3756f5cc551996932dd8802f335db6789002f06e3ff11eb19c8715113e588bc39c7", 'whirlpool (OO/3)');


is( whirlpool_file('t/data/binary-test.file'), pack("H*","a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d"), 'whirlpool (raw/file/1)');
is( whirlpool_file_hex('t/data/binary-test.file'), "a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d", 'whirlpool (hex/file/1)');
is( whirlpool_file_b64('t/data/binary-test.file'), "qEs15wI3HXqWxTMnR9UhCkJVEtLWxexeuIUXGNOTn68LhNPBxrEHHmxuVO/JbqezpG+QGVVPq7DUopJP+l3/jQ==", 'whirlpool (base64/file/1)');
is( digest_file('Whirlpool', 't/data/binary-test.file'), pack("H*","a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d"), 'whirlpool (digest_file_raw/file/1)');
is( digest_file_hex('Whirlpool', 't/data/binary-test.file'), "a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d", 'whirlpool (digest_file_hex/file/1)');
is( digest_file_b64('Whirlpool', 't/data/binary-test.file'), "qEs15wI3HXqWxTMnR9UhCkJVEtLWxexeuIUXGNOTn68LhNPBxrEHHmxuVO/JbqezpG+QGVVPq7DUopJP+l3/jQ==", 'whirlpool (digest_file_b64/file/1)');
is( digest_file_b64u('Whirlpool', 't/data/binary-test.file'), "qEs15wI3HXqWxTMnR9UhCkJVEtLWxexeuIUXGNOTn68LhNPBxrEHHmxuVO_JbqezpG-QGVVPq7DUopJP-l3_jQ", 'whirlpool (digest_file_b64u/file/1)');
is( Crypt::Digest::Whirlpool->new->addfile('t/data/binary-test.file')->hexdigest, "a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d", 'whirlpool (OO/file/1)');
{
  open(my $fh, '<', 't/data/binary-test.file');
  binmode($fh);
  is( Crypt::Digest::Whirlpool->new->addfile($fh)->hexdigest, "a84b35e702371d7a96c5332747d5210a425512d2d6c5ec5eb8851718d3939faf0b84d3c1c6b1071e6c6e54efc96ea7b3a46f9019554fabb0d4a2924ffa5dff8d", 'whirlpool (OO/filehandle/1)');
  close($fh);
}

is( whirlpool_file('t/data/text-CR.file'), pack("H*","2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0"), 'whirlpool (raw/file/2)');
is( whirlpool_file_hex('t/data/text-CR.file'), "2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0", 'whirlpool (hex/file/2)');
is( whirlpool_file_b64('t/data/text-CR.file'), "KEb3+Mcx/HfAhQN7cb7Akb33cvR1nAZ2C+qRTvbx4M+yRUiChlC7dIfWoelq3lQyaL0B6Q2uyV2+nvgX3GaL0A==", 'whirlpool (base64/file/2)');
is( digest_file('Whirlpool', 't/data/text-CR.file'), pack("H*","2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0"), 'whirlpool (digest_file_raw/file/2)');
is( digest_file_hex('Whirlpool', 't/data/text-CR.file'), "2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0", 'whirlpool (digest_file_hex/file/2)');
is( digest_file_b64('Whirlpool', 't/data/text-CR.file'), "KEb3+Mcx/HfAhQN7cb7Akb33cvR1nAZ2C+qRTvbx4M+yRUiChlC7dIfWoelq3lQyaL0B6Q2uyV2+nvgX3GaL0A==", 'whirlpool (digest_file_b64/file/2)');
is( digest_file_b64u('Whirlpool', 't/data/text-CR.file'), "KEb3-Mcx_HfAhQN7cb7Akb33cvR1nAZ2C-qRTvbx4M-yRUiChlC7dIfWoelq3lQyaL0B6Q2uyV2-nvgX3GaL0A", 'whirlpool (digest_file_b64u/file/2)');
is( Crypt::Digest::Whirlpool->new->addfile('t/data/text-CR.file')->hexdigest, "2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0", 'whirlpool (OO/file/2)');
{
  open(my $fh, '<', 't/data/text-CR.file');
  binmode($fh);
  is( Crypt::Digest::Whirlpool->new->addfile($fh)->hexdigest, "2846f7f8c731fc77c085037b71bec091bdf772f4759c06760bea914ef6f1e0cfb24548828650bb7487d6a1e96ade543268bd01e90daec95dbe9ef817dc668bd0", 'whirlpool (OO/filehandle/2)');
  close($fh);
}

is( whirlpool_file('t/data/text-CRLF.file'), pack("H*","5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf"), 'whirlpool (raw/file/3)');
is( whirlpool_file_hex('t/data/text-CRLF.file'), "5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf", 'whirlpool (hex/file/3)');
is( whirlpool_file_b64('t/data/text-CRLF.file'), "XQnIy/5/aPXjdKrDV+4O5rOsy+eUsbgmuKcqT2dx+GzbZWBDJeCcVH9u63GiXpTTNhhuwEUlXBUtUvtX05TZzw==", 'whirlpool (base64/file/3)');
is( digest_file('Whirlpool', 't/data/text-CRLF.file'), pack("H*","5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf"), 'whirlpool (digest_file_raw/file/3)');
is( digest_file_hex('Whirlpool', 't/data/text-CRLF.file'), "5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf", 'whirlpool (digest_file_hex/file/3)');
is( digest_file_b64('Whirlpool', 't/data/text-CRLF.file'), "XQnIy/5/aPXjdKrDV+4O5rOsy+eUsbgmuKcqT2dx+GzbZWBDJeCcVH9u63GiXpTTNhhuwEUlXBUtUvtX05TZzw==", 'whirlpool (digest_file_b64/file/3)');
is( digest_file_b64u('Whirlpool', 't/data/text-CRLF.file'), "XQnIy_5_aPXjdKrDV-4O5rOsy-eUsbgmuKcqT2dx-GzbZWBDJeCcVH9u63GiXpTTNhhuwEUlXBUtUvtX05TZzw", 'whirlpool (digest_file_b64u/file/3)');
is( Crypt::Digest::Whirlpool->new->addfile('t/data/text-CRLF.file')->hexdigest, "5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf", 'whirlpool (OO/file/3)');
{
  open(my $fh, '<', 't/data/text-CRLF.file');
  binmode($fh);
  is( Crypt::Digest::Whirlpool->new->addfile($fh)->hexdigest, "5d09c8cbfe7f68f5e374aac357ee0ee6b3accbe794b1b826b8a72a4f6771f86cdb65604325e09c547f6eeb71a25e94d336186ec045255c152d52fb57d394d9cf", 'whirlpool (OO/filehandle/3)');
  close($fh);
}

is( whirlpool_file('t/data/text-LF.file'), pack("H*","05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0"), 'whirlpool (raw/file/4)');
is( whirlpool_file_hex('t/data/text-LF.file'), "05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0", 'whirlpool (hex/file/4)');
is( whirlpool_file_b64('t/data/text-LF.file'), "BbL14ogzpzTcjcdj4SAw+3jbrF/ZcJvDAxXqgVB9OzOGl8HFhHSr60HxEERDgQAL/9oXag+gsSsbZcz9n20ZsA==", 'whirlpool (base64/file/4)');
is( digest_file('Whirlpool', 't/data/text-LF.file'), pack("H*","05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0"), 'whirlpool (digest_file_raw/file/4)');
is( digest_file_hex('Whirlpool', 't/data/text-LF.file'), "05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0", 'whirlpool (digest_file_hex/file/4)');
is( digest_file_b64('Whirlpool', 't/data/text-LF.file'), "BbL14ogzpzTcjcdj4SAw+3jbrF/ZcJvDAxXqgVB9OzOGl8HFhHSr60HxEERDgQAL/9oXag+gsSsbZcz9n20ZsA==", 'whirlpool (digest_file_b64/file/4)');
is( digest_file_b64u('Whirlpool', 't/data/text-LF.file'), "BbL14ogzpzTcjcdj4SAw-3jbrF_ZcJvDAxXqgVB9OzOGl8HFhHSr60HxEERDgQAL_9oXag-gsSsbZcz9n20ZsA", 'whirlpool (digest_file_b64u/file/4)');
is( Crypt::Digest::Whirlpool->new->addfile('t/data/text-LF.file')->hexdigest, "05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0", 'whirlpool (OO/file/4)');
{
  open(my $fh, '<', 't/data/text-LF.file');
  binmode($fh);
  is( Crypt::Digest::Whirlpool->new->addfile($fh)->hexdigest, "05b2f5e28833a734dc8dc763e12030fb78dbac5fd9709bc30315ea81507d3b338697c1c58474abeb41f110444381000bffda176a0fa0b12b1b65ccfd9f6d19b0", 'whirlpool (OO/filehandle/4)');
  close($fh);
}
