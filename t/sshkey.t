use strict;
use warnings;
use Test::More tests => 756;

use Crypt::PK::RSA;
use Crypt::PK::ECC;
use Crypt::PK::DSA;
use Crypt::PK::Ed25519;
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;

my $rsa = Crypt::PK::RSA->new;
my $ec  = Crypt::PK::ECC->new;
my $dsa = Crypt::PK::DSA->new;
my $ed  = Crypt::PK::Ed25519->new;
ok($rsa, "RSA new");
ok($ec,  "ECC new");
ok($dsa, "DSA new");

my $dir = "t/data/ssh";

sub _check_rsa {
  my ($K, $name, $nick, $private) = @_;
  my $R = {
    ssh_rsa_1024 => {
            'N' => 'B8E7C9348A016072F92B0E350AA3480880F5B4FBB4043DC93BFC35C8A460241F31C34D02EEEFF233C410C22FB890845D9E430691FECF525E3B360D5FCE4F749733742324EE0F4B79C79337CFED98EA9BD2C64A2701811F31E4B3E6C68355037A8E22730FE7186181B29862EB2E04C025A4482AFD3F6E0AF2C8BAF4671A10530F',
            'd' => 'F952104B778A43B2C3A6FA912AB6DFFA1769378FED3B8AD43CBDE707941CCE9801518615DE784BECE10277D440D91CA1DF342137DA8D52531D23D504C9FAF90858771098B47CF5C2D13A50787326FE7B8922E3CDD13ABEA78833619E229E69E5BD4063041C801B7FC51B82E036BD4E29FBDC1C7A636215425CC2243BE34CCD1',
            'dP' => '2F010FA8E263C85825D3449D76D82DD4E27393750535501FCDC0718E248440D40A7670A1FD920B78D951BC7EE8D3DF70FD0658FB91F5291DD7CCA6E59BD0BECF',
            'dQ' => '6AF292E939F528716A83C2F2A35B809FDD7AD0E9D36FBDC9C9F2C86E8F8086EEF4E24461F533C4B2964C04B53E650DA90C01371A3B2B60A9883BCF5B27893829',
            'e' => '10001',
            'p' => 'F61B2C906F31146E28B01A319B1F5DF5695BCED85B58A5859C9108607EB05DC242C40940D12F8820A86A4E8239C5E161576B6502FC1BCBC920048DFC01854CB7',
            'q' => 'C056C228341621B96B42809E14753BE5F0126C25F0106B4C20EFFE193F617295000798908F039E00C4046ECEDA7B34AE7C66C8C9450BE802411A844645570469',
            'qP' => 'C5F7EB4D275C6D5B5CFFC12FEED4819390C2D8029CAA50C7F67B07F9CAF0FCCB11F83C4798102F7AFA49FA6DD104AE4EACB0E3F63B59FD8F022547266070A3A',
    },
    ssh_rsa_1536 => {
            'N' => 'A460779FFE416176D1301B86197DA9D863DD9C9835FD82AC3B384D9DC4CC90CA3E44CA7FF3B5A208111246BF6046ED39448BC19DF37C05BD2AEA9387621F27109B615B2EDA76E7C6EECBF3D8098DDCBF160BD62994C6DE9A3DE2E9873C50A6DD9D4B00A89BA3390EAFECC41E1857E96F56959912E205CEC7C6B6A88B3BB538C7CD255C2D78DF432D37967A9D84CE56D92D6241490A63124E162271EE8BE111DD4CD7A34199662867CB10A791DF04F00487CB3BD5C5912947CF6524E2AFC296BD',
            'd' => '7DDD37FC146DEFB951386AFAE5ADE94DBE3A44DBF00B6BF1816EFD4F9F0F9C969FD380D334C3918C67B5FCE231505DF909D991A9E674C2D834726600B64B70583101FD16054622F79A8624F2F96DDCE79C73F7CAE316DC0072FEBB1E483AE1697A0EA7115B8B6740DCECA64428075C9916DD0949CAA7E218B945759B4E4C2760415AE4F3D71E283D95640D3BBE0B28CB53BBB745BA1A38609F2CFBEEA5C8D149331504E4667E1CC0A2968BC7A7835F80C52128CD8331CFA447EA6F63FCD2ADA9',
            'dP' => '1A7FC0D04F8FFA3C484040330045C3667F04C83B262816AB0F79786A32F9B9B85D603AD4E1118237A2ADE048CDCD9B9C4CEF6F71742D7112656B3D1653311C52D997D8E675C913CACB47AAC3156142AEE588EA54EED7FA545C093C5C4FEB7C17',
            'dQ' => '4C35FBA76395AACD9D3CC3439020793BFCB7D70296C5149895D7B76CCCD63E677253311AD255FFDF9E9F263C38908AA7907522263BB9F61B4810AEDF390DEFCBE29002BE0F327278DAC3F24386987DF9D2DE7D47E4C635280791D824D1C17329',
            'e' => '10001',
            'p' => 'CDBDECA70F14F35C6CB658B7AE804737E8527847868AFD17CFDADFFE6789BDC41AD400089C33A8535E75188E5CF01EDF0CC298D1FB0DA7BD7993139BECEFD20574E023DB71EDCA50B4967D56B6676BC2BE64FD1D3DDDE2D5A4849B53BE9B3847',
            'q' => 'CC87C6F19BEAD9549437305A1B7765A668F4C2579DCA318A4734836189DD7B3766A3279B0FD139E2612FFAEB65FD1933E74F121BBCBDE420B03E4D1252E9D391FE321F98DD941515BBF38E8631B0CB7B80469DD179E0FD6C72292CCFEC45FEDB',
            'qP' => '4664ADCFFF062FA8ECD41D317B900CD258332F413B165D772E15AC1D96F8AA9E11762B5C1059A7C8B48870D6325EF023E52186B5BC2981963FFF0F02F41161B36BC6283DD05A51C3902A4E320A3346DBD0123ECC5849BB97DC1D8F48E948C84A',
    },
    ssh_rsa_2048 => {
            'N' => 'DDC63374FB6C5CEE976B781A9873F983442F0EB96AD2EF0ADEE5F114069CA5A2B4236E1B5455453E3B1FFA45265B6DE360DC4BDC5934FB35063BD70ECB19282234AF5B814D4AD79D7ACE9BD8D05D881A0C7DC59BEF2095442D25D044580805215EB1A99566F251779FACCE0AB58E631389BA3D7F23C9A192CFCACE521713C70DEC8A533F25CD81D59AE3A1CCE8528D234740654FD07A1EF0DEDD41A154E3403C252B14879EBBBE08D796DB35DCA12B19A05ECB6E38A1EE09FB1970CD61EC8A0023D43A0218C68375243C59F13F044509AB998D129F86C507B88473306DB836449659F2415128E882522710915085037C966A8FB9A1D720C88D37B2A7E7AE091B',
            'd' => '4379DE8625495F2D28DD05F9F190B7C5FCA4E4B1FD92983092891BC4A00E614713D003DC44D87CECE648607951A657D4EACF9C353ADF27DF863A06C0F5827DF78A58205B430D16754FBC3526CE9EE69E2656CE1D17B0AE39C412D13F3A199696049DC19F37675AEA2EA70139B8EBCDB150225E3BA4C3E0692ED7E1D69036F044F72BF282247FC247DF06E4D701A18ADBF78902AC5D374A5826FB54F8783F205A1304F39EDC54434458ABBA264F70CD995E934A4DE5CF08F777B95D8FC90D1E8585DAE4DE50CDF649CEB50EBC959582850CF937692FB2F6B7F51B75C4CE05F1215A1CA0B17BC9CC01D1428A4EECD124616483B9E7DC03F62B98E186227379F221',
            'dP' => '4C745096BAD7E1204A1A5615B58ED2067E9F74343A66FE34738B6A35E44EB9C30A9000E1F86C8218AA7F6E89ACE6067E73B53349EBF9A6279AE4243785D07BE8DC3FF7A1CEE596D3A6B48361F9549ECBC6CCC64CDCC01AD3731E3FEA48FB28506C5BE30A394960540D8B9C22E57423B23CFC0D690AB05FFD49F3C03DD851CDD1',
            'dQ' => '362871B6C6DB8872F6EF0E643F889A53FA835B6BD52D8296443A51729AAAEEB5C49E65FF68EDE06839CB2F3DA340E22571FB44D582C40F35C681BEE91648308DEBAC96598C328486E434633158B0674450F00A216ACE7C64651172A34FCFD7601EDF1AD94129F8081ABED1F31846D676D30A0A0621B4811D17A3E11A2A971B95',
            'e' => '10001',
            'p' => 'F7DA46D9F3D35FD667777128C566B809EFA9ED004948F2ABD642A17F867DCC275C87E513DF5C38643FECDDC5CAE973A58FCCA00D5CF1566E080CF4B33C60DEC9E79883B85BAC98AF067C542A81C14B129C1E8EC2BFA1E1A73AE157BCD875542115BBEA31FFA3EEF2B3B65F35688914D9355DD6EF2F39FB1B946D225CE794B187',
            'q' => 'E51078436AC01128519553899B22501295821AFB90CCBAE3159A6BB3BD25828C30A45525FF868E6AAA756B27BE059B7D26F3EFB08EE74CCE3756C7107563B887AD90F9E7E340F533A442CD85C5B54A0B673726565B4BC54C1AFE5393FD7988F21C0A6765B095C52F50537A5709EDA3EFD5747A320E380DE7871437CF6BFD20CD',
            'qP' => '241F61FA8CACD86DE6C365AC0F62AEC0244E5AC45740B9A8674273D6B8CCC5EE09A06239D3F0422A735011F36F4BEE43EAA8E8F107D6EDC9A549693D64B853E31385DA2D9809820046DBE23746E826CD348555E64F2747D277CC8763063EBF0371D856023B98E16328F3F6AFD6B548BC5B9668674ACFED6B93507738F5CA1A80',
    },
    ssh_rsa_4096 => {
            'N' => 'A3A14A915FDB49E98563F84ED8D03F68CB648252DA0B98DAA8BCC39CFDB581F8583C1A0110369F7D5EF1FAA7EFD70C8638326F7543DA35AF27569C09C72ACFFD2CEC92A4E50D6DB7E50EC16CB4DF19AEAAB2B8F888A19A9AC10BD87B1934FF467235C900F5F5802990C9A26D4DE43BAD04AE790E0AB8D321E4A4007A9E5A9D58B63C21A6F45782CA4ED3411B276B74F47C035D08E78903905C71F3634E64D27D86AED0618243B0BE4B7BF7C1F8FA8892C3F9AA8DA57DA3C97BDC6DC7B9B8F8520945040E2EB15E7FF2B4B4ED59BF45397553479965A1C93378B67C28117E2967B6241C77A67011625F8C6DEF4FF3A6F1B972E20F3302480393FBDB0EC0E627CA4A84CBAE4406CBBC96FDECF2C6B9B8D8D8398CD41BFA3B22B9085C9D4FC82A2A7BC4ED4ADB3C523E17300D14483C61B09027CCAEBE4F1B81159FD3C909E5BFC9D4293A6E32B096B2F00671C90A213F58D16ACBACFAA506A2F3870FAAE3883AE0D250E9258EC27FA12D3D4FD9D061727F9598E3DE7695189AC085CB8B454E01EC46FECFE7F9E222C138853AD9E65118D18CB2774E5915CBF0BD230E9305A26C17D0D6FCC37805E60C4805687558EA589C8B41CEEE95BCA682E32E3679210E34355D1D125CDC3D7F34FD944F8D0BE10EC31CAC3AEFB2F44AD5EA503C984C70B66BBF6BDCC7527CAE9D7533F1954587A99484FD1373B5FF17F4365D34F1CF30B88F',
            'd' => '70230C083EA9F8A8499AEE4392C07C8423C758ACD0F35BA89634EED5BAE55611CCDE3B6FF91D86059438BEEFB2252D571A522E222E02F0017E3313B27BC4B24F2E275E8414D93414EFAC42106E8FEA78D250B304D815EFEF185736DF7DB1DD33F8F7352E2C613798C4B9FA4F702EF65AA737AE8C59FAB9EEA3536564A2FB3493E427A764545558B3AE7B8645C6A914B8ABF85E1CC91813D22E188594CBD7BA8CFDECF5AFAD67184C014D0EC8E70942E959D6D2F449B2A5B961E1F97603A868BD47CEFD6D7EC05D23D03FD93243EC19D3BBBCFBF77B37F9BC058101EB2FB9C7446505B060AB3668238399A88975C063EB8A8CD9B152E2C0597B640186C5D9B4F00B9EFF91A343BFB7E39479B3C708322EAFD282E354DDCEF663BAEFA33E239A88BDEFDE0D7DC5288FC453C817EF201EABB51557DEC4CE873F0FDDDE0B87CC5EA62B44E72B14E13742316BEC034217FEBD728A59A3F823C448CDF3892C14777D501E40600D817145F903A748A575351F0D87FAB4BB3B939E5E8EC08575D9FC3EF6F332F8510CB992B637540427C60EE3808639A2821BB0912DBAC3F010F67759EA20005600C493566031085F57575A58D3798B187AD105598173FF739229CA290F29432DDAA99E9A69490EECAE379AC01E714F9E997F346BE52DA42D1671715E7DB836C32EB37A8749F2FC4C9917115F195E205747BAAC68C67F9B9C41FDBCFD91',
            'dP' => '2BE66D365291569847FF30473A0A330B879DC6323CAAEFAAA432B55260DF249F01987769C1D0FAEA78C8410A8CCAB05DDF3640232AA6C6F29A4FFA00D3B691517B58623A1BD3313FA4258478C8801BB05913B4C7066C33645ED226A14DD28DE1BE0DC6E4064DD88EDC7BE421D0070982731AC97A3077A120B4DA045ED6F86AAA7DF00CBBD1391DB1C8BA6FFFBFDD1BC0DF9A652585533082C7772759994897905790032EFAD4A4C4EF5A9B6F319699166ED00FA8425EF9620966298AA1C9E4EDF4631C40C05D6EF457B2145020DCB43465DC8D8AD5AD695A441393E904112E148B6B32E8A4C053B90027E3363066ED7FF0340AA02ACF9E571D0AAC80CD0447C1',
            'dQ' => '3B2CCC8217EC24F123E428758B2A5FCEB3DA96674BDEA03FCE3471473E785EAAED7354C79AE6E644A39A383A26B8099357F2F8EACF1D8267BE587DA30ECAD5BD565F1DD484C5027BD22710B40063F6EE8DCD72FD7EC2F4BCB70F3D5591E37E411D7DC02D3A9687ED4898F6CD9ECF299BB82FC9474CAF4A6F0F9B33F7542F628F31D368584BAD9CE742E8AAB71E79C9D60759C76151E02EC175507213CBF0A48FEA43B0712DB11761ACD09787D0E6B5382A25F7D0076D4CB70DCA7EE8034767ADD2B27D2F16BAE358255C3066D48D346DB30957DA2BB8E23B81F26C2886F03A15CC77F1FB9DDF59240FE8C6E5B351ACD67972A85ACF567F0A5CCAC9A1968CCB05',
            'e' => '10001',
            'p' => 'D36CFB9308B8FC6B211997126792149363A7C419F09889A9628706DE410B640C282C6A987AB570F0916F1A63E41B09576EB1E0DF8B6638298FC6971DE80F25061B939833BC396F92D6B5AA2EE6217D5FF53D83968F561EB67280A11984A9AECF9CF64F7F6BA4798AB4803CC2390E2D070281AA9C1AD2BAC6C5A8481B009687CE322A0A27FE967AB639B886BD0669917EC8AD770B2EF822200E5576280B7AAC56F8EEE50AA5EB393836C5F5A63F0490B990738E13E77441A30B240655FF7BAFC7E36CD2C5B167AE766AF9C121F5B4D870764F8723208337ADC75F1D9598A5E41D602A1BC3A4AA395D88851AE73C4BCFF8217C5DB0A3704B606228D081E8EB2B99',
            'q' => 'C620B139F1972C67CD6DD6A44310DBA126564BB9323880410F0B298F42686F289FA3F4BD0F484999A5384304FB737CD7081CE389C5268CA32033D7DE78DEEB0CE59D06246476A3990060B6D3855FF632A65C07FD8306ECD28FF7E57CBBB7B419940F8F250C6BE7ABE2AE5B0F88434819C31985BAC2F4F9EFA6FD9D361F016C16C302689FECD35B7BA472F4ABD0D30A399D123705D976C9B16CC299E96D363AF72B711CDCD8B72A980724F6EDC62C63E7D29117DAF397BD4DCC480BC04F4D04E84E79BBDAE87550D6CFCBF866CF5FD392220B490CF13576F1110DB52D442633EC1A05E429BEB2BEBAEEC5FE76855749D7F5075FAD0687BC00AD8AA36F4D105E67',
            'qP' => 'C27EB9DA8DE611220C7139C0C82B23D0F0767F48CC715F37DFE09FF7DF46FB0837D32F63170AD1484F3D0FCF1FE19780F6090C462B442F7E1C99A422CFB1FF1CD6CAC7EDD3E3F2166940E41120F2D5EC3EA0690E528BA5DF0F5A89B07CDE3DED92DDBF781E107CDC75939CFBB8AC5FAD10F61D11274147F690B00174EE86285D6D12A7468148572492C586CAEB8E24E935B9DCB3BF8F11BAAE94472338F69F64CCB3D911C29E40DCE3760CCEE7F604BB7C8F24E3E5FD60695305FB0ED152766386521596D5DDC00AE91214F1CA40B3FD9DC327ADD538CADC9F3C2D3730AEFBB8439BC14638F2838B7FC11CEAFAA4827C2D412AFC18A3F2D37572F8BF44F9A170',
    },
    ssh_rsa_768 => {
            'N' => 'D879B7864050A795088D444EEBF5411B8EBF8340C4DDC35647181DB0EB10FF0F329E9BCEFAD46742A6AB0BAC66B0D83EDA488A0FD41E52CFCEF46285561E7E80A3B1EF9B5ED5DCAC5F9F8074D463504CCE7E2F6EA6758B39889346BBF96D51D7',
            'd' => 'ABC13709BFB1BEA51299F31EA33C7E21FD4A9A3B2377C86A8611EE4CD6D52F69C181F2A17086623F91B998937B0EC922EFB82A5E4364D9EE3F8577B30511605BD7FEE7C3FBEE50B3890D9AEDFDB850625F7CB6B16F02BB24A3B238DC81BFAF01',
            'dP' => '33F7E8BF9E0C5FBF35A5DEE52AAD59E5FFA098BA878A8239E5B4904AB7F330ADD24065D62F35B00BEF54490B42B9408B',
            'dQ' => 'D302842FF78EC4E9172F3880CDAD75200619A4CFFC3EEC113499F393897E2B05C560499D4AC0572405707248B5F12BC1',
            'e' => '10001',
            'p' => 'EEEC625535BFFDE8C95F108EFA915E099E074C2EC4E185226CE8C78B0ED0705E0317C2C587107D9882E2E552C45E6097',
            'q' => 'E7F2999513312DC453489E98728D02F063851FCFA3A963146947B3E73CEE90ACB70FC8AF83B5DCEBDA0B7F61563D80C1',
            'qP' => '48D2A86459D33635373676A71AA5A4E255613E7E71E6C6941C426D1F80275FC81613E2E6C40EA7C3779F33C36DC52A2',
    },
    ssh_rsa_8192 => {
            'N' => 'A95F7BB6356731EE7E07A1EEFF018A8B22D611C1CB2D6D3BAF7B4C9367A1C77302ACE910A10A1BA74959DED9F93179CB8B76988064DADD8DAEEC431A8BD300E2FAF8D6B9C2E69748434368A93F2E3FF38F4399078D561D75A11A14900E87A48E684ABE4B4C91A95E29D3FC244C3F7954E2833B197C323AC947049B10CF7C708998230BD76C534E85AD92F16F2D27A01E4490660758853B4C0068815AE5FAAF1AAA2148962EA8516E101A579F40D6EFD729FF3F5C6493F243A4DEC1656ED75F571B01CD7DA7E32A56E31E908DF86E31CCA155397AF6385AA9AD7D6448A28BA701C942BA23AE7BFAAB60CA17C28EB826B31A5F5F67225EB98EB0EA7E30AD450B56ABA8BD0FFA531762F311180490B53DC55EACB485CA91CA63C84AC1AEF94A9511DD5D686418DD57A274CADF61923CEC6C0E446CCA3382ADF3254E472E3AE9C804ACE915617437D9BA1FA8E1FE60DD6ADBD0D6DEF6725813810235AEBB718784736E229386AEC612E427E5A563B23FD9D2AFAA798EF5B7B94D17591A68B6B8E243D672648CAAFF6EB3453DD268129FE27F2AD1670410F3B38810B27E78044C9952117FA8E97815FA60CD1EBE2B375045F5E5198D8B1474E53DB772267B01951B3795DD96DE58216CD362E1566C2EDD2CC83772696DB0AF76AD5A516CAB95F190663BFE5C91CC79564422006D2499803CFF696041769BE0E7802D22F449CAC3B59D975F0F46F534B8C3F281ADDE17ED5B2527FFAFD48A05B7E807EA82C2631E5CB69A9496E7795824792DB2B3DFAD00CD4F727F49FB4AA464E3539470C73E352524301227CCE4BA261BF306AF0E7E90919DA781A19514AA7F6E654770514A3488EABEE87D83C638249CF535A39C489FBF51ED707D3C9B377DD81BBA5970961695F17AB7FDA0B4966256432D497D9F176972519AA90CB2557C0558A29489EBB4FB083FBB662BCAB4352604EC025585621F3F4A8F725B2A977301642A92F47167F5B116D14EE2F3854232737D4C356C953753FE8F51C6284BDE2957C64F189A371F2AC44165B2CB0D5661701EF2C1EEC5FB3FC84C5E36717AF4DE90A2E4291FBFFC4110A7CAB08C70E538F5A6D6D40FB8A307B1B0DC8F1C97A853BA1CC10985F795D0E58AEAD04C972A528CCF3EF1F9AA1414A22469973354B4BFFF12E83D90FF73AB9C50F95CB3ACBAE6D361E4AA24DCC868B48DBC7BC6935B4946A738A908C345723C650F901992419777A31D433D7F570D300A42A26E117DC66ABCAD0D4DEB1BE0E84517B2B757C05BE837D8696EFA4ED25062D37FB06030792AE27F35D9DD76811DE942AE1F75928CF32AB11C258786B547D1F68F36DD4DE94E4E5B5FB42F10280BB8FE86E4BF0B73A57C548F225E157A49F11537D79CC21EA72EC5078A6A92E48BDDCA76EA43DAE3DFE6616954221E6AC5D67DE3AF19C4218D0859251D5301F9',
            'd' => '452530F922F61D21531C4494B0506DC1FD97CD2A038B6913BBC12772EA14D6BAF235AAF459FA296DF2F9188C7E3A1F91E43EA7658B46FAB9F3D68A529510B044F9D68ABACD819BF3295AA4A8AB9D730838CD8CF4D3537BB560EEA7C463DA2668E8D4D2B924EA366DB5BFD028F563D861BA137F161968DC2CFDAC38ADF536C52EB7085FB6338812FF69EC1A5A9BE19871A2E61C71154756FCE111C8F555FC306E3F545530D29D6E98F343FDCF8B05F4662FC3FF96F58C9C93D704058A2665108C1BFF7167C219705886621CFB88975C074139ECBC71367274E0D9D70DFC25ED294283D63FE8E4BE6226A27A6EB81B1FD97083CD0BEAB12729C4BA068852C4642B9EEAC53C77A26262C7FE8B82999D1439B63BE57AD5470D8C0CE1D00E61C17BF80E1A2B1AEA37BAA61CEE11A1E0B4B4842C92ECA2E3C28EC73BCCA82C8C6A9278AE2A7DCB0A4A1EBDE85CE6DE15A76F0F8C439C449A4BB0B2B3373D3D52CCD35AD8748F2BA5C0414819AD9C068667A0C26D6AB8338FC6D084536AD1E83BE8609EF7363E2C5B46EA678F75FCA6F62B85A90ACEF0326DC53FDEE58A292D4FFC017FCA9B065741EA1F0C53D1202BBE6A2C1585D117C2D6B81E3A42E0FC2AAD6BB4EFCD63E84A9F4A0E068250A21A8A4B4B13F5E6E4799E6F139113D537FB18BCC489A826609E390EB4141E9973F544216145983C6E9D4067E1BAA732A4EE5733ECB95E5DE229343087960003E9ADF8BB59760C852444F2037C2279049F346355DC4A7A8B84285CC507A8D37AC99B9A3EAAFE197A9B0E2B4BBA0FF89FE911C559608DC0E62B440CD6466F88A28D7CFB682356D067794DBE6F0F6605E0E546171D290E626704205F2E92C5801ECFA15C7C5767C63730C5F74D794E2D87DA8011E94636067B7D9BD8B90D834CF4B47C0F0534A37DF7FAE1516A9AC08C2726FC6DC639249469B4E2C2EA60E16D69B7E4055C2CAEA073EA1CBACCC93CD47BD4BB67D261AAC572516E284C1A11222ADA27C3807BCF0546BB084FD94C2C690B37EA1B0B05BF246AA17FF8B630AF0AF999D878EE9CCDD083154D34D15F3F54AF12E610CBE34B9B692A5140D91CE6C3A1B5DE21D7F28B4B3BCF4E34A06F0491E3525BE5FCC9177DF00BAB8B15F166164F482CD2B04098464EB42C1F5C15CFBE7119F4C2D02421E69F955F06C80452741E5BE98F36BDD51F4A1130A29F8DAF94E8A992F887F2C2486339D1FE807652ED1D010781C580F1C1FA527DF804AA8F5D09E1320E37FB93E8F87E4C9E1F1F80AEBDBFBCF6C0B4066429DA3C4B6ED03596C1096D2F56BEEFDFD65267B19E21AEA347871A5F4C749C4B3AC1E336A57C0AF37DB66A240CB32F44C42B9CAB5EF294832042339F703CEEE241DDB9002B198E210394DF7357290B049EBF46814411FDCA93A1F12D5234B32AFDFA7A1C5409EA7431D2082504C4B1',
            'dP' => '50EF253FB29B957F25875D04BA6C203D1A0B4FB5AD2E3C1764BA5B0EB675E1281BF14C2412BA23840ABB33856173BA9609D9069E0D0E8839B0BA5389B44AA782C351446BB4987415351B16A342D26FD77D9B17480E4F90ACE82F90D068FCCA4F107EF31FA35698BFAAF86C3819BDCE46968C0C3A7B91D2C4C749013D0349B5AA9EB44E20AC66746A427FB42501F968CD469D5D812F744DD05B7D6C28625B9642EB039C02568AC2A0E62266104F7DA1CC4EB0818B0126A3F211CDC50C30A7AF8779121AE1373A736EBB771BF83174F905EBCDAFB340786644A1BC1727368EB9BDF167E490D933610C0CF59B79D91C21B73991B591F47617E5CE20E63AAE050CD020C37FDB66B527EF5355F3866353BA612965978FC6ACA45342D53E714E59EE2811C9A99571E5AE3D30A7D10D97F8DA5D117CC813EB71FCC2F01A5AB80D2BA050F2A0208A61A47BEA69DD25683701C188539782BF1FDFB7B59AEBCB4B2BF7E90504F11EE022530A504567C54F797BC0E026B6B812DFACE2287AEB8F9CA3211118E333DCAFD3DA51B7B787E49A4FE272585D5EE46AADE1CC0B655DF0C469EE61DCDDB9435DB8FC3D7E1FC27E91F7454AE1706F6D6597303362CDA03BB8DE70CDA9FCBDCB8C875FF318CD2DD1D053F3D9D45BA9A956A26796AAB463DA2140815632127FADEF69AE08CCE9C5E8A8EC73ABC06A12B53B6BCC4D574F3A0AEEF45F0DF1',
            'dQ' => 'C4F6989E69D3BAB693DB0AA31BB98E26F4235B7AFB545829F52FF33D492969239D5A540FF899A0843C566A8F59B31F41487BDC55F550E58EFCB1382CFE423A8410D2CD19F4D26E9EE098AE87576505F344C85D332F2F6EF04C77B2D9D5C3A9B09D5E2C0B0DEFF9291A03B309ADD98A650C8C19C02A2E15928117068C286E7F3AFD369C107E1C492A30DD86861887EC31683C4A959216FA54B3F1F5A5BEAF84D748A37922A9963B224317FFB324C90ADFF6595CFE827CDDEACE7AF4924D8C10367F09388699420DEA07D3802C32073AE22F72C54011A6457D3A644870C3115DF1733C42CB7ECD50F2541E12A7744D28E8D69135211ECAA5EF9CB94DD30B8A179A977BB35B7AD9F4276DD0C444B294C01FB5F2AC860553C8D0D7384DBFAD210AA849310B8F509A4CFE83C9BCE184C5856F1705E1080543958260838F859AB8F49AA4A2CC53B1CFC191A5A5CA5B7A9DBF1F801378FDBFB8D4626F4EB6E9F6FC83EED33A192A23126CE85E3D69CD17BCFFF45E98F9E02E8A7448E9E3BF33C11C695B6E30F3566BAE13D3E18BE6AE52B261D2C7EA90DEEF63F34FF5114AD9B02890DA74C8902BE23F69F07D861A1ABE16E7BB484012715886738C8B4EE263372EAAB4C85641E766E89D72BEAC181CEF5FFB7E4DE11E1FCD3FCDEAEBB0EAA501C415159922145F3AEBA80FDFFEEF9D9E78E922EBD8DB53482F527AC582605DEFDF9945',
            'e' => '10001',
            'p' => 'D3FF688EABC3AC9E4177E6E99B68D78916B806E2C97BE65AF2E157E1BAB759A6AAC34E445641A11CAC0CEA460957BF993C70A2F6806510013CD16D7096D213DD3DA302B60E0A282AA88A9E35386A46403ACC46EB0FC0CC45D4A9B1D424F83774777CBE0D3EA43DF2346347FF1427DD02DF9257E58F15B7229AC3A33D11A067583E32CC9AF9F98AB5B4B6C46ACD0784A1BD11ED677952D988FF331D5288FBB57F41826CD8730EC96648F753508F8D40CEC4FDC05A651B6EB72AD964D2EA639E6BBA07D10CAB08170362BC42756F5585BD2C9B50598CF32D46AE707A29263EF2FDF1E61CFBECE3A9108E1DCCABF0FFFCEC82E51A1BB0075464167F2A2698D1D275C38BEFC81424545B2335E3B905382B6ED42776B3FAE36C2B74C5484DBA9ED808D6F7B9EC63F9F1B46FDD4FA8ABF5DFBA6196EA3164F235AA4428382D43B0BD366C240C62BD2778462068EE16792A3396F383F9312E31ED4F4D924BF34E146ECCB2817377F85691535DAED3FED7795F9AE7CCE90E5CE7031FDA397CDEFFEF8235A8A0C2D9FBEDE2A2936A7E7CDFC1D039C95046D1FAF887AFA22065323ECF9F3308350D895B005A4F49F63E026EFCB4F7A4D2ABDD2D48AC16C4129842BBCA974BB2F90120F9F299E4E8B2C28C9A6B9DB1E2980E14FE38D16845E394D2A37D6DC2C7A93D185908168A4752FC04A2DB0B75E3A0E0C0DC1A9D478BF1B29369B1DA45',
            'q' => 'CC8731273CD2D3FECF4DB70DB94110B5A9B3819E26AF7A5D7804DE8348FE93D6479DC7C83493367656EB54402FC6AA4A2BC1472A63DE15E0F67D2FBD0CC3028311E53EB1206609325AD1207A6CA6BB705F51D1604277B94A7B5DA28F2151DD49BBF09BBB32C8B09886D0CF68769DE8D551FC1F9B6BF9336611BB5BF69A067AFFA61EE7CAFC67C14D0A33428E927A695440DFB84B2C2B9D38C27F8EE956DA4FD03948F33C52AB587AF1E1A1594889BF6BC64B248EE3EA918F606F82792AF3E84E4C5428174610D04FB846ACEE773E09113C784B432FCFDFA11DD2C8E04E897822E363ECCE141908B0E76EE13B4F504E4B079F2F5B8F873DC3DB6AA912985D3DA738D10D7DE09E6A624A452695A95F89F7499C16D4C9DC631252738878A8E75DA07DE0BEEF89567F477E7631584C61FDAC9911BF04DD5688CED39ABDA202A59CD2E97D62B7D832BB8E99EA37D7D0A0DC41F369D7DB45114AC5FB913173BC51E613FE65C17EA1C9DD9B43B3909810D1445F8289DF6AC3EF1F1275E6926B563D69BB96054DBA0AE17BAB795954BB311E9D47CC4BFBF7521D13EB71D399AE8E25A7667032F7577F93CC1056155BC88F778A3FB0CDC651780F235A9D844CE5EDCFBB069EB31B76984B769AF09A194E8DFEE24E3BD7D3C6559392EE68170855D0A2CBAF889DBA60550FFD522CD524FDAB042C1937A99D8E62258C0A8FF5B46F17B6FE25',
            'qP' => 'BE0A7246BF680218C49D95ED8DB7099104F755E96CB3C11D440EC441C6E56A55D3931CCF2FB30C7219AFF0EA5ECCC63FBBD5F4AD8F9A997762876CD74B127A8E6090DB331367E63FE7B845577FE73D33B261BD1D8A902CAA329CC3851A69C51D3463FBF53C5430242B894C7F83F20793D25B47C6E8B06596F8D8A6D83A63F3F340682EA868B9B40C27C0B7247CECF04467A7ACD0A1E8F732D4DFABB8866A1D008DD79E6CA3ADE343BD02ECAC09AAD952529FA4CF60F1480E4170581D7D52E07250D0881C49A5D53D6C5CEA8BF51786DF70990AAB5A267D2D3C393564E7F2C886262B939B98E3A7DD8BE05756080F416539B6B9E7581FB369A49049C714D73033C92BF277216F8EE516CDB5BB88DF79A5953DF395FD99C0A4BC67312ED14FF433AE6B71207B4798022EDD8800A29C6E163D0F6130BA8DBBD653C0AAFABB8FCE2E2A1F198DB2B08F084CA116EDB74EF8E712F0BBE218B65508E7BBDD1FC4B81359C6F3AD841B71B9D657738803C5FC91264EDD10B64C7F3C2C44B1493B306F64C9B67B5B3BE42BF8F682ECCFDF0432EA2AD33B85961503595EFF6AF6A053D20BABB371B3A179BC1F73AD7FB6DB4A431EF321B7D0AC82AEC758393EB1AC137A3CE74E6DA90980D83244CDE608A763433BC299B6849CA252D059716EC1353063AD068AD25C4B2F5D6FC34AE45E4B2B275510CD911BBB639634A06030410E09E4F7E3',
    },
  };
  my $kh = $K->key2hash;
  $kh->{$_} =~ s/^0+// for (qw/N d dP dQ e p q qP/); #strip leading zeroes
  is($kh->{e}, $R->{$name}{e}, "$name/$nick/e");
  is($kh->{N}, $R->{$name}{N}, "$name/$nick/N");
  if ($private) {
    ok($K->is_private, "$name/$nick/is_private");
    is($kh->{d} , $R->{$name}{d} , "$name/$nick/d");
    is($kh->{p} , $R->{$name}{p} , "$name/$nick/p");
    is($kh->{q} , $R->{$name}{q} , "$name/$nick/q");
    is($kh->{qP}, $R->{$name}{qP}, "$name/$nick/qP");
    is($kh->{dP}, $R->{$name}{dP}, "$name/$nick/dP");
    is($kh->{dQ}, $R->{$name}{dQ}, "$name/$nick/dQ");
  }
  else {
    ok(!$K->is_private, "$name/$nick/is_not_private");
  }
};

for my $f (qw/ssh_rsa_1024 ssh_rsa_1536 ssh_rsa_2048 ssh_rsa_4096 ssh_rsa_768 ssh_rsa_8192/) {
  #diag "$dir/${f}_pkcs8";
  $rsa->import_key("$dir/${f}_pkcs8");
  _check_rsa($rsa, $f, "${f}_pkcs8", 1);
  #diag "$dir/${f}_pkcs8_pw";
  $rsa->import_key("$dir/${f}_pkcs8_pw", "secret");
  _check_rsa($rsa, $f, "${f}_pkcs8_pw", 1);
  #diag "$dir/${f}_pkcs8.pub";
  $rsa->import_key("$dir/${f}_pkcs8.pub");
  _check_rsa($rsa, $f, "${f}_pkcs8.pub", 0);
  ##
  #diag "$dir/${f}_pem";
  $rsa->import_key("$dir/${f}_pem");
  _check_rsa($rsa, $f, "${f}_pem", 1);
  #diag "$dir/${f}_pem_pw";
  $rsa->import_key("$dir/${f}_pem_pw", "secret");
  _check_rsa($rsa, $f, "${f}_pem_pw", 1);
  #diag "$dir/${f}_pem.pub";
  $rsa->import_key("$dir/${f}_pem.pub");
  _check_rsa($rsa, $f, "${f}_pem.pub", 0);
  ##
  #diag "$dir/${f}_openssh";
  $rsa->import_key("$dir/${f}_openssh");
  _check_rsa($rsa, $f, "${f}_openssh", 1);
  #diag "$dir/${f}_openssh_pw";
  $rsa->import_key("$dir/${f}_openssh_pw", "secret");
  _check_rsa($rsa, $f, "${f}_openssh_pw", 1);
  #diag "$dir/${f}_openssh.pub";
  $rsa->import_key("$dir/${f}_openssh.pub");
  _check_rsa($rsa, $f, "${f}_openssh.pub", 0);
  ##
  $rsa->import_key("$dir/${f}_rfc4716.pub");
  _check_rsa($rsa, $f, "${f}_rfc4716.pub", 0);
}

sub _check_ecc {
  my ($K, $name, $nick, $private) = @_;
  my $E = {
    ssh_ecdsa_256 => {
      curve_A        => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
      curve_B        => '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
      curve_Gx       => '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
      curve_Gy       => '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
      curve_cofactor => 1,
      curve_order    => 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
      curve_prime    => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
      pub_x          => '8E102175FA320D0D583E8EBD6A9BFCBF3CB13B39EA1AACE6C5E4021EAFAFD365',
      pub_y          => '7857336A28C25329FFF6A2F3FC27D6835A6A8F72A03A2159E01C93DF161F248B',
      k              => '6B0288C07B3793976145721D1E003EF42EA569B8931BF33E5DE8EBB0BE25AA23',
    },
    ssh_ecdsa_384 => {
      curve_A        => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
      curve_B        => 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
      curve_Gx       => 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
      curve_Gy       => '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
      curve_cofactor => 1,
      curve_order    => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
      curve_prime    => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
      pub_x          => '9642172A80894DA890979F39DCA786930621A91B5E4926CB06D4CE5E237C074251A420FA514356B3B919293836511177',
      pub_y          => 'C885A93FBEFDFBF276C09CDA0913AF61FB1C22D56E211ECCF8AA5C1AB475C93307298AD8B08733D06426DB8E9B886634',
      k              => 'F775C2D8302B016D6C4B6044326C62CB33A794B55DC0370932B3AA88C5DDFD64120939743A461E77C48BAED57F07165C',
    },
    ssh_ecdsa_521 => {
      curve_A        => '1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC',
      curve_B        => '51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
      curve_Gx       => 'C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
      curve_Gy       => '11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650',
      curve_cofactor => 1,
      curve_order    => '1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
      curve_prime    => '1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
      pub_x          => '164DF9B2BB5E3FDB700B060ABD4F68BCC062EFB0DDEA51013EB15A3046F4099759E4C0B79D2A9F9461D15A449B5298DD3DD3BB71840DA4AF585C76CD48EE616D4D6',
      pub_y          => '159832886171C09618CFC3408DE7415CC8321F8256A652B91509B93F972F6A0948B42F6A90A8A851784273AED831806D8AF5E551ED0F808ABA91B1D3A9B5FAFB937',
      k              => 'DE25E7EFC05FCB26B854A24ED7BCA80859C6760685EAD9E6D72920C2E06C981252E18CBB73E1E231A7493248A0EABF0D11ADE94957B76A6E222DB9E0025C7E6E0E',
    },
  };
  my $kh = $K->key2hash;
  $kh->{$_} =~ s/^0+// for (qw/curve_A curve_B curve_Gx curve_Gy curve_order curve_prime pub_x pub_y k/); #strip leading zeroes
  is($kh->{curve_A}, $E->{$name}{curve_A}, "$name/$nick/curve_A");
  is($kh->{curve_B}, $E->{$name}{curve_B}, "$name/$nick/curve_B");
  is($kh->{curve_Gx}, $E->{$name}{curve_Gx}, "$name/$nick/curve_Gx");
  is($kh->{curve_Gy}, $E->{$name}{curve_Gy}, "$name/$nick/curve_Gy");
  is($kh->{curve_cofactor}, $E->{$name}{curve_cofactor}, "$name/$nick/curve_cofactor");
  is($kh->{curve_order}, $E->{$name}{curve_order}, "$name/$nick/curve_order");
  is($kh->{curve_prime}, $E->{$name}{curve_prime}, "$name/$nick/curve_prime");
  is($kh->{pub_x}, $E->{$name}{pub_x}, "$name/$nick/pub_x");
  is($kh->{pub_y}, $E->{$name}{pub_y}, "$name/$nick/pub_y");
  if ($private) {
    ok($K->is_private, "$name/$nick/is_private");
    is($kh->{k}, $E->{$name}{k}, "$name/$nick/k");
  }
  else {
    ok(!$K->is_private, "$name/$nick/is_not_private");
  }
}

for my $f (qw/ssh_ecdsa_256 ssh_ecdsa_384 ssh_ecdsa_521/) {
  #diag "$dir/${f}_pkcs8";
  $ec->import_key("$dir/${f}_pkcs8");
  _check_ecc($ec, $f, "${f}_pkcs8", 1);
  #diag "$dir/${f}_pkcs8_pw";
  $ec->import_key("$dir/${f}_pkcs8_pw", "secret");
  _check_ecc($ec, $f, "${f}_pkcs8_pw", 1);
  #diag "$dir/${f}_pkcs8.pub";
  $ec->import_key("$dir/${f}_pkcs8.pub");
  _check_ecc($ec, $f, "${f}_pkcs8.pub", 0);
  ##
  #diag "$dir/${f}_pem";
  $ec->import_key("$dir/${f}_pem");
  _check_ecc($ec, $f, "${f}_pem", 1);
  #diag "$dir/${f}_pem_pw";
  $ec->import_key("$dir/${f}_pem_pw", "secret");
  _check_ecc($ec, $f, "${f}_pem_pw", 1);
  ##
  #diag "$dir/${f}_openssh";
  $ec->import_key("$dir/${f}_openssh");
  _check_ecc($ec, $f, "${f}_openssh", 1);
  #diag "$dir/${f}_openssh_pw";
  $ec->import_key("$dir/${f}_openssh_pw", "secret");
  _check_ecc($ec, $f, "${f}_openssh_pw", 1);
  #diag "$dir/${f}_openssh.pub";
  $ec->import_key("$dir/${f}_openssh.pub");
  _check_ecc($ec, $f, "${f}_openssh.pub", 0);
  ##
  $ec->import_key("$dir/${f}_rfc4716.pub");
  _check_ecc($ec, $f, "${f}_rfc4716.pub", 0);
}

sub _check_dsa {
  my ($K, $name, $nick, $private) = @_;
  my $E = {
    ssh_dsa_1024 => {
      'g' => '90F53CC0A24C241AD71C83FCD09639A8C2B9F4CE233280866EA5FA794154F88A23EDBAD97A58B75DBB29EE263CBF172418B3A138D240DD3CB87320FFC2FA5BF71D3B6699FA68640674B5C409BCDC3030A8BAC3ADA475C3FE10445C6BE556F2CBCAA77A3ACF8D32686C1375046B2FF38C079239A80A7EA91487E41987804E526',
      'q' => 'A1A6E6CB1D58B03C1FA34AF51BF1EE131D2ECF05',
      'p' => 'A53CFDABE69057869D2AB0606EDD6674251BED3540D6B1BB7179BF435C2FF491516EC876952AF2DD78B222B4980EB28E984B84E7F9B7C82E81311506594FF3A00D49B162807ED6377BFAC9D256AA6EB4A4D84D1CDFFFE7472736D22C5DBC5EAB756DB08EB8A641F5389A9E6431CB9AEEF79384F410A3B3B329527C5FF0B55049',
      'x' => '98C1BD9D96FD64B6AAC85814CEF879FE089E3044',
      'y' => '760F535CCC5414C35ABBBB48D0B81B653258659860B8CBCAD0551DF42605AE750A6AAB4ACDA409F18B180D729DF60436CC5C26AF67B17ADBE22D7B1F9047245907D20EC1503A5E05E2EBF20B0ADD681FA96C2D66C0E496D39BC3D721503FEC88AEAAFDD93F7D2201D87A348A77AFEE4EBC679664348E173B0B84B2C015866C0',
    }
  };
  my $kh = $K->key2hash;
  $kh->{$_} =~ s/^0+// for (qw/g p q x y/); #strip leading zeroes
  is($kh->{g}, $E->{$name}{g}, "$name/$nick/g");
  is($kh->{q}, $E->{$name}{q}, "$name/$nick/q");
  is($kh->{p}, $E->{$name}{p}, "$name/$nick/p");
  if ($private) {
    ok($K->is_private, "$name/$nick/is_private");
    is($kh->{x}, $E->{$name}{x}, "$name/$nick/x");
    is($kh->{y}, $E->{$name}{y}, "$name/$nick/y");
  }
  else {
    ok(!$K->is_private, "$name/$nick/is_not_private");
  }
}

{
  my $f = "ssh_dsa_1024";
  ##
  #diag "$dir/${f}_pkcs8";
  $dsa->import_key("$dir/${f}_pkcs8");
  _check_dsa($dsa, $f, "${f}_pkcs8", 1);
  #diag "$dir/${f}_pkcs8_pw";
  $dsa->import_key("$dir/${f}_pkcs8_pw", "secret");
  _check_dsa($dsa, $f, "${f}_pkcs8_pw", 1);
  #diag "$dir/${f}_pkcs8.pub";
  $dsa->import_key("$dir/${f}_pkcs8.pub");
  _check_dsa($dsa, $f, "${f}_pkcs8.pub", 0);
  ##
  #diag "$dir/${f}_pem";
  $dsa->import_key("$dir/${f}_pem");
  _check_dsa($dsa, $f, "${f}_pem", 1);
  #diag "$dir/${f}_pem_pw";
  $dsa->import_key("$dir/${f}_pem_pw", "secret");
  _check_dsa($dsa, $f, "${f}_pem_pw", 1);
  ##
  #diag "$dir/${f}_openssh";
  $dsa->import_key("$dir/${f}_openssh");
  _check_dsa($dsa, $f, "${f}_openssh", 1);
  #diag "$dir/${f}_openssh_pw";
  $dsa->import_key("$dir/${f}_openssh_pw", "secret");
  _check_dsa($dsa, $f, "${f}_openssh_pw", 1);
  #diag "$dir/${f}_openssh.pub";
  $dsa->import_key("$dir/${f}_openssh.pub");
  _check_dsa($dsa, $f, "${f}_openssh.pub", 0);
  ##
  $dsa->import_key("$dir/${f}_rfc4716.pub");
  _check_dsa($dsa, $f, "${f}_rfc4716.pub", 0);
}

sub _check_ed {
  my ($K, $name, $nick, $private) = @_;
  my $E = {
    ssh_ed25519 => {
      'curve' => 'ed25519',
      'priv' => 'd5bcfa901e39d1ce557f7b692af91e5e818d76c42230f66248b955819b4e5904',
      'pub' => 'bd17b2215c443a7a1e9b286a4f0e76288130984cd942acccd4f1a064bb749fbe'
    }
  };
  my $kh = $K->key2hash;
  is($kh->{curve}, $E->{$name}{curve}, "$name/$nick/curve");
  is($kh->{pub}, $E->{$name}{pub}, "$name/$nick/pub");
  if ($private) {
    ok($K->is_private, "$name/$nick/is_private");
    is($kh->{priv}, $E->{$name}{priv}, "$name/$nick/priv");
  }
  else {
    ok(!$K->is_private, "$name/$nick/is_not_private");
  }
}

{
  my $f = "ssh_ed25519";
  ##
  #diag "$dir/${f}_openssh";
  $ed->import_key("$dir/${f}_openssh");
  _check_ed($ed, $f, "${f}_openssh", 1);
  #diag "$dir/${f}_openssh_pw";
  $ed->import_key("$dir/${f}_openssh_pw", "secret");
  my $kh_priv = $ed->key2hash;
  _check_ed($ed, $f, "${f}_openssh_pw", 1);
  #diag "$dir/${f}_openssh.pub";
  $ed->import_key("$dir/${f}_openssh.pub");
  my $kh_pub = $ed->key2hash;
  _check_ed($ed, $f, "${f}_openssh.pub", 0);
  ##
  $ed->import_key("$dir/${f}_rfc4716.pub");
  _check_ed($ed, $f, "${f}_rfc4716.pub", 0);
  ##
  $ed->import_key($kh_priv);
  _check_ed($ed, $f, "keyhash.priv", 1);
  $ed->import_key($kh_pub);
  _check_ed($ed, $f, "keyhash.pub", 0);
}
