for I in 1 2 3
do
  for C in 512 1024 1536 2048 3072 4096
#  for C in 512
  do

echo "processing $C"
PREF="key_$C-$I"
openssl dsaparam -genkey -out "$PREF.key.pem" $C
openssl dsa -in "$PREF.key.pem" -out "$PREF.pri.pem"
openssl dsa -in "$PREF.key.pem" -pubout -out "$PREF.pub.pem"
openssl dsa -in "$PREF.key.pem" -out "$PREF.pri.der" -outform der
openssl dsa -in "$PREF.key.pem" -pubout -out "$PREF.pub.der" -outform der
echo -n 'test-data' | openssl dgst -sha1   -sign "$PREF.pri.pem" -out "$PREF.dsa-sha1.sig"
echo -n 'test-data' | openssl dgst -sha256 -sign "$PREF.pri.pem" -out "$PREF.dsa-sha256.sig"
HEX_DSA_SHA1=`perl -00 -pe '$_ = unpack("H*", $_)' < "$PREF.dsa-sha1.sig"`
HEX_DSA_SHA256=`perl -00 -pe '$_ = unpack("H*", $_)' < "$PREF.dsa-sha256.sig"`
HEX_PRI=`openssl dsa -in "$PREF.pri.pem" -inform PEM -text | perl -00 -pe 's/[\n\r] +//sg' | grep "^priv:" | perl -00 -pe 's/[\n\r\s:priv]//sg'`
HEX_PUB=`openssl dsa -in "$PREF.pri.pem" -inform PEM -text | perl -00 -pe 's/[\n\r] +//sg' | grep "^pub:"  | perl -pe 's/^pub://'| perl -00 -pe 's/[\n\r\s:]//sg'`
HEX_PRI_DER=`perl -00 -pe '$_ = unpack("H*", $_)' < "$PREF.pri.der"`
HEX_PUB_DER=`perl -00 -pe '$_ = unpack("H*", $_)' < "$PREF.pub.der"`
echo "  {SIZE=>$C,PRI_FILE=>'$PREF.pri.pem',PUB_FILE=>'$PREF.pub.pem',PRI=>'$HEX_PRI',PUB=>'$HEX_PUB',DSA_SHA1=>'$HEX_DSA_SHA1',DSA_SHA256=>'$HEX_DSA_SHA256',PRI_DER=>'$HEX_PRI_DER',PUB_DER=>'$HEX_PUB_DER'}," >> tmp.txt
rm "$PREF.key.pem"

  done
done


