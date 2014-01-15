for I in 1 2 3
do
  for C in secp112r1 secp112r2 secp128r1 secp128r2 secp160k1 secp160r1 secp160r2 secp192k1 secp224k1 secp224r1 secp256k1 secp384r1 secp521r1 prime192v1 prime192v2 prime192v3 prime239v1 prime239v2 prime239v3 prime256v1
  do

echo "processing $C"
PREF="key_$C-$I"
openssl ecparam -param_enc explicit -name "$C" -genkey -out "$PREF.key.pem"
openssl ec -in "$PREF.key.pem" -param_enc explicit -out "$PREF.pri.pem"
openssl ec -in "$PREF.key.pem" -param_enc explicit -conv_form compressed -out "$PREF.pric.pem"
openssl ec -in "$PREF.key.pem" -pubout -param_enc explicit -out "$PREF.pub.pem"
openssl ec -in "$PREF.key.pem" -pubout -param_enc explicit -conv_form compressed -out "$PREF.pubc.pem"
echo -n 'test-data' | openssl dgst -sha1   -sign "$PREF.pri.pem" -out "$PREF.ecdsa-sha1.sig"
echo -n 'test-data' | openssl dgst -sha256 -sign "$PREF.pri.pem" -out "$PREF.ecdsa-sha256.sig"
HEX_ECDSA_SHA1=`cat "$PREF.ecdsa-sha1.sig" | perl -00pe '$_ = unpack("H*", $_)'`
HEX_ECDSA_SHA256=`cat "$PREF.ecdsa-sha256.sig" | perl -00pe '$_ = unpack("H*", $_)'`
HEX_PRI=`openssl ec -in "$PREF.pri.pem" -inform PEM -text | perl -00pe 's/[\n\r] +//sg' | grep "^priv:" | perl -00pe 's/[\n\r\s:priv]//sg'`
HEX_PUB=`openssl ec -in "$PREF.pri.pem" -inform PEM -text | perl -00pe 's/[\n\r] +//sg' | grep "^pub:"  | perl -pe 's/^pub://'| perl -00pe 's/[\n\r\s:]//sg'`
HEX_PUBC=`openssl ec -in "$PREF.pric.pem" -inform PEM -text | perl -00pe 's/[\n\r] +//sg' | grep "^pub:"  | perl -pe 's/^pub://'| perl -00pe 's/[\n\r\s:]//sg'`
echo "  {CURVE=>'$C',PRI_FILE=>'$PREF.pri.pem',PUB_FILE=>'$PREF.pub.pem',PRI=>'$HEX_PRI',PUB=>'$HEX_PUB',PUBC=>'$HEX_PUBC',ECDSA_SHA1=>'$HEX_ECDSA_SHA1',ECDSA_SHA256=>'$HEX_ECDSA_SHA256'}," >> tmp.txt
rm "$PREF.key.pem" "$PREF.pric.pem" "$PREF.pubc.pem"

  done
done
