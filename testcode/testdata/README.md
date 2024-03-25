
## create rsa key and  cert

### create rsassa-pss cert
openssl req -x509 -outform DER -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -days 3650 \
  -nodes -keyout rsassa-pss.key -out rsassa-pss.crt -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:*.example.com,IP:10.0.0.1"

## create rsa pkcs8
openssl genpkey  -out rsakey_pkcs8.pem -algorithm RSA -pkeyopt rsa_keygen_bits:2048

### get pkcs8 pubkey from privete key
openssl rsa -in rsakey_pkcs8.pem -outform DER -pubout -out rsapub.der

### get pkcs1 pubkey from private key
openssl rsa -in rsakey_pkcs8.pem -RSAPublicKey_out -outform DER  -out rsapub_pkcs1.der

### transfer PEM to DER
openssl pkcs8 -in rsakey_pkcs8.pem -nocrypt -topk8 -out rsakey_pkcs8.der -outform DER

### create pkcs1 from pkcs8
openssl pkcs8 -in rsakey_pkcs8.pem -nocrypt -out rsakey_pkcs1.der -outform DER  

### sign using rsa private key, to verify the result rsa-pkcsv15
openssl pkeyutl -sign -inkey rsakey_pkcs8.pem  -rawin -in <(printf "00010203040506070809" | xxd -r -p) -hexdump


## create ecdsa key and cert

### create ecdsa-nistp384 
openssl ecparam -genkey -name secp384r1 -noout -out secp384r1.pem
### or create a ec pkcs8
openssl genpkey -out prime256v1_pkcs8.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256

### convert pkcs1 to pkcs8
openssl pkcs8 -topk8 -inform PEM -outform DER -in secp384r1.pem -out secp384r1_pkcs8.DER -nocrypt

### get ec pubkey 
openssl ec -in secp384r1.pem -pubout -outform DER -out secp384r1pub.der

### sign using ec private key
openssl pkeyutl -sign -inkey secp384r1.pem  -digest sha256 -rawin -in <(printf "00010203040506070809" | xxd -r -p) -hexdump


## convert unencrypted pkcs8 to a encrypted pkcs8
openssl pkcs8 -in prime256v1_pkcs8.der -inform DER -topk8 -outform DER -out prime256v1_pkcs8_enc.der 