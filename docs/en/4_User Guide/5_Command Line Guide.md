# 1 Overview

The openHiTLS command source code is located in the apps directory, and the compiled result is hitls. Users can run the hitls command to perform various cryptographic operations. This tool provides a complete cryptographic function suite, including random number generation, symmetric/asymmetric encryption, digital signatures, PKI certificate management, and SSL/TLS connections.

## 1.1 Supported Command List
|Command Category|Command Name|Description|
|-|-|-|
|**Basic Commands**| | |
||help|Display help information and list of supported commands|
||list|List supported algorithms and functions, including digest, symmetric, asymmetric, MAC, random number, KDF algorithms, etc.|
|**Encryption and Digest**|| |
||enc|Symmetric encryption and decryption operations, supporting multiple symmetric algorithms|
||mac|Message authentication code calculation and verification|
||dgst|Message digest calculation and digital signature operations|
||kdf|Key derivation function, derive keys from input materials|
|**Key and Parameter Management**|| |
||rsa|RSA key processing, including format conversion and information display|
||genrsa|Generate RSA private keys|
||genpkey|Generate various types of public and private keys|
||pkey|Public and private key processing tool|
||pkeyutl|Use keys for encryption, decryption, signing, verification and other operations|
||keymgmt|Key management functions, including key creation, deletion, querying, etc. (SM mode)|
|**PKI Certificate Management**|| |
||pkcs12|Processing of PKCS#12 format certificates and key packages|
||x509|Generation, parsing, conversion and verification of X.509 certificates|
||crl|Generation and management of certificate revocation lists|
||verify|Certificate chain verification and trust relationship checking|
||req|Generation and processing of certificate signing requests|
|**SSL/TLS Communication**|| |
||s_client|SSL/TLS client tool|
||s_server|SSL/TLS server tool|
|**Other Utility Tools**|| |
||rand|Generate random numbers of specified length, supporting hexadecimal and Base64 encoded output|
||prime|Generate and test primes, support hexadecimal input/output|

## 1.2 Command Usage

```bash
hitls <command> [options]
```

Where `<command>` is the specific functional command, and `[options]` are the parameter options for that command. Each command supports the `-help` option to view detailed usage instructions.

# 2 Options

## 2.1 Provider Options

- `-provider <name>`: Specify the Provider name, which can also be the Provider path. The command line loads and initializes the Provider identified by this name.
- `-provider-path`: Specify the Provider search path, used in conjunction with `-provider <name>`. This path is prepended to the name.
- `-provider-attr`: Specify the attribute query clause to be used when the Provider obtains algorithms. For more detailed description, please refer to [Provider Development Guide](../5_Developer%20Guide/4_provider%20Development%20Guide.md).

# 3 Commands

## 3.1 Basic Commands

### 3.1.1 help

**Function**: Display help information for all supported commands or specific commands

**Usage**:

```
hitls help [command name]
```

**Parameters**:
- No parameters: Display list of all supported commands
- Command name: Display detailed help information for specific command

**Examples**:

```bash
hitls help                # Display all supported commands
hitls help rand           # Display help information for rand command
```

### 3.1.2 list

**Function**: List supported algorithms and functions, including digest, symmetric, asymmetric, MAC, random number, KDF algorithms, etc.

**Usage**:
```
hitls list [-help] [-all-algorithms] [-digest-algorithms] [-cipher-algorithms] [-asym-algorithms] [-mac-algorithms] [-rand-algorithms] [-kdf-algorithms] [-all-curves]
```

**Supported Options**:
- `-help`: Display help information
- `-all-algorithms`: List all supported algorithms
- `-digest-algorithms`: List all supported digest algorithms
- `-cipher-algorithms`: List all supported symmetric algorithms
- `-asym-algorithms`: List all supported asymmetric algorithms
- `-mac-algorithms`: List all supported MAC algorithms
- `-rand-algorithms`: List all supported random number algorithms
- `-kdf-algorithms`: List all supported KDF algorithms
- `-all-curves`: List all supported curves

**Examples**:
```bash
hitls list -all-algorithms
hitls list -cipher-algorithms
hitls list -all-curves
```

## 3.2 Encryption and Digest

### 3.2.1 enc

**Function**: Symmetric encryption and decryption operations, supporting multiple symmetric algorithms

**Usage**:

```
hitls enc -cipher <algorithm> {-enc|-dec} [-in <file>] [-out <file>] [-pass <password source>] [-md <algorithm>] [-provider name] [-provider-path path] [-provider-attr attr]
```

**Supported Options**:

- `-help`: Display help information
- `-cipher <algorithm>`: Required. Specify the encryption algorithm
- `-enc`: Must choose one of `-enc` or `-dec`. Perform encryption
- `-dec`: Must choose one of `-enc` or `-dec`. Perform decryption
- `-in <file>`: Input file, defaults to standard input
- `-out <file>`: Output file, defaults to standard output
- `-pass <password source>`: Password source, defaults to interactive input. Formats:
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-md <algorithm>`: Key derivation algorithm, defaults to SHA-256
- `-provider`, `-provider-path`, `-provider-attr`: See [Provider Options](#21-provider-options)

**Examples**:

```bash
# Encrypt a file (using AES-256-CBC)
hitls enc -cipher aes256_cbc -enc -in plain.txt -out encrypted.enc -pass pass:mypassword

# Decrypt a file
hitls enc -cipher aes256_cbc -dec -in encrypted.enc -out decrypted.txt -pass pass:mypassword

# Encrypt using SM4 algorithm
hitls enc -cipher sm4_cbc -enc -in data.bin -out data.enc -pass stdin

# Use SHA3-256 as key derivation algorithm
hitls enc -cipher aes128_gcm -enc -in file.txt -out file.enc -pass file:password.txt -md sha3_256
```

AES-WRAP algorithms are not supported by the `enc` command.

**Function**: Symmetric encryption/decryption

**Usage**:
```
hitls enc -cipher <alg> -enc|-dec -in <infile> -out <outfile> -pass <pass> [options]
```

**Options**:
- `-help`: Show help information
- `-cipher <alg>`: Specify the symmetric algorithm. Use `hitls list -cipher-algorithms` to view supported algorithms.
- `-enc`: Encryption
- `-dec`: Decryption
- `-in <file>`: Input file
- `-out <file>`: Output file
- `-pass <pass:xxx|file:xxx>`: Passphrase source
- `-hex`: Hex-encoded output/input
- `-base64`: Base64-encoded output/input
- `-md <alg>`: Digest algorithm used to derive the key (default: SHA256)
- `-iter <count>`: Number of PBKDF2 iterations used for key derivation. If not specified, the default value `10000` is used. The valid range for `count` is `1` to `4294967295`.
- `-provider`, `-provider-path`, `-provider-attr`: See [Provider options](#21-provider-options)

**Notes**:
- If `-hex`/`-base64` is not specified, the output is binary.
- The decryption format must match the encryption output format (for example, use `-base64` for both).

**Examples**:
```bash
# Binary output by default
hitls enc -cipher aes128_ecb -enc -in in.txt -pass pass:12345678 -out out.bin

# Hex output
hitls enc -cipher aes128_ecb -enc -in in.txt -pass pass:12345678 -out out.txt -hex

# Base64 output
hitls enc -cipher aes128_ecb -enc -in in.txt -pass pass:12345678 -out out.txt -base64
```

### 3.2.2 mac

**Function**: Message authentication code calculation and verification

**Usage**:

```
hitls mac -name <algorithm> {-key <string key> | -hexkey <hex key>} [-in <file>] [-out <file>] [-binary] [-provider name] [-provider-path path] [-provider-attr attr]
```

**Supported Options**:

- `-help`: Display help information
- `-name <algorithm>`: Specify the MAC algorithm
- `-key <string key>`: Must choose one of `-key` or `-hexkey`. Provide the key as a string
- `-hexkey <hex key>`: Must choose one of `-key` or `-hexkey`. Provide the key as a 0x-prefixed hexadecimal number
- `-in <file>`: Specify input file, defaults to standard input
- `-out <file>`: Specify output file, defaults to standard output
- `-binary`: Output result in binary format
- `-provider`, `-provider-path`, `-provider-attr`: See [Provider Options](#21-provider-options)

**Examples**:

```bash
# Using a string key
hitls mac -name hmac_sha256 -key "mySecretKey" -in input.txt

# Using a hexadecimal key
hitls mac -name hmac_sha256 -hexkey 0x1234567890abcdef -in input.txt

# Output to file
hitls mac -name hmac_sm3 -key "mykey" -in input.txt -out output.txt

# Binary output
hitls mac -name hmac_sm3 -key "testkey" -in input.txt -out output.bin -binary
```

GMAC algorithms are not supported by the `mac` command.

### 3.2.3 dgst

**Function**: Message digest calculation and digital signature operations

**Usage**:

```
hitls dgst [-md <algorithm>] [-sign <private key file> | -verify <public key file> -signature <signature file>] [-out <file>] [-provider name] [-provider-path path] [-provider-attr attr] [file...]
```

- Digest mode

  ```
  hitls dgst [-md <algorithm>] [-out <file>] [file...]
  ```

- Signing mode

  ```
  hitls dgst [-md <algorithm>] -sign <private key file> [-out <file>] [-userid <user ID>] [file...]
  ```

- Verification mode

  ```
  hitls dgst [-md <algorithm>] -verify <public key file> -signature <signature file> [-userid <user ID>] [file...]
  ```

**Supported Options**:

- `-help`: Display help information
- `-md <algorithm>`: Specify digest algorithm, defaults to SHA-256
- `-out <file>`: Specify output file, defaults to standard output
- `-sign <private key file>`: Required in signing mode. Specify private key file
- `-verify <public key file>`: Required in verification mode. Specify public key file
- `-signature <signature file>`: Required in verification mode. Specify signature file
- `-userid <user ID>`: User ID for SM2 algorithm, defaults to `1234567812345678`
- `-provider`, `-provider-path`, `-provider-attr`: See [Provider Options](#21-provider-options)
- `[file...]`: List of files to compute digest for, defaults to standard input

**Examples**:

```bash
# Digest mode
hitls dgst file1.txt file2.txt

# Signing mode: ECDSA signature
hitls dgst -md sha256 -sign ec_private.pem -out sig.txt msg.txt

# Signing mode: SM2 signature
hitls dgst -md sm3 -userid "my_user_id" -sign sm2_private.pem -out sig.txt msg.txt

# Verification mode
hitls dgst -md sha256 -verify public.pem -signature sig.txt msg.txt

# SM2 verification
hitls dgst -md sm3 -userid "my_user_id" -verify sm2_pub.pem -signature sig.txt msg.txt
```

### 3.2.4 kdf

**Function**: Key derivation function, derive keys from input materials

**Usage**:

```
hitls kdf -keylen <bytes> {-pass <string password> | -hexpass <hex password>} {-salt <string salt> | -hexsalt <hex salt>} [-mac <algorithm>] [-iter <iterations>] [-out <file>] [-binary] [-provider <name>] [-provider-path <path>] [-provider-attr <attr>] <algorithm...>
```

**Supported Options**:

- `-help`: Display help information
- `-keylen <bytes>`: Required. Length of derived key (in bytes)
- `-pass <string password>`: Must choose one of `-pass` or `-hexpass`. Provide the password as a string
- `-hexpass <hex password>`: Must choose one of `-pass` or `-hexpass`. Provide the password as a 0x-prefixed hexadecimal number
- `-salt <string salt>`: Must choose one of `-salt` or `-hexsalt`. Provide the salt as a string
- `-hexsalt <hex salt>`: Must choose one of `-salt` or `-hexsalt`. Provide the salt as a 0x-prefixed hexadecimal number
- `-mac <algorithm>`: Specify MAC algorithm, defaults to HMAC-SHA256
- `-iter <iterations>`: Specify iteration count, defaults to 1000
- `-out <file>`: Specify output file, defaults to standard output
- `-binary`: Binary output, defaults to hexadecimal
- `-provider`, `-provider-path`, `-provider-attr`: See [Provider Options](#21-provider-options)
- `<algorithm...>`: Required, at the end of the command. Specify the KDF algorithm, using the first argument as the algorithm name

**Examples**:

```bash
# Basic usage
hitls kdf -keylen 32 -pass "mypassword" -salt "mysalt" pbkdf2

# Specify full parameters
hitls kdf -keylen 32 -pass "password" -salt "salt" -mac hmac_sha512 -iter 10000 -out key.txt pbkdf2

# Using hexadecimal output
hitls kdf -keylen 32 -hexpass 0x70617373776f7264 -hexsalt 0x73616c74 -iter 1000 pbkdf2

# Binary output to file
hitls kdf -keylen 32 -pass "password" -salt "salt" -binary -out key.bin pbkdf2
```

## 3.3 Key and Parameter Management

### 3.3.1 rsa

**Function**: RSA key processing, including format conversion and information display

**Usage**:

```
hitls rsa [-help] [-in <file>] [-out <file>] [-text] [-noout]
```

**Supported Options**:

- `-help`: Display help information
- `-in <file>`: Input RSA private key file (PEM format), defaults to standard input
- `-out <file>`: Specify output file, defaults to standard output
- `-text`: Display RSA key details in text format
- `-noout`: Do not output the key in PEM format

**Examples**:

```bash
# View key details
hitls rsa -in rsa_private.pem -text -noout

# Output key to file
hitls rsa -in rsa_private.pem -out output.pem

# Output both text and PEM format
hitls rsa -in rsa_private.pem -text -out output.pem
```

### 3.3.2 genrsa

**Function**: Generate RSA private keys

**Usage**:

```
hitls genrsa -cipher <algorithm> [-out <file>] <key length>
```

**Supported Options**:

- `-help`: Display help information
- `-cipher <algorithm>`: Required. Specify the symmetric encryption algorithm for encrypting the private key
- `-out <file>`: Specify output file, defaults to standard output
- `<key length>`: Required, at the end. RSA key length (bits), supported lengths: 1024, 2048, 3072, 4096

**Examples**:

```bash
# Generate a 2048-bit key
hitls genrsa -cipher aes256_cbc -out server_key.pem 2048

# Encrypt the private key using SM4 algorithm
hitls genrsa -cipher sm4_cbc -out gm_key.pem 2048
```

### 3.3.3 genpkey

**Function**: Generate various types of public and private keys

**Usage**:

```
hitls genpkey -algorithm <algorithm> [-pkeyopt <param>:<value>] [-out <file>] [-pubout <public key file>] [-outform <format>] [-<algorithm> -pass <password source>]
```

**Supported Options**:

- `-help`: Display help information
- `-algorithm <algorithm>`: Required. Specify the key algorithm type
- `-pkeyopt <param>:<value>`: Algorithm-specific parameters
  - `-pkeyopt rsa_keygen_bits:<bits>`: RSA algorithm. Specify key length (bits), supported lengths: 1024, 2048, 3072, 4096, defaults to 2048
  - `-pkeyopt ec_paramgen_curve:<curve name>`: EC algorithm, required. Specify curve name
  - `-pkeyopt mldsa_param:<variant>`: ML-DSA algorithm, required. Specify algorithm variant, supported variants: ML-DSA-44, ML-DSA-65, ML-DSA-87
- `-out <file>`: Specify output private key file, defaults to standard output
- `-pubout <file>`: Specify output public key file
- `-outform <format>`: Output format, supports PEM and DER
- `-<algorithm>`: Specify the algorithm for encrypting the output private key
- `-pass <password source>`: Password source for the encryption algorithm, defaults to interactive input. Formats:
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file

**Examples**:

```bash
# Generate a 2048-bit RSA key
hitls genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_key.pem

# Generate a 4096-bit RSA key encrypted with AES-256
hitls genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes256_cbc -pass pass:mypassword -out rsa_encrypted.pem

# Generate an EC key (P-256 curve)
hitls genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P_256 -out ec_key.pem

# Generate both public and private keys
hitls genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem -pubout public.pem

# Output key in DER format
hitls genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER -out key.der
```

### 3.3.4 pkey

**Function**: Public and private key processing tool

**Usage**:

```
hitls pkey [-in <file>] [-passin <password source>] [-out <file>] [-pubout] [-<algorithm> -passout <password source>] [-text] [-noout]
```

**Supported Options**:

- `-help`: Display help information
- `-in <file>`: Input key file, only PEM format is supported, defaults to standard input
- `-passin <password source>`: Decryption password for the input file. If the input file is encrypted and this option is not specified, defaults to interactive input. Formats:
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-out <file>`: Output file, defaults to standard output
- `-pubout`: Extract and output the public key from the private key
- `-<algorithm>`: Specify the encryption algorithm for the output private key
- `-passout <password source>`: Encryption password for the output file. If an encryption algorithm is specified and this option is not specified, defaults to interactive input. Formats:
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-text`: RSA only. Print key details in text format
- `-noout`: Do not output the key in PEM format

**Examples**:

```bash
# Extract public key from private key
hitls pkey -in private.pem -pubout -out public.pem

# View RSA key details in text format
hitls pkey -in rsa_private.pem -text -noout

# Encrypt private key using AES-256-CBC
hitls pkey -in private.pem -aes256_cbc -passout pass:mypassword -out private_enc.pem

# Decrypt an encrypted private key
hitls pkey -in private_enc.pem -passin pass:mypassword -out private_dec.pem

# Re-encrypt a private key
hitls pkey -in old_enc.pem -passin pass:oldpass -aes128_cbc -passout pass:newpass -out new_enc.pem
```

### 3.3.5 pkeyutl

**Function**: Use keys for encryption, decryption, signing, verification and other operations

**Usage**:

```
hitls pkeyutl {-encrypt | -decrypt | -derive} [-pubin <public key file>] [-prvin <private key file>] [-in <file>] [-out <file>] [-inkey <local key>] [-peerkey <peer public key>] [-userid <user ID>] [-inR <peer R file>] [-outR <output R file>] [-inr <local r file>] [-outr <output r file>] [-rpass <password source>]
```

- Encryption mode

  ```
  hitls pkeyutl -encrypt -pubin <public key file> -in <plaintext file> -out <ciphertext file>
  ```

- Decryption mode

  ```
  hitls pkeyutl -decrypt -prvin <private key file> -in <ciphertext file> -out <plaintext file>
  ```

- Key exchange mode

  ```
  hitls pkeyutl -derive -inkey <local private key> -userid <user ID> [-peerkey <peer public key>] [-inR <peer R file>] [-outR <output R file>] [-inr <local r file>] [-outr <output r file>] [-rpass <password source>] [-out <shared key file>]
  ```

**Supported Options**:

- `-help`: Display help information
- `-encrypt`: Must choose one of `-encrypt`, `-decrypt`, or `-derive`. Perform public key encryption, only SM2 encryption is supported
- `-decrypt`: Must choose one of `-encrypt`, `-decrypt`, or `-derive`. Perform private key decryption, only SM2 decryption is supported
- `-derive`: Must choose one of `-encrypt`, `-decrypt`, or `-derive`. Perform key exchange, only SM2 key agreement is supported
- `-pubin <public key file>`: Required for encryption. Public/private key file for encryption (PEM format)
- `-prvin <private key file>`: Required for decryption. Private key file for decryption (PEM format)
- `-in <file>`: Required for encryption or decryption. Input file
- `-out <file>`: Required for encryption or decryption. Output file
- `-inkey <local private key file>`: Required for key exchange. Local private key file (PEM format)
- `-peerkey <file>`: Required for computing shared key. Peer's public/private key file (PEM format)
- `-userid <user ID>`: User ID for SM2 algorithm, defaults to `1234567812345678`
- `-outR <output R file>`: In key exchange, output local temporary public key (hexadecimal format)
- `-outr <output r file>`: In key exchange, output local temporary private key r (PKCS#12 encrypted format)
- `-inr <file>`: In key exchange, input previously saved local temporary private key r (PKCS#12 file)
- `-rpass <password source>`: When using `-outr`/`-inr`, password source for encrypting/decrypting the temporary private key r. If `-outr`/`-inr` is used and this option is not specified, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file

- `-provider`, `-provider-path`, `-provider-attr`: See [Provider Options](#21-provider-options)

**Examples**:

```bash
# Encrypt a plaintext file
hitls pkeyutl -encrypt -pubin pub.pem -in plaintext.txt -out ciphertext.txt

# Decrypt ciphertext using private key
hitls pkeyutl -decrypt -prvin prv.pem -in ciphertext.txt -out decrypted.txt

# SM2 key exchange, step 1: Party A (initiator) generates temporary public key R_A and temporary private key r_A
hitls pkeyutl -derive -inkey prv_a.pem -userid "1234567812345678" -outR R_a.txt -outr r_a.p12 -rpass pass:test1234

# SM2 key exchange, step 2: Party B (responder) receives R_A, generates R_B, and computes shared key
hitls pkeyutl -derive -inkey prv_b.pem -userid "1234567812345678" -outR R_b.txt -outr r_b.p12 -rpass pass:test1234 -inR R_a.txt -peerkey pub_a.pem -out shared_b.txt

# SM2 key exchange, step 3: Party A receives R_B, loads previously saved r_A, and computes shared key
hitls pkeyutl -derive -inkey prv_a.pem -userid "1234567812345678" -inr r_a.p12 -rpass pass:test1234 -inR R_b.txt -peerkey pub_b.pem -out shared_a.txt

# Key exchange, only generate temporary keys without computing shared key
hitls pkeyutl -derive -inkey prv_a.pem -userid "1234567812345678" -outR R_a.txt
```

### 3.3.6 keymgmt
Key management functions, including key creation, deletion, querying, etc. (SM mode)

## 3.4 PKI Certificate Management

### 3.4.1 pkcs12

**Function**: Processing of PKCS#12 format certificates and key packages

**Usage**:

- Export mode (create PKCS#12 file)

  ```
  hitls pkcs12 -export -in <certificate file> -inkey <private key file> [-out <file>] [-passin <password source>] [-passout <password source>] [-name <friendly name>] [-caname <CA name>]... [-chain -CAfile <CA certificate file>] [-keypbe <algorithm>] [-certpbe <algorithm>] [-macalg <algorithm>]
  ```

- Import mode (parse PKCS#12 file)

  ```
  hitls pkcs12 -in <PKCS12 file> [-out <file>] [-passin <password source>] [-passout <password source>] [-clcerts] [-<algorithm>]
  ```

**Supported Options**:

- `-help`: Display help information
- `-export`: Enable export mode for creating PKCS#12 files. If this option is not specified, import mode is used to parse PKCS#12 files
- `-in <file>`: Required. Input file: PEM certificate file in export mode, PKCS#12 file in import mode
- `-out <file>`: Output file: PKCS#12 file in export mode, PEM file in import mode, defaults to standard output
- `-passin <password source>`: Input file password source, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-passout <password source>`: Output file password source, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-inkey <file>`: Required in export mode. Specify private key file (PEM format)
- `-clcerts`: Effective in import mode. Output only user certificates
- `-name <string>`: Effective in export mode. Set friendly name for user certificate and private key
- `-caname <string>`: Effective in export mode. Set friendly name for CA certificate. When the input file contains multiple CA certificates, `-caname` can be specified multiple times to set a friendly name for each CA certificate
- `-chain`: Effective in export mode. Include certificate chain
- `-CAfile <file>`: Effective in export mode, required when using `-chain`. CA certificate file (PEM format)
- `-keypbe <algorithm>`: Effective in export mode. PBE encryption algorithm for the private key, defaults to `PBES2` (PKCS#5 v2.0 encryption scheme)
- `-certpbe <algorithm>`: Effective in export mode. PBE encryption algorithm for the certificate, defaults to `PBES2` (PKCS#5 v2.0 encryption scheme)
- `-macalg <algorithm>`: Effective in export mode. Digest algorithm for MAC integrity check, defaults to `sha256` (SHA-256 digest algorithm)
- `-<algorithm>`: Effective in import mode. Encryption algorithm for the output private key, defaults to `aes256_cbc` (AES-256-CBC encryption algorithm)

**Examples**:

```bash
# Create a PKCS#12 file from certificate and private key
hitls pkcs12 -export -in user_cert.pem -inkey user_prv.pem -out user.p12 -passin pass: -passout pass:test1234 -name "My User Key"

# Create a PKCS#12 file with CA certificate
hitls pkcs12 -export -in bundle.pem -inkey user_prv.pem -out user.p12 -passin pass: -passout pass:test1234 -name "MyUser" -caname "MyCA"

# Create a PKCS#12 file with certificate chain
hitls pkcs12 -export -in user_cert.pem -inkey user_prv.pem -out user.p12 -passin pass: -passout pass:test1234 -chain -CAfile ca_chain.pem -name "ChainUser"

# Create a PKCS#12 file with custom MAC algorithm
hitls pkcs12 -export -in user_cert.pem -inkey user_prv.pem -out user.p12 -passin pass: -passout pass:test1234 -macalg sha512

# Parse a PKCS#12 file and output certificate and private key
hitls pkcs12 -in user.p12 -out output.pem -passin pass:test1234 -passout pass:newpass
```

### 3.4.2 x509

**Function**: Generation, parsing, conversion and verification of X.509 certificates

**Usage**:

```
hitls x509 [-help] [-in <file>] [-inform PEM|DER] [-out <file>] [-outform PEM|DER] [-noout] [-req] [-signkey <private key file>] [-CA <CA certificate> -CAkey <CA private key>] [-days <days>] [-set_serial <serial number>] [-md <algorithm>] [-extfile <extension config file>] [-extensions <section name>] [-passin <password source>] [-userid <SM2 user ID>] [-text] [-issuer] [-subject] [-hash] [-fingerprint] [-pubkey] [-nameopt oneline|multiline|rfc2253]
```

**Supported Options**:

- `-help`: Display help information
- `-in <file>`: Input file, accepts a certificate or CSR, defaults to standard input
- `-inform PEM|DER`: Input file format, choose from `PEM` or `DER`, defaults to PEM
- `-out <file>`: Output file, defaults to standard output
- `-outform PEM|DER`: Output file format, choose from `PEM` or `DER`, defaults to PEM
- `-noout`: Do not output certificate encoded data
- `-req`: Indicates the input is a CSR; sign it and output a certificate
- `-signkey <file>`: Requires `-req` option. Self-signing private key file (PEM format), cannot be used together with `-CA`
- `-CA <file>`: Requires `-req` option. CA certificate file (PEM format), must be used with `-CAkey`
- `-CAkey <file>`: Requires `-req` option. CA private key file (PEM format), must be used with `-CA`
- `-days <days>`: Requires `-req` option. Certificate validity period (days), must be an integer, defaults to 30
- `-set_serial <hex value>`: Requires `-req` option. Certificate serial number as a `0x`-prefixed hexadecimal value, defaults to a randomly generated 20-byte number
- `-md <algorithm>`: Digest algorithm for signing/fingerprint, signing defaults to `sha256`, fingerprint defaults to `sha1`
- `-extfile <file>`: Requires `-req` option. X.509v3 extension configuration file, must be used with `-extensions`
- `-extensions <section name>`: Requires `-req` option. Section name in the configuration file, must be used with `-extfile`
- `-passin <password source>`: Requires `-req` option. Password source for private key/certificate file, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-userid <ID>`: Requires `-req` option. User ID for SM2 signing
- `-text`: Print full certificate information in text format
- `-issuer`: Print issuer DN
- `-subject`: Print subject DN
- `-hash`: Print hash of the subject DN
- `-fingerprint`: Print certificate fingerprint
- `-pubkey`: Output the public key from the certificate (PEM format)
- `-nameopt <format>`: DN display format, defaults to `oneline`
  - `oneline`: Single-line display
  - `multiline`: Multi-line indented display, one attribute per line
  - `rfc2253`: RFC 2253 format, reverse order display

**Supplementary Notes**: The extension file uses INI-style configuration format. Supported extension types include:

| Extension                | Description                  | Example Value                  |
| ------------------------ | ---------------------------- | ------------------------------ |
| `basicConstraints`       | Basic constraints            | `CA:TRUE` or `CA:FALSE`        |
| `keyUsage`               | Key usage                    | `critical,keyCertSign,cRLSign` |
| `extendedKeyUsage`       | Extended key usage           | `serverAuth,clientAuth`        |
| `subjectAltName`         | Subject alternative name     | `DNS:example.com,IP:1.2.3.4`  |
| `subjectKeyIdentifier`   | Subject key identifier       | `hash`                         |
| `authorityKeyIdentifier` | Authority key identifier     | `keyid` or `keyid:always`      |

Example configuration file `ext.cnf`:

```ini
[v3_ca]
basicConstraints = CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
```

**Examples**:

```bash
# View PEM certificate details
hitls x509 -in cert.pem -text -noout

# Print certificate issuer and subject information
hitls x509 -in cert.pem -issuer -subject -noout

# Generate a self-signed certificate from CSR, valid for 365 days
hitls x509 -req -in request.csr -signkey private_key.pem -days 365 -out cert.pem

# Issue a certificate using CA
hitls x509 -req -in request.csr -CA ca_cert.pem -CAkey ca_key.pem -days 365 -out signed_cert.pem

# Issue a certificate with specific serial number and digest algorithm
hitls x509 -req -in request.csr -signkey key.pem -set_serial 0x01 -md sha384 -days 365 -out cert.pem

# Convert PEM certificate to DER format
hitls x509 -in cert.pem -outform DER -out cert.der

# Display DN names in multi-line format
hitls x509 -in cert.pem -subject -nameopt multiline -noout

# Extract the public key from a certificate
hitls x509 -in cert.pem -pubkey -noout

# Print certificate fingerprint (using SHA-256)
hitls x509 -in cert.pem -fingerprint -md sha256 -noout

# Issue a CA certificate with v3 extensions
hitls x509 -req -in ca.csr -signkey ca_key.pem -days 3650 -extfile ext.cnf -extensions v3_ca -out ca_cert.pem

# Issue a certificate using an encrypted private key
hitls x509 -req -in request.csr -signkey encrypted_key.pem -passin pass:MyPassword123 -out cert.pem
```

### 3.4.3 crl
Generation and management of certificate revocation lists

**Function**: Parse, output, and verify CRLs, and print issuer/hash/text information  
**Usage**:

```
hitls crl [-help] [-in file] [-inform PEM|DER] [-out file] [-outform PEM|DER] [-noout] [-nextupdate] [-CAfile file] [-issuer] [-hash] [-text]
```

**Supported Options**:
- `-help`: Display help information
- `-in <file>`: Input CRL file, default stdin
- `-inform <PEM|DER>`: Input format, PEM or DER
- `-out <file>`: Output file, default stdout
- `-outform <PEM|DER>`: Output format, PEM or DER
- `-noout`: Do not output CRL content (PEM/DER), but still print issuer/hash/text information
- `-nextupdate`: Print CRL next update time
- `-CAfile <file>`: Verify CRL using CA certificate
- `-issuer`: Print issuer DN
- `-hash`: Print issuer DN hash (prefix: "Issuer Hash=")
- `-text`: Print CRL in text

**Examples**:
```bash
# Print issuer/hash/text to a file
hitls crl -in crl.pem -noout -issuer -hash -text -out crl_info.txt

# Convert DER to PEM
hitls crl -in crl.der -inform DER -out crl.pem -outform PEM

# Verify CRL signature
hitls crl -in crl.pem -noout -CAfile ca.crt
```

### 3.4.4 verify

**Function**: Certificate chain verification and trust relationship checking

**Usage**:

```
hitls verify -CAfile <CA certificate file> [-nokeyusage] [-verbose] [certificate files ...]
```

**Supported Options**:

- `-help`: Display help information
- `-CAfile <file>`: Required. Trusted CA certificate file (PEM format), can be a bundle file containing multiple CA certificates
- `-nokeyusage`: Skip the keyUsage extension check of the certificate
- `-verbose`: Print additional subject DN information when verification fails
- `[certificate files...]`: Certificate files to verify (PEM format), multiple files accepted, defaults to standard input

**Examples**:

```bash
# Verify a user certificate directly issued by root CA
hitls verify -CAfile root_ca_cert.pem user_cert.pem

# Verify multiple certificates
hitls verify -CAfile root_ca_cert.pem cert1.pem cert2.pem cert3.pem

# Verify a certificate with only digitalSignature but no keyEncipherment
hitls verify -CAfile root_ca_cert.pem -nokeyusage sign_only_cert.pem

# Print additional subject DN information when verification fails
hitls verify -CAfile wrong_ca_cert.pem -verbose user_cert.pem
```

### 3.4.5 req

**Function**: Generation and processing of certificate signing requests

**Usage**:

- Generate a new CSR

  ```
  hitls req -new -subj <DN> [-key <private key file>] [-keyform PEM|DER] [-mdalg <algorithm>] [-config <config file>] [-passin <password source>] [-passout <password source>] [-out <file>] [-outform PEM|DER] [-verify] [-text] [-noout]
  ```

- View/verify an existing CSR

  ```
  hitls req [-in <file>] [-inform PEM|DER] [-verify] [-text] [-noout] [-out <file>] [-outform PEM|DER]
  ```

**Supported Options**:

- `-help`: Display help information
- `-new`: Generate new CSR mode, mutually exclusive with view/verify existing CSR mode
- `-verify`: Verify the self-signature of the CSR. If used with `-new`, verifies the newly generated CSR
- `-mdalg <algorithm>`: Effective only when generating a new CSR. Signature digest algorithm, defaults to SHA256 (RSA) / SM3 (SM2) / SHA512 (ED25519)
- `-subj <DN>`: Required when generating a new CSR. Certificate subject DN in the format `/type1=value1/type2=value2/...`
- `-key <file>`: Private key file, used for signing when generating a new CSR. Defaults to auto-generating a 2048-bit RSA private key
- `-keyform PEM|DER`: Private key file format, choose from `PEM` or `DER`. If not specified, defaults to automatic format detection
- `-passin <password source>`: Password source for reading the encrypted private key, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-passout <password source>`: Password source for encrypting the output key file when auto-generating keys, defaults to interactive input
  - `stdin`: Standard input
  - `pass:<password>`: Read password from command line
  - `file:<file path>`: Read password from file
- `-noout`: Do not output CSR encoded data
- `-text`: Print full CSR information in text format
- `-config <file>`: Effective only when generating a new CSR. Configuration file for adding extensions
- `-in <file>`: Input CSR file, defaults to standard input
- `-inform PEM|DER`: Input CSR file format, choose from `PEM` or `DER`, defaults to PEM
- `-out <file>`: Output file, defaults to standard output
- `-outform PEM|DER`: Output CSR file format, choose from `PEM` or `DER`, defaults to PEM

**Supplementary Notes**: The configuration file uses INI style and **must** contain a `[req]` section, which references the extension section via `req_extensions`. Supported types are as follows:

| Type Prefix | Description              | Example Value              |
| ----------- | ------------------------ | -------------------------- |
| `DNS`       | DNS domain name          | `DNS:example.com`          |
| `IP`        | IP address (IPv4/IPv6)   | `IP:192.168.1.1`           |
| `email`     | Email address            | `email:user@example.com`   |
| `URI`       | Uniform Resource Identifier | `URI:http://example.com` |
| `dirName`   | Directory name           | `dirName:dir_section`      |

Example configuration file:

```ini
[req]
req_extensions = req_ext

[req_ext]
subjectAltName = DNS:example.com, DNS:www.example.com, IP:192.168.1.1, email:user@example.com
```

**Examples**:

```bash
# Generate a basic RSA CSR
hitls req -new -key rsa_key.pem -subj "/CN=User/O=MyOrg/C=CN" -out request.csr

# Specify SHA-384 digest algorithm
hitls req -new -key rsa_key.pem -subj "/CN=User/C=CN" -mdalg sha384 -out request.csr

# Generate CSR using an encrypted private key
hitls req -new -key encrypted_key.pem -passin pass:MyPassword123 -subj "/CN=User/O=Org/C=CN" -out request.csr

# Generate a CSR with SAN extension
hitls req -new -key rsa_key.pem -subj "/CN=example.com/O=MyOrg/C=CN" -config san.cnf -out san_request.csr

# View CSR text information, display both text and output PEM
hitls req -in request.csr -text -out request_copy.csr

# Verify CSR self-signature
hitls req -in request.csr -verify -noout

# Generate CSR and verify immediately
hitls req -new -key rsa_key.pem -subj "/CN=User/C=CN" -verify -out request.csr
```

### 3.4.6 asn1parse
ASN.1 Encoding Structure Parsing and Cryptographic Object Diagnosis

## 3.5 SSL/TLS Communication

### 3.5.1 s_client

**Function**: Establish a TLS, TLCP, or DTLCP client connection with an explicit protocol version, cipher list, trust chain, and optional client certificate.

**Usage**:

```bash
hitls s_client -host <host> [-port <port>] [-tls|-tls1_2|-tls1_3|-tlcp|-dtlcp]
    [-cipher <suites>] [-CAfile <file>] [-chainCAfile <file>]
    [-cert <file> -key <file>] [-noverify] [-state] [-prexit]
```

**Main Options**:

- `-tls`: Use TLS and allow TLS 1.2 or TLS 1.3 negotiation by default.
- `-tls1_2`, `-tls1_3`: Allow only the selected TLS version.
- `-cert <file>`, `-key <file>`: Configure the TLS client certificate and private key for mutual authentication. They must be used together.
- `-cipher <suites>`: Specify a colon-separated cipher suite list. Both standard `TLS_*` names and openHiTLS `HITLS_*` names are accepted.
- `-CAfile <file>`, `-chainCAfile <file>`: Configure the CA and intermediate certificates used to verify the server.
- `-noverify`: Do not verify the server certificate. This does not prevent the client from sending its own certificate.
- `-tlcp_sign_cert/-tlcp_sign_key`, `-tlcp_enc_cert/-tlcp_enc_key`: Configure the TLCP/DTLCP signing and encryption certificate pairs.

**TLS 1.3 Mutual Authentication Example**:

```bash
hitls s_client -host 127.0.0.1 -port 4433 -tls1_3 \
    -CAfile ca.pem -chainCAfile intermediate.pem \
    -cert client.pem -key client.key.pem
```

### 3.5.2 s_server

**Function**: Start a TLS, TLCP, or DTLCP server with an explicit protocol version, cipher list, server certificate, and client-certificate verification policy.

**Usage**:

```bash
hitls s_server [-accept <host:port>] [-port <port>] [-tls|-tls1_2|-tls1_3|-tlcp|-dtlcp]
    [-cipher <suites>] [-CAfile <file>] [-chainCAfile <file>]
    [-cert <file> -key <file>] [-noverify] [-accept_once] [-state]
```

`-cert/-key` configure the TLS server certificate and private key. The server verifies client certificates by default; use `-CAfile/-chainCAfile` for its trust chain or `-noverify` to disable client-certificate verification. Protocol, cipher, and TLCP certificate options follow the same rules as `s_client`.

**TLS 1.3 Mutual Authentication Example**:

```bash
hitls s_server -accept 127.0.0.1:4433 -tls1_3 \
    -cert server.pem -key server.key.pem \
    -CAfile ca.pem -chainCAfile intermediate.pem
```

## 3.6 Other Utility Tools

### 3.6.1 rand

**Function**: Generate random data
**Usage**:

```
hitls rand [-help] [-out file] [-algorithm alg] [-hex] [-base64] [-provider name] [-provider-path path] [-provider-attr attr] numbytes
```

**Supported Options**:
- `-help`: Display help information
- `-hex`: Output in hexadecimal format, default format is binary
- `-base64`: Output in Base64 format, default format is binary
- `-out <file>`: Write output to specified file, if not specified, output to stdout
- `-algorithm <algorithm>`: Specify random number generation algorithm, supported random number algorithms can be viewed using [list](#312-list) command
- `-provider`, `-provider-path`, `-provider-attr`: Please refer to [Provider Options](#21-provider-options)

**Examples**:
```bash
# Generate 16 bytes of random data, output in binary format
hitls rand 16

# Generate 32 bytes of random data, output in hexadecimal format
hitls rand -hex 32

# Generate 64 bytes of random data, save in Base64 format to rand.txt
hitls rand -base64 -out rand.txt 64

# Use hmac-sha256 random number algorithm to generate 10 bytes of random data, output in hexadecimal format
hitls rand -algorithm hmac-sha256 -hex 10
```

### 3.6.2 prime

**Function**: Generate and test primes

**Usage**:

```
hitls prime [-help] [-generate] [-bits num] [-hex] [-checks num] [number]
```

**Supported Options**:

- `-help`: Show help information
- `-bits <n>`: Specify the bit length of the prime to be generated
- `-hex`: Use hexadecimal format for input/output (decimal by default)
- `-generate`: Enable prime generation mode
- `-check <n>`: Number of iterations for primality testing (default: 64)

**Examples**:

```bash
# Check if a decimal number is prime
./hitls prime 17

# Check a hexadecimal number
./hitls prime -hex 1F

# Customize number of primality test rounds
./hitls prime -checks 128 97

# Generate a 256-bit prime
./hitls prime -generate -bits 256

# Output in hexadecimal format
./hitls prime -generate -bits 128 -hex
```

### 3.6.3 errdecode

**Function**: Convert error codes to human-readable strings

**Usage**:

```
hitls errdecode [-help] [-v | --verbose] [--stack] [-hex] [error_code ...]
```

**Supported Options**:

- `-help`: Display help information
- `-v`, `--verbose`: Show detailed error code field breakdown
- `--stack`: Display error stack (if supported)
- `-hex`: Force hexadecimal parsing

**Arguments**:

- `error_code`: Error code in decimal or hexadecimal format
  - Hexadecimal can be with (0x) or without prefix
  - Multiple error codes can be specified

**Examples**:

```bash
# Decode a decimal error code
hitls errdecode 101

# Decode a hexadecimal error code (with 0x prefix)
hitls errdecode 0x0E000065

# Decode a hexadecimal error code (without 0x prefix)
hitls errdecode 0E000065

# Show detailed error code field breakdown
hitls errdecode -v 0x1408F10B

# Batch process multiple error codes
hitls errdecode 101 0x0E000065 234567890

# Read error codes from pipeline
echo "0x1408F10B" | hitls errdecode

# Display error stack
hitls errdecode --stack
```
