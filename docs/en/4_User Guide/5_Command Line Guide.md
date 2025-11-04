# 1 Overview

The openHiTLS command source code is located in the apps directory, and the compiled result is hitls. Users can run the hitls command to perform various cryptographic operations. This tool provides a complete cryptographic function suite, including random number generation, symmetric/asymmetric encryption, digital signatures, PKI certificate management, and SSL/TLS connections.

## 1.1 Supported Command List
|Command Category|Command Name|Description|
|-|-|-|
|**Basic Commands**| | |
||help|Display help information and list of supported commands|
||list|List supported algorithms and functions, including digest, symmetric, asymmetric, MAC, random number, KDF algorithms, etc.|
|**Random Number Generation**|| |
||rand|Generate random numbers of specified length, supporting hexadecimal and Base64 encoded output|
|**Password Processing**|| |
||passwd|Generate and verify password hashes, supporting algorithms like SHA512|
|**Encryption and Decryption**|| |
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

## 3.2 Random Number Generation

### 3.2.1 rand

**Function**: Generate random data
**Usage**:

```
hitls rand [-help] [-out file] [-algorithm alg] [-hex] [-base64] [-provider name] [-provider-path path] [-provider-attr attr] numbytes
```

**Supported Options**:
- `-help`: Display help information
- `-hex`: Output in hexadecimal format
- `-base64`: Output in Base64 format
- `-out <file>`: Write output to specified file, if not specified, output to stdout
- `-algorithm <algorithm>`: Specify random number generation algorithm, supported random number algorithms can be viewed using [list](#312-list) command
- `-provider`, `-provider-path`, `-provider-attr`: Please refer to [Provider Options](#21-provider-options)
- numbytes: 

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

## 3.3 Password Processing

### 3.3.1 passwd
Generate and verify password hashes, supporting algorithms like SHA512

## 3.4 Encryption and Decryption

### 3.4.1 enc
Symmetric encryption and decryption operations, supporting multiple symmetric algorithms

### 3.4.2 mac
Message authentication code calculation and verification

### 3.4.3 dgst
Message digest calculation and digital signature operations

### 3.4.4 kdf
Key derivation function, derive keys from input materials

## 3.5 Key and Parameter Management

### 3.5.1 rsa
RSA key processing, including format conversion and information display

### 3.5.2 genrsa
Generate RSA private keys

### 3.5.3 genpkey
Generate various types of public and private keys

### 3.5.4 pkey
Public and private key processing tool

### 3.5.5 pkeyutl
Use keys for encryption, decryption, signing, verification and other operations

### 3.5.6 keymgmt
Key management functions, including key creation, deletion, querying, etc. (SM mode)

## 3.6 PKI Certificate Management

### 3.6.1 pkcs12
Processing of PKCS#12 format certificates and key packages

### 3.6.2 x509
Generation, parsing, conversion and verification of X.509 certificates

### 3.6.3 crl
Generation and management of certificate revocation lists

### 3.6.4 verify
Certificate chain verification and trust relationship checking

### 3.6.5 req
Generation and processing of certificate signing requests

## 3.7 SSL/TLS Communication

### 3.7.1 s_client
SSL/TLS client tool

### 3.7.2 s_server
SSL/TLS server tool
