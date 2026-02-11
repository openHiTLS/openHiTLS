# Release Notes

Version: openHiTLS 0.3.0

# New Features

**openHiTLS 0.3.0 adds the following features:**

### Post-Quantum Cryptographic Algorithms
* ML-KEM support ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final))
* ML-DSA support ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
* SLH-DSA support ([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final))
* XMSS support ([RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html))
* Classic McEliece support ([McEliece](http://classic.mceliece.org/))
* FrodoKEM support ([FrodoKEM](https://frodokem.org/))

### PKI
* Post-quantum capabilities support
    * XMSS certificate support ([RFC 9802](https://datatracker.ietf.org/doc/rfc9802/))
    * ML-DSA certificate support ([RFC 9881](https://datatracker.ietf.org/doc/rfc9881/))
    * ML-KEM certificate support ([RFC-to-be 9935](https://www.ietf.org/id/draft-ietf-lamps-kyber-certificates-11.txt))
    * SLH-DSA certificate support ([RFC 9909](https://datatracker.ietf.org/doc/rfc9909/))
    * ML-DSA CMS capability ([RFC 9882](https://www.rfc-editor.org/rfc/rfc9882.html))
* Others
    * X25519 certificate support ([RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html))
    * Enhanced certificate verification: partial chain verification, external public key verification, hostname verification
    * CMS: SignedData encoding/decoding and signature verification support
    * Enhanced PKCS12: CRL-bag, key-bag, secret-bag support, provider offload support

### Authentication Protocols
* SPAKE2+ protocol ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html))
* HOTP ([RFC 4226](https://www.rfc-editor.org/rfc/rfc4226.html))
* TOTP ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html))

### Cryptographic Algorithms
* AES-WRAP, RSA ISO9796-2:1997 signature
* SM4-HCTR, SM4-CCM modes
* SHA256-MB multi-buffer interface
* nistp192 curve
* Asymmetric algorithm key verification
* Random number fork reseeding capability
* Paillier algorithm homomorphic operation support
* SM9 Identity-Based Cryptography

### TLS
* Enhanced protocol certificate usability
  * Certificate loading from Buffer
  * CRL support
  * Certificate loading from directory
* Enhanced session management
* DTLS MTU transmission optimization
* Handshake buffer memory minimization
* RFC8998 cipher suite support
* Certificate Authorities extension support
* TLS_FALLBACK_SCSV support

### Command Line
New command line tools, supporting:
* Basic commands: help, list
* Random number: rand
* Encryption/decryption: enc, mac, dgst, kdf
* Key and parameter management: genpkey, pkey, param...
* Certificate and PKI: req, x509, pkcs7, pkcs12, crl...
* SSL/TLS client and server: s_client, s_server
* Password and storage: passwd

### Performance and Platform
* SM2/SM3 ARMv7 assembly optimization
* Darwin/macOS cross-platform support
* STM32F407 build configuration

### Authentication Related
* ISO19790 Provider
* SM Provider

### Bug Fixes
* Fixed cipher suite inconsistency in HRR scenario
* Fixed ticket nonceLen parsing failure
* Fixed certificate UTC time support before year 2000
* T61 string format support
* PSS certificate signature algorithm matching fix
* Fixed DRBG, ML-KEM, and atomic lock memory leaks
* Fixed DH key derivation leading zero issue
* Fixed DRBG entropy source waste issue
* Fixed BMP encoding issue
* Fixed certificate parsing address offset issue
* Fixed scrypt integer overflow issue
* Fixed initialization function order issue
* Fixed decode address offset issue
* Fixed AES-XTS assembly optimization issue
* Fixed symmetric algorithm assembly calling convention issue
* Fixed decode framework P8 key password input issue
* Fixed certificate key codec module memory issue
