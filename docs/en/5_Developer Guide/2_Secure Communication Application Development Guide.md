# TLS Feature Introduction

## Protocol Description

openHiTLS offers functions such as creating, configuring, and managing security protocol links based on transport-layer security protocol standards, with the main functional interfaces available in the protocol module. openHiTLS supports various protocol versions and features, including basic protocol handshake, key update, application-layer protocol negotiation, and server name indication. **In TLS1.3, openHiTLS also supports Hybrid Key Exchange to provide protection against future quantum computing threats.**

Currently, openHiTLS supports the following protocol versions:

- TLS1.2: used for secure renegotiation, application-layer protocol negotiation, server name indication, and session resumption
- TLS1.3: used for key update, application-layer protocol negotiation, server name indication, and session resumption
- DTLS1.2: used for secure renegotiation, application-layer protocol negotiation, server name indication, and session resumption
- TLCP: used for secure renegotiation and session resumption

### TLS/DTLS1.2 Specifications

| Configuration Item| Specifications|
| :---- | :---- |
| TLS version| TLS12 (0x0303u)<br>DTLS12 (0xfefdu)|
| Algorithm suite| TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)<br>TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)<br>TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)<br>TLS_DH_anon_WITH_AES_128_CBC_SHA (0x0034)<br>TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)<br>TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)<br>TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)<br>TLS_DH_anon_WITH_AES_256_CBC_SHA (0x003A)<br>TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)<br>TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003D)<br>TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 (0x0040)<br>TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)<br>TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 (0x006A)<br>TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006B)<br>TLS_DH_anon_WITH_AES_128_CBC_SHA256 (0x006C)<br>TLS_DH_anon_WITH_AES_256_CBC_SHA256 (0x006D)<br>TLS_PSK_WITH_AES_128_CBC_SHA (0x008C)<br>TLS_PSK_WITH_AES_256_CBC_SHA (0x008D)<br>TLS_DHE_PSK_WITH_AES_128_CBC_SHA (0x0090)<br>TLS_DHE_PSK_WITH_AES_256_CBC_SHA (0x0091)<br>TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x0094)<br>TLS_RSA_PSK_WITH_AES_256_CBC_SHA (0x0095)<br>TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)<br>TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)<br>TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009E)<br>TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009F)<br>TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 (0x00A2)<br>TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 (0x00A3)<br>TLS_DH_anon_WITH_AES_128_GCM_SHA256 (0x00A6)<br>TLS_DH_anon_WITH_AES_256_GCM_SHA384 (0x00A7)<br>TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00A8)<br>TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00A9)<br>TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (0x00AA)<br>TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (0x00AB)<br>TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00AC)<br>TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (0x00AD)<br>TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00AE)<br>TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00AF)<br>TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00B2)<br>TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00B3)<br>TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00B6)<br>TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00B7)<br>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009)<br>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xC00A)<br>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xC013)<br>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xC014)<br>TLS_ECDH_anon_WITH_AES_128_CBC_SHA (0xC018)<br>TLS_ECDH_anon_WITH_AES_256_CBC_SHA (0xC019)<br>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xC023)<br>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xC024)<br>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)<br>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)<br>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)<br>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)<br>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)<br>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)<br>TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (0xC035)<br>TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA (0xC036)<br>TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (0xC037)<br>TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (0xC038)<br>TLS_RSA_WITH_AES_128_CCM (0xC09C)<br>TLS_RSA_WITH_AES_256_CCM (0xC09D)<br>TLS_DHE_RSA_WITH_AES_128_CCM (0xC09E)<br>TLS_DHE_RSA_WITH_AES_256_CCM (0xC09F)<br>TLS_RSA_WITH_AES_128_CCM_8 (0xC0A0)<br>TLS_RSA_WITH_AES_256_CCM_8 (0xC0A1)<br>TLS_PSK_WITH_AES_256_CCM (0xC0A5)<br>TLS_DHE_PSK_WITH_AES_128_CCM (0xC0A6)<br>TLS_DHE_PSK_WITH_AES_256_CCM (0xC0A7)<br>TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xC0AC)<br>TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xC0AD)<br>TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)<br>TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)<br>TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCAA)<br>TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAB)<br>TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAC)<br>TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAD)<br>TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 (0xCCAE)<br>TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 (0xD001)<br>TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 (0xD002)<br>TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 (0xD005)|
| EC dotted format| uncompressed (0)|
| Elliptic curve| secp256r1 (23)<br>secp384r1 (24)<br>secp521r1 (25)<br>brainpoolP256r1 (26)<br>brainpoolP384r1 (27)<br>brainpoolP512r1 (28)<br>x25519 (29)|
| Signature hash algorithm| dsa_sha256 (0x0402)<br>dsa_sha384 (0x0502)<br>dsa_sha512 (0x0602)<br>rsa_pkcs1_sha256 (0x0401)<br>rsa_pkcs1_sha384 (0x0501)<br>rsa_pkcs1_sha512 (0x0601)<br>ecdsa_secp256r1_sha256 (0x0403)<br>ecdsa_secp384r1_sha384 (0x0503)<br>ecdsa_secp521r1_sha512 (0x0603)<br>rsa_pss_rsae_sha256 (0x0804)<br>rsa_pss_rsae_sha384 (0x0805)<br>rsa_pss_rsae_sha512 (0x0806)<br>rsa_pss_pss_sha256 (0x0809)<br>rsa_pss_pss_sha384 (0x080a)<br>rsa_pss_pss_sha512 (0x080b)<br>ed25519 (0x0807)|
| Dual-ended verification| **HITLS_CFG_SetClientVerifySupport** (disabled by default)|
| Blank client certificate| **HITLS_CFG_SetNoClientCertSupport** (disabled by default)|
| Do not verify peer certificate| **HITLS_CFG_SetVerifyNoneSupport** (disabled by default)|
| Renegotiation| **HITLS_CFG_SetRenegotiationSupport** (disabled by default)|
| Verify client certificate only once| **HITLS_CFG_SetClientOnceVerifySupport** (disabled by default)|
| Send handshake packets in a single flight| **HITLS_CFG_SetFlightTransmitSwitch** (disabled by default)|
| Quiet shutdown mode| **HITLS_CFG_SetQuietShutdown** (disabled by default)|
| Extend primary key| **HITLS_CFG_SetExtenedMasterSecretSupport** (enabled by default)|
| Support **sessionTicket**| **HITLS_CFG_SetSessionTicketSupport** (enabled by default)|
| Verify **keyUsage**| **HITLS_CFG_SetCheckKeyUsage** (enabled by default)|
| Auto-generate DH parameter| **HITLS_CFG_SetDhAutoSupport** (enabled by default)|

### TLS1.3 Specifications

| Configuration Item| Specifications|
| :---- | :---- |
| TLS version| TLS13 (0x0304u)|
| Algorithm suite| TLS_AES_128_GCM_SHA256 (0x1301)<br>TLS_AES_256_GCM_SHA384 (0x1302)<br>TLS_CHACHA20_POLY1305_SHA256 (0x1303)<br>TLS_AES_128_CCM_SHA256 (0x1304)<br>TLS_AES_128_CCM_8_SHA256 (0x1305)|
| EC dotted format| uncompressed (0)|
| Supported Groups (Key Exchange Groups) | **Traditional Elliptic Curves:**<br>secp256r1 (23)<br>secp384r1 (24)<br>secp521r1 (25)<br>x25519 (29)<br>**Finite Field DH Groups:**<br>ffdhe2048 (256)<br>ffdhe3072 (257)<br>ffdhe4096 (258)<br>ffdhe6144 (259)<br>ffdhe8192 (260)<br>**Hybrid Key Exchange:**<br>X25519MLKEM768 (4588)<br>SecP256r1MLKEM768 (4587)<br>SecP384r1MLKEM1024 (4589) |
| Signature hash algorithm| rsa_pkcs1_sha256 (0x0401)<br>rsa_pkcs1_sha384 (0x0501)<br>rsa_pkcs1_sha512 (0x0601)<br>ecdsa_secp256r1_sha256 (0x0403)<br>ecdsa_secp384r1_sha384 (0x0503)<br>ecdsa_secp521r1_sha512 (0x0603)<br>rsa_pss_rsae_sha256 (0x0804)<br>rsa_pss_rsae_sha384 (0x0805)<br>rsa_pss_rsae_sha512 (0x0806)<br>rsa_pss_pss_sha256 (0x0809)<br>rsa_pss_pss_sha384 (0x080a)<br>rsa_pss_pss_sha512 (0x080b)<br>ed25519 (0x0807)|
| Dual-ended verification| **HITLS_CFG_SetClientVerifySupport** (disabled by default)|
| Blank client certificate| **HITLS_CFG_SetNoClientCertSupport** (disabled by default)|
| Do not verify peer certificate| **HITLS_CFG_SetVerifyNoneSupport** (disabled by default)|
| Verify client certificate only once| **HITLS_CFG_SetClientOnceVerifySupport** (disabled by default)|
| Authentication after handshake| **HITLS_CFG_SetPostHandshakeAuthSupport** (disabled by default)|
| Send handshake packets in a single flight| **HITLS_CFG_SetFlightTransmitSwitch** (disabled by default)|
| Quiet shutdown mode| **HITLS_CFG_SetQuietShutdown** (disabled by default)|
| Extend primary key| **HITLS_CFG_SetExtenedMasterSecretSupport** (enabled by default)|
| Support **sessionTicket**| **HITLS_CFG_SetSessionTicketSupport** (enabled by default)|
| Verify **keyUsage**| **HITLS_CFG_SetCheckKeyUsage** (enabled by default)|
| Auto-generate DH parameter| **HITLS_CFG_SetDhAutoSupport** (enabled by default)|

### Post-Quantum Cryptography Support

openHiTLS supports Hybrid Key Exchange in TLS1.3 to address the threat of future quantum computers to traditional cryptography. The hybrid key exchange scheme combines traditional ECDH key exchange with lattice-based ML-KEM algorithms, providing "defense in depth" security assurance.

**Supported Hybrid Key Exchange Algorithms:**

| Algorithm Name | Components | Security Strength | IANA Code Point | Use Case |
| :---- | :---- | :---- | :---- | :---- |
| X25519MLKEM768 | X25519 + ML-KEM-768 | 192-bit | 4588 | High-performance scenarios, recommended |
| SecP256r1MLKEM768 | ECDH(NIST P-256) + ML-KEM-768 | 192-bit | 4587 | Scenarios requiring NIST curve compatibility |
| SecP384r1MLKEM1024 | ECDH(NIST P-384) + ML-KEM-1024 | 256-bit | 4589 | High-security requirement scenarios |

**Usage Notes:**
- Hybrid key exchange algorithms are only available in TLS 1.3
- X25519MLKEM768 has the highest priority in default configurations
- Requires the `HITLS_TLS_FEATURE_KEM` feature to be enabled at compile time
- Both client and server need to support the same hybrid key exchange algorithm for successful negotiation

**API Configuration Example:**
```c
// Configure supported groups, including hybrid key exchange
uint16_t groups[] = {
    HITLS_HYBRID_X25519_MLKEM768,           // Hybrid key exchange
    HITLS_EC_GROUP_CURVE25519,              // Traditional X25519
    HITLS_EC_GROUP_SECP256R1,               // Traditional NIST P-256
};
HITLS_CFG_SetGroups(config, groups, sizeof(groups) / sizeof(groups[0]));
```

> **NOTE:** Post-quantum cryptographic algorithms have larger key and ciphertext sizes (e.g., X25519MLKEM768 has a public key length of 1216 bytes), which may increase handshake message sizes.

### TLCP Specifications

| Configuration Item| Specifications|
| :---- | :---- |
| TLCP version| TLCP11 (0x0101u)|
| Algorithm suite| ECDHE_SM4_CBC_SM3 (0xE011)<br>ECC_SM4_CBC_SM3 (0xE013)|
| EC dotted format| HITLS_POINT_FORMAT_UNCOMPRESSED (0)|
| Elliptic curve| curveSM2 (41)|
| Signature hash algorithm| sm2sig_sm3 (0x0708)|
| Dual-ended verification| **HITLS_CFG_SetClientVerifySupport** (disabled by default)|
| Blank client certificate| **HITLS_CFG_SetNoClientCertSupport** (disabled by default)|
| Do not verify peer certificate| **HITLS_CFG_SetVerifyNoneSupport** (disabled by default)|
| Verify client certificate only once| **HITLS_CFG_SetClientOnceVerifySupport** (disabled by default)|
| Send handshake packets in a single flight| **HITLS_CFG_SetFlightTransmitSwitch** (disabled by default)|
| Quiet shutdown mode| **HITLS_CFG_SetQuietShutdown** (disabled by default)|
| Verify **keyUsage**| **HITLS_CFG_SetCheckKeyUsage** (enabled by default)|

### Extended Capabilities

| Name| DTLS1.2 | TLS1.2 | TLS1.3 | TLCP |
| :---- | :---- | :---- | :---- | :---- |
| server_name | Yes| Yes| Yes| No|
| supported_groups | Yes| Yes| Yes| Yes|
| ec_point_formats | Yes| Yes| No| Yes|
| signature_algorithms | Yes| Yes| Yes| No|
| application_layer_protocol_negotiation | Yes| Yes| Yes| No|
| extended_master_secret | Yes| Yes| No| No|
| session_ticket | Yes| Yes| No| No|
| encrypt_then_mac | Yes| Yes| No| Yes|
| renegotiation_info | Yes| Yes| No| Yes|
| early_data | No| No| No| No|
| supported_versions | No| No| Yes| No|
| cookie | Yes| No| Yes| No|
| pre_shared_key | No| No| Yes| No|
| psk_key_exchange_modes | No| No| Yes| No|
| certificate_authorities | No| No| No| No|
| oid_filters | No| No| No| No|
| post_handshake_auth | No| No| Yes| No|
| signature_algorithms_cert | No| No| No| No|
| key_share | No| No| Yes| No|

### Framework

![image](../images/Developer%20Guide/Secure%20Communication%20Application%20Development%20Guide_figures/TheFramework.png)

### Context Overview

In openHiTLS, secure transmission context is split into two layers: `HITLS_Config` and `HITLS_Ctx`. `HITLS_Config` is the configuration context, with one context for each service type (like client or server) in a process. `HITLS_Ctx` is the link context, with one context for each connection. The configuration context and link context have a many-to-one relationship, and each link context in openHiTLS has a copy of the configuration context.

### Non-blocking I/O Capability

The protocol module cannot create file descriptions (FDs). Users must create and configure FDs in openHiTLS. Once openHiTLS reads and writes the FDs, users should close them. openHiTLS supports **non-blocking I/O** in both handshake and read/write phases. If calling `HITLS_Read` or `HITLS_Write` returns `HITLS_REC_NORMAL_RECV_BUF_EMPTY` or `HITLS_REC_NORMAL_IO_BUSY`, openHiTLS needs to repeat the read/write operation. In practice, the epoll/select driver is typically used to implement non-blocking I/O capabilities. The following is a piece of exemplary code of non-blocking I/O:

```c
// Shake hands with the client.
do {
    ret = HITLS_Connect(ctx);
} while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
// Shake hands with the server.
do {
    ret = HITLS_Accept(ctx);
} while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
```

> **NOTE:** The `do while` statement serves as a reference only. In practice, the service logic may be implemented in a different manner.

### Constraints

1. The openHiTLS client and server are both authenticated using certificates.
2. Users can quickly get started with openHiTLS using the default configurations provided. Typically, only a few additional configurations based on the defaults are required for openHiTLS to function properly. openHiTLS provides a rich set of configuration interfaces, and an API manual is provided to help product developers configure openHiTLS options as needed.

### Dependencies

The openHiTLS algorithm and certificate are decoupled from the protocol layer. Currently, it provides a self-implemented callback registration capability. The registration-related functions are as follows:

```c
/**
 * @brief   Register the default certificate callback function
 */
int32_t HITLS_CertMethodInit(void);

/**
 * @brief   Register the default algorithm callback function
 */
void HITLS_CryptMethodInit(void);

/**
 * @brief   Registering memory management callback functions
 */
int32_t BSL_SAL_CallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE funcType, void *funcCb);

/**
 * @brief   Initialize global random number
 */
int32_t CRYPT_EAL_RandInit(CRYPT_RAND_AlgId id, CRYPT_RandSeedMethod *seedMeth, void *seedCtx,
    const uint8_t *pers, uint32_t persLen);
```

## Time Sequence Interaction of Secure Communication Applications

![image](../images/Developer%20Guide/Secure%20Communication%20Application%20Development%20Guide_figures/CommunicationApplications.png)

# Example TLS Client

## Client Type

### Certificate Authentication-based Client

To use the certificate authentication-based client, you need both a trust certificate pool and device certificates. The trust certificate pool specifies which certificate authorities the client trusts.

#### Loading Trust Certificates

- The trust certificate pool specifies which certificate authorities the client trusts. It must be configured prior to connection establishment and will then be loaded into the certificate management engine. There are two types of trust certificate pools:

1. Pool used to verify the peer certificate chain
   When using algorithm suites that require server identity verification, the server sends certificates and the certificate chain to the TLS client through handshake messages. If the certificates and certificate chain are not issued by any authority trusted by the client, the client will send a critical alarm and terminate the handshake process. If no trust certificate pool is configured, certificate chain verification will fail, resulting in a TLS handshake failure.

   For the configuration context, users can use the following interface to configure a trust certificate pool for verifying peer certificates:

    ```c
    /**
     * @brief   Set `VerifyStore` for TLS to verify certificates.
     */
    int32_t HITLS_CFG_SetVerifyStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone);
    ```

    For the link context, users can call `HITLS_SetVerifyStore` to set `VerifyStore`.

    > **NOTE:** Calling `HITLS_CFG_NewXXXConfig` will generate a default certificate pool, `CertStore`. If `VerifyStore` is not set, `CertStore` will be used to verify the certificate chain by default.

2. Pool used to generate the local certificate chain
   As part of the handshake process, the server sends its local certificate to the peer for verification. If the certificate chain for the local certificate is not configured, the server will search the trust certificate pool for the chain and send it to the peer. If the server has sent a certificate chain, it can request the TLS client's certificate to verify the client's identity, which is known as ***two-way authentication***. The TLS client will then send its local certificate and certificate chain to the server through handshake messages. If the local certificate is not found in the configured trust certificate pool or the pool is not configured, the client will send an empty certificate message. Whether the handshake can proceed depends on the server's behavior.

   Users can use the following interface to configure a trust certificate pool for generating the local certificate chain:

    ```c
    /**
     * @brief Set the chain store used for TLS configuration to construct a certificate chain.
     */
    int32_t HITLS_CFG_SetChainStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone);
    ```

- Using device certificates and the corresponding certificate chains: The server or client (in two-way authentication) needs to send device certificates and certificate chains to the peer. In addition to the trust certificate pools, the certificate chains can be added based on the device certificates. When certificate chains are sent to the peer, those that match the device certificates are preferred. You can use the following interfaces to add the desired certificate chains:

    ```c
    /**
     * @brief Add certificates to the certificate chain being used by **config**.
     */
    int32_t HITLS_CFG_AddChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone);
    ```

- Adding certificates to the trust certificate pool: After configuring a trust certificate pool, you can add trust certificates to it through the following interface:

    ```c
    /**
     * @brief Add certificates to the specified trust certificate pool.
     */
    int32_t HITLS_CFG_AddCertToStore(HITLS_Config *config, char *certPath, HITLS_CERT_StoreType storeType);
    ```

    > **NOTE:** This interface can be used to add certificates to the default certificate pool, verification certificate pool, and certificate chain pool. The certificates are transferred using relative paths.

#### Configuring Client Certificates

A client certificate is a credential for client identity authentication. In two-way authentication, the TLS client will send its local certificate and certificate chain to the server through handshake messages. If no certificate is found in the client or no certificate is configured by users, the TLS client sends an empty certificate message. Whether the handshake can proceed depends on the server's behavior.

For the configuration context, users can use the following interfaces to configure client certificates:

```c
/**
 * @brief Add device certificates. Only one certificate of each type can be added.
 */
int32_t HITLS_CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone);
/**
 * @brief Load the device certificates from a file.
 */
int32_t HITLS_CFG_LoadCertFile(HITLS_Config *config, const uint8_t *file, HITLS_ParseFormat format);
/**
 * @brief Read the device certificates from the buffer.
 */
int32_t HITLS_CFG_LoadCertBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);
/**
 * @brief Add SM device certificates. Only one certificate of each type can be added.
 */
int32_t HITLS_CFG_SetTlcpCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert);
```

In addition to certificates, you need to configure private keys. Configuring certificates alone will also lead to handshake failure. You can use the following interfaces to configure private keys for certificates in the configuration context:

```c
/**
 * @brief Add private keys for device certificates. Only one private key can be added for each type of certificate.
 */
int32_t HITLS_CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone);
/**
 * @brief Load the private keys of device certificates from a file.
 */
int32_t HITLS_CFG_LoadKeyFile(HITLS_Config *config, const uint8_t *file, HITLS_ParseFormat format);
/**
 * @brief Read the private keys of device certificates from the buffer.
 */
int32_t HITLS_CFG_LoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format);
/**
 * @brief Add SM device certificates. Only one certificate of each type can be added.
 */
int32_t HITLS_CFG_SetTlcpCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert);
```

You can use the following interface to delete all certificates and private keys:

```c
/**
 * @brief Release all loaded certificates and private keys.
 */
int32_t HITLS_CFG_RemoveCertAndKey(HITLS_Config *config);
```

In the link contexts that have been generated, you can use the following interface to delete the certificates and private keys:

```c
/**
 * @brief Release all loaded certificates and private keys.
 */
int32_t HITLS_RemoveCertAndKey(HITLS_Ctx *ctx);
```

> **NOTE:** Each type of certificate and the corresponding private keys can be configured only once. If you try to configure them again, the previous configuration will be overwritten. Certificates of different types are not affected. For example, if two RSA certificates are configured in sequence, only the last one takes effect. If you configure an RSA certificate and an ECDSA certificate in sequence, both certificates take effect.

### PSK Authentication-based Client

The procedure for establishing connections based on PSK negotiation is as follows:

![image](../images/Developer%20Guide/Secure%20Communication%20Application%20Development%20Guide_figures/LinkSetupProcess.PNG)

1. If PSK negotiation is used, the client sends a **ClientHello** message containing the PSK algorithm suite to the server, and the server determines whether to use the PSK algorithm suite.
2. After a specific PSK algorithm suite is selected, the server includes **`identity_hint`** in the **ServerKeyExchange** message to indicate which PSK the client should use.
3. After receiving the **ServerKeyExchange** message containing **`identity_hint`**, the client requests the PSK and identity information from the TLS user through callback.
4. Then, the client includes **`identity`** in the **ClientKeyExchange** message to indicate which PSK the server should use.
5. After receiving the **ClientKeyExchange** message containing **`identity`**, the server requests the PSK from the upper-layer (the TLS user) through callback.
6. Then, the two ends generate a pre-master key based on the obtained PSK individually and clear the PSK. The PSK negotiation process is complete.

Therefore, the client using PSK authentication needs to set a pre-shared key to obtain the following callback information:

```c
/**
 * @brief Obtain the PSK prototype on the client.
 */
typedef uint32_t (*HITLS_PskClientCb)(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen, uint8_t *psk, uint32_t maxPskLen);
/**
 * @brief Set the PSK callback on the client, which is used to obtain an identity and PSK during PSK negotiation.
 */
int32_t HITLS_CFG_SetPskClientCallback(HITLS_Config *config, HITLS_PskClientCb callback);
```

## Sample Code

### Certificate Authentication-based Client

See [client.c](../../../testcode/demo/client.c)

### PSK Authentication-based Client

Most code of PSK Authentication-based client is the same as that Certificate Authentication-based client, except for the configuration of `HITLS_Config`.

```c
...
uint32_t ExampleClientCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen, uint8_t *psk,
    uint32_t maxPskLen)
{
    (void)ctx;
    (void)hint;
    int32_t ret;
    const char pskTrans[] = "psk data";
    uint32_t pskTransUsedLen = sizeof(pskTransUsedLen);
    if (memcpy_s(identity, maxIdentityLen, "hello", strlen("hello") + 1) != EOK) {
        return 0;
    }
    if (memcpy_s(psk, maxPskLen, pskTrans, pskTransUsedLen) != EOK) {
        return 0;
    }
    return pskTransUsedLen;
}


int main(int32_t argc, char *argv[])
{
    ...
    config = HITLS_CFG_NewTLS12Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config failed.\n");
        return -1;
    }
    uint16_t cipherSuite = HITLS_PSK_WITH_AES_128_GCM_SHA256;
    // config cipher suite
    if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetCipherSuites err\n");
        return -1;
    }
    // config PSK callbacks
    if (HITLS_CFG_SetPskClientCallback(config, (HITLS_PskClientCb)ExampleClientCb) != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetPskClientCallback err\n");
        return -1;
    }

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed.\n");
        goto EXIT;
    }

    ...
}
```

### TLCP Client

The steps except for the following are the same as those described in "Certificate Authentication-based Client."

```c
config = HITLS_CFG_NewTLCPConfig();
if (config == NULL) {
    printf("HITLS_CFG_NewTLCPConfig failed.\n");
    return -1;
}
uint16_t cipherSuite = HITLS_ECC_SM4_CBC_SM3;
// Configure the algorithm suite.
if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
    printf("HITLS_CFG_SetCipherSuites err\n");
    return -1;
}

/* Load certificates. This capability needs to be implemented by users. */
HITLS_CFG_AddCertToStore(config, "rootCA.pem", TLS_CERT_STORE_TYPE_DEFAULT);
HITLS_CFG_AddCertToStore(config, "intCA.pem", TLS_CERT_STORE_TYPE_DEFAULT);
// In two-way authentication scenarios, load the signature certificate and private key from a file. This capability needs to be implemented by users.
HITLS_CERT_X509 *signCert = LoadCertFromFile("ClientSignCert.pem");
HITLS_CERT_X509 *signKey =  LoadKeyFromFile("ClientSignKey.pem");
// Load the encryption certificate and private key from a file.
HITLS_CERT_X509 *encCert = LoadCertFromFile("ClientEncCert.pem");
HITLS_CERT_X509 *encKey = LoadKeyFromFile("ClientEncKey.pem");
//Add the SM signature certificate and private key.
HITLS_CFG_SetTlcpCertificate(config, signCert, false, false);
HITLS_CFG_SetTlcpPrivateKey(config, signKey, false, false);
//Add the SM encryption certificate and private key.
HITLS_CFG_SetTlcpCertificate(config, signCert, false, true);
HITLS_CFG_SetTlcpPrivateKey(config, signKey, false, true);
...
```

# Example TLS Server

## Server Type

### Certificate Authentication-based Server

To use the certificate authentication-based TLS server, you need both a trust certificate pool and device certificates. The trust certificate pool specifies which certificate authorities the client trusts. A device certificate is a credential for server identity authentication. The server can determine whether to verify the client identity based on two-way authentication configuration items.

#### Configuring the Two-Way Authentication Server

If the server has sent a certificate chain, it can request the TLS client's certificate to verify the client's identity, which is known as two-way authentication.
openHiTLS provides the following configuration items:

1. Two-way authentication
   This function is disabled by default. That is, the server does not verify the client identity by default. You can control the function through the `HITLS_CFG_SetClientVerifySupport` interface.

```c
/**
 * @brief Set whether to verify the client certificate.
            This setting has no impact on the client.
            The server sends a certificate request.
 */
int32_t HITLS_CFG_SetClientVerifySupport(HITLS_Config *config, bool support);
```

2. Acceptance of no client certificates
   This setting takes effect only when two-way authentication is enabled. It is disabled by default, meaning that the TLS server must verify the client certificate. If the certificate chain sent by the client is empty or fails verification, the TLS server sends a critical alarm and terminates the handshake.
   You can control the function through the `HITLS_CFG_SetNoClientCertSupport` interface.

```c
/**
 * @brief Set whether to accept the scenario without any client certificates. This setting takes effect only when client certificate verification is enabled.
            This setting has no impact on the client.
            The server checks whether the certificate verification is successful when receiving an empty certificate from the client. The verification fails by default.
 */
int32_t HITLS_CFG_SetNoClientCertSupport(HITLS_Config *config, bool support);
```

#### Loading Trust Certificate Pools

Refer to "Loading Trust Certificates."

#### Configuring Server Certificates

If the algorithm suite requires server identity verification, users need to configure the server certificates, certificate chain, and private keys. Refer to "Configuring Client Certificates."

### PSK Authentication-based Server

The callback for the PSK authentication-based server to obtain the pre-shared key is slightly different from that used by the client, as shown below:

```c
/**
 * @brief Server PSK negotiation callback
*/
typedef int32_t (*HITLS_PskFindSessionCb)(HITLS_Ctx *ctx, const uint8_t *identity, uint32_t identityLen,
    HITLS_Session **session);
/**
 * @brief Set the callback for the PSK authentication-based server, which is used to obtain a PSK during PSK negotiation.
 */
int32_t HITLS_CFG_SetPskServerCallback(HITLS_Config *config, HITLS_PskServerCb callback);
```

For details about the remaining procedure, see "PSK Authentication-based Client."

## Sample Code

### Certificate Authentication-based Server

See [server.c](../../../testcode/demo/server.c)

### ### PSK Authentication-based Server

Most code of PSK Authentication-based server is the same as that Certificate Authentication-based server, except for the configuration of `HITLS_Config`.

```c
...

uint32_t ExampleServerCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen)
{
    (void)ctx;
    if (identity == NULL || strcmp((const char *)identity, "hello") != 0) {
        return 0;
    }
    const char pskTrans[] = "psk data";
    uint32_t pskTransUsedLen = sizeof(pskTransUsedLen);
    if (memcpy_s(psk, maxPskLen, pskTrans, pskTransUsedLen) != EOK) {
        return 0;
    }
    return pskTransUsedLen;
}

int main(int32_t argc, char *argv[])
{
    ...
    config = HITLS_CFG_NewTLS12Config();
    if (config == NULL) {
        printf("HITLS_CFG_NewTLS12Config failed.\n");
        return -1;
    }
    uint16_t cipherSuite = HITLS_PSK_WITH_AES_128_GCM_SHA256;
    // config cipher suite
    if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetCipherSuites err\n");
        return -1;
    }
    // config PSK callback
    if (HITLS_CFG_SetPskServerCallback(tlsConfig, (HITLS_PskServerCb)ExampleServerCb) != HITLS_SUCCESS) {
        printf("HITLS_CFG_SetPskClientCallback err\n");
        return -1;
    }

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("HITLS_New failed.\n");
        goto EXIT;
    }

    ...
}
```

### TLCP Server

The steps except for the following are the same as those described in "Certificate Authentication-based Server."

```c
...
config = HITLS_CFG_NewTLCPConfig();
if (cfg == NULL) {
    printf("HITLS_CFG_NewTLCPConfig failed.\n");
    return -1;
}

uint16_t cipherSuite = HITLS_ECC_SM4_CBC_SM3;
// Configure the algorithm suite.
if (HITLS_CFG_SetCipherSuites(config, &cipherSuite, 1) != HITLS_SUCCESS) {
    printf("HITLS_CFG_SetCipherSuites err\n");
    return -1;
}

if (HITLS_CFG_SetClientVerifySupport(config, true) != HITLS_SUCCESS) {
    printf("HITLS_CFG_SetClientVerifySupport err\n");
    return -1;
}

/* Load certificates. This capability needs to be implemented by users. */
HITLS_CFG_AddCertToStore(config, "rootCA.pem", TLS_CERT_STORE_TYPE_DEFAULT);
HITLS_CFG_AddCertToStore(config, "intCA.pem", TLS_CERT_STORE_TYPE_DEFAULT);
// Load the signature certificate and private key from a file. This capability needs to be implemented by users.
HITLS_CERT_X509 *signCert = LoadCertFromFile("ServerSignCert.pem");
HITLS_CERT_X509 *signKey =  LoadKeyFromFile("ServerSignKey.pem");
// Load the encryption certificate and private key from a file.
HITLS_CERT_X509 *encCert = LoadCertFromFile("ServerEncCert.pem");
HITLS_CERT_X509 *encKey = LoadKeyFromFile("ServerEncKey.pem");
//Add the SM signature certificate and private key.
HITLS_CFG_SetTlcpCertificate(config, signCert, false, false);
HITLS_CFG_SetTlcpPrivateKey(config, signKey, false, false);
//Add the SM encryption certificate and private key.
HITLS_CFG_SetTlcpCertificate(config, signCert, false, true);
HITLS_CFG_SetTlcpPrivateKey(config, signKey, false, true);
...
```

# Example of TLS Session Key Update

## Update Type

### TLS1.2/TLCP or DTLS1.2/TLCP Renegotiation Example

TLS1.2/TLCP or DTLS1.2/TLCP supports security renegotiation. The renegotiation function enables the client or server to initiate a new negotiation over the same security connection to generate a new key. This function applies to connections that require high confidentiality and transmit a large amount of data.
The security renegotiation procedure is as follows:

![image](../images/Developer%20Guide/Secure%20Communication%20Application%20Development%20Guide_figures/SecurityRenegotiationProcedure.png)

> **NOTE:** Users can enter the renegotiation state through the `HITLS_Renegotiate` interface and trigger renegotiation handshakes through the `HITLS_Accept`, `HITLS_Connect`, `HITLS_Write`, or `HITLS_Read` interface. The `HITLS_Accept` and `HITLS_Connect` interfaces are recommended.

**Client example**

```c
/* Exchange data at the application layer. */
const uint8_t sndBuf[] = "Hi, this is client\n";
uint32_t writeLen = 0;
ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Write error:error code:%d\n", ret);
    goto EXIT;
}
uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
uint32_t readLen = 0;
ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Read failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
/* The client enters the renegotiation state. */
ret = HITLS_Renegotiate(ctx);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Renegotiate error:error code:%d\n", ret);
    goto EXIT;
}
/* The client initiates a handshake, and the server processes the handshake through the `HITLS_Read` interface. */
ret = HITLS_Connect(ctx);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Connect failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
/* The renegotiation is complete, and the data exchange at the application layer proceeds. */
```

**Server example**

```c
/* Exchange data at the application layer. */
uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
uint32_t readLen = 0;
ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Read failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
const uint8_t sndBuf[] = "Hi, this is server\n";
uint32_t writeLen = 0;
ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Write error:error code:%d\n", ret);
    goto EXIT;
}
/* The server enters the renegotiation state. */
ret = HITLS_Renegotiate(ctx);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Renegotiate error:error code:%d\n", ret);
    goto EXIT;
}
/* The server initiates a handshake, and the client processes the handshake through the `HITLS_Read` interface. */
ret = HITLS_Accept(ctx);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Accept failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
/* The renegotiation is complete, and the data exchange at the application layer proceeds. */
```

### Example of TLS1.3 Key Update

TLS1.3 supports key update after connection establishment. The involved functions are as follows:

```c
/**
 * @brief Set the `KeyUpdate` type and send a `KeyUpdate` message to the peer.
 */
int32_t HITLS_KeyUpdate(HITLS_Ctx *ctx, uint32_t updateType);
```

The following `KeyUpdate` types are supported:

```c
The HITLS_UPDATE_NOT_REQUESTED = 0, // The peer does not have to reply to the `KeyUpdate` message.
HITLS_UPDATE_REQUESTED = 1, // The peer must reply to the `KeyUpdate` message.
```

**Client example**

```c
/* Exchange data at the application layer. */
uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
uint32_t readLen = 0;
ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Read failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
const uint8_t sndBuf[] = "Hi, this is server\n";
uint32_t writeLen = 0;
ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Write error:error code:%d\n", ret);
    goto EXIT;
}
/* The client initiates a `KeyUpdate` message that does not require replies from the peer. The peer processes the message through the `HITLS_Read` interface. */
ret = HITLS_KeyUpdate(ctx, HITLS_UPDATE_NOT_REQUESTED);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_KeyUpdate error:error code:%d\n", ret);
    goto EXIT;
}
/* The key update process is complete. */
```

**Server example**

```c
/* Exchange data at the application layer. */
uint8_t readBuf[HTTP_BUF_MAXLEN + 1] = {0};
uint32_t readLen = 0;
ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Read failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
const uint8_t sndBuf[] = "Hi, this is server\n";
uint32_t writeLen = 0;
ret = HITLS_Write(ctx, sndBuf, sizeof(sndBuf), &writeLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Write error:error code:%d\n", ret);
    goto EXIT;
}
/* The server initiates a `KeyUpdate` message that requires replies from the peer. The peer processes the message through the `HITLS_Read` interface and returns replies to the `KeyUpdate` message. */
ret = HITLS_KeyUpdate(ctx, HITLS_UPDATE_REQUESTED);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_KeyUpdate error:error code:%d\n", ret);
    goto EXIT;
}
/* The `HITLS_Read` interface receives the peer's replies to the `KeyUpdate` message. */
ret = HITLS_Read(ctx, readBuf, HTTP_BUF_MAXLEN, &readLen);
if (ret != HITLS_SUCCESS) {
    printf("HITLS_Read failed, ret = 0x%x.\n", ret);
    goto EXIT;
}
/* The key update process is complete. */
```

