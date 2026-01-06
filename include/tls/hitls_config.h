/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/**
 * @defgroup hitls_config
 * @ingroup  hitls
 * @brief    TLS parameter configuration
 */

#ifndef HITLS_CONFIG_H
#define HITLS_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_type.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup hitls_config
* @brief   (D)TLCP 1.1 version
*/
#define HITLS_VERSION_TLCP_DTLCP11 0x0101u

/**
 * @ingroup  hitls_config
 * @brief    TLS any version
*/
#define HITLS_TLS_ANY_VERSION 0x03ffu

/**
 * @ingroup  hitls_config
 * @brief    SSL3.0 version number
*/
#define HITLS_VERSION_SSL30 0x0300u

/**
 * @ingroup  hitls_config
 * @brief    TLS1.0 version number
*/
#define HITLS_VERSION_TLS10 0x0301u

/**
 * @ingroup  hitls_config
 * @brief    TLS1.1 version number
*/
#define HITLS_VERSION_TLS11 0x0302u

/**
  * @ingroup  hitls_config
  * @brief    TLS1.2 version
 */
#define HITLS_VERSION_TLS12 0x0303u

/**
  * @ingroup  config
  * @brief    TLS 1.3 version
 */
#define HITLS_VERSION_TLS13 0x0304u

/**
  * @ingroup  config
  * @brief    Prefix of SSL 3.0 or later
 */
#define HITLS_VERSION_TLS_MAJOR 0x03u

/**
 * @ingroup  hitls_config
 * @brief    DTLS any version
*/
#define HITLS_DTLS_ANY_VERSION 0xfe00u

/**
  * @ingroup hitls_config
  * @brief   DTLS 1.2 version
 */
#define HITLS_VERSION_DTLS12 0xfefdu

/**
  * @ingroup hitls_config
  * @brief Maximum size of the configuration data
 */
#define HITLS_CFG_MAX_SIZE 1024

/**
  * @ingroup hitls_config
  * @brief Configure the maximum size of the TLS1_3 cipher suite
 */
#define TLS13_CIPHERSUITES_MAX_LEN 80

/**
  * @ingroup hitls_config
  * @brief   enumerate ciphersuites supported by HITLS with IANA coding
 * */
typedef enum {
    HITLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
    HITLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
    HITLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
    HITLS_DH_ANON_WITH_AES_128_CBC_SHA = 0x0034,
    HITLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    HITLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
    HITLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
    HITLS_DH_ANON_WITH_AES_256_CBC_SHA = 0x003A,
    HITLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
    HITLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
    HITLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040,
    HITLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
    HITLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A,
    HITLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,
    HITLS_DH_ANON_WITH_AES_128_CBC_SHA256 = 0x006C,
    HITLS_DH_ANON_WITH_AES_256_CBC_SHA256 = 0x006D,
    HITLS_PSK_WITH_AES_128_CBC_SHA = 0x008C,
    HITLS_PSK_WITH_AES_256_CBC_SHA = 0x008D,
    HITLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090,
    HITLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091,
    HITLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094,
    HITLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095,
    HITLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
    HITLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
    HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,
    HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,
    HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2,
    HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3,
    HITLS_DH_ANON_WITH_AES_128_GCM_SHA256 = 0x00A6,
    HITLS_DH_ANON_WITH_AES_256_GCM_SHA384 = 0x00A7,
    HITLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8,
    HITLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9,
    HITLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA,
    HITLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB,
    HITLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC,
    HITLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD,
    HITLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE,
    HITLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF,
    HITLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2,
    HITLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3,
    HITLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6,
    HITLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7,
    HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
    HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,
    HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
    HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
    HITLS_ECDH_ANON_WITH_AES_128_CBC_SHA = 0xC018,
    HITLS_ECDH_ANON_WITH_AES_256_CBC_SHA = 0xC019,
    HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
    HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024,
    HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
    HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,
    HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
    HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
    HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
    HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
    HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035,
    HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036,
    HITLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037,
    HITLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038,
    HITLS_RSA_WITH_AES_128_CCM = 0xC09C,
    HITLS_RSA_WITH_AES_256_CCM = 0xC09D,
    HITLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E,
    HITLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F,
    HITLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0,
    HITLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1,
    HITLS_PSK_WITH_AES_256_CCM = 0xC0A5,
    HITLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6,
    HITLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7,
    HITLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC,
    HITLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD,
    HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
    HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA,
    HITLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB,
    HITLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC,
    HITLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD,
    HITLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE,
    HITLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xD001,
    HITLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xD002,
    HITLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 0xD005,

    /* TLS1.3 cipher suite */
    HITLS_AES_128_GCM_SHA256 = 0x1301,
    HITLS_AES_256_GCM_SHA384 = 0x1302,
    HITLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    HITLS_AES_128_CCM_SHA256 = 0x1304,
    HITLS_AES_128_CCM_8_SHA256 = 0x1305,
    /* TLCP 1.1 cipher suite */
    HITLS_ECDHE_SM4_CBC_SM3 = 0xE011,
    HITLS_ECC_SM4_CBC_SM3 = 0xE013,
    HITLS_ECDHE_SM4_GCM_SM3 = 0xE051,
    HITLS_ECC_SM4_GCM_SM3 = 0xE053,
} HITLS_CipherSuite;

/**
 * @ingroup hitls_config
 * @brief   Create DTLS12 configuration items, including the default settings. The user can call the
 *          HITLS_CFG_SetXXX interface to modify the settings.
 *
 * @attention The default configuration is as follows:
    Version number: HITLS_VERSION_DTLS12
    Algorithm suite: HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256, HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:secp256r1, secp384r1, secp521r1, x25519, x448
    Extended Master Key: Not Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    Renegotiation: Not supported
    This API is a version-specific API. After the configuration context is created,
    the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport, HITLS_CFG_SetVersionSupport,
    HITLS_SetMinProtoVersion, or HITLS_SetMaxProtoVersion interface cannot be used to set other supported versions.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_NewDTLS12Config(void);

/**
 * @ingroup hitls_config
 * @brief   Create DTLS12 configuration items with provider, including the default settings. Same as HITLS_CFG_NewDTLS12Config
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewDTLS12Config(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Create TLCP configuration items, including default settings.
 *
 * The user can call the HITLS_CFG_SetXXX interface to modify the settings.
 *
 * @attention   The default configuration is as follows:
    Version number: HITLS_VERSION_TLCP_DTLCP11
    Algorithm suite: HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3, HITLS_ECDHE_SM4_GCM_SM3, HITLS_ECC_SM4_GCM_SM3
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:sm2
    Extended Master Key: Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    Renegotiation: Not supported
    This API is a version-specific API. After the configuration context is created,
    the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport, HITLS_CFG_SetVersionSupport,
    HITLS_SetMinProtoVersion, or HITLS_SetMaxProtoVersion interface cannot be used to set other supported versions.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, object application failed.
 */
HITLS_Config *HITLS_CFG_NewTLCPConfig(void);

/**
 * @ingroup hitls_config
 * @brief   Create TLCP configuration items with provider, including the default settings. Same as HITLS_CFG_NewTLCPConfig
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewTLCPConfig(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Create DTLCP configuration items, including the default settings. The user can call the
 *          HITLS_CFG_SetXXX interface to modify the settings.
 *
 * @attention The default configuration is as follows:
    Version number: HITLS_VERSION_TLCP_DTLCP11
    Algorithm suite: HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3, HITLS_ECDHE_SM4_GCM_SM3, HITLS_ECC_SM4_GCM_SM3
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:sm2
    Extended Master Key: Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    Renegotiation: Not supported
    This API is a version-specific API. After the configuration context is created,
    the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport, HITLS_CFG_SetVersionSupport,
    HITLS_SetMinProtoVersion, or HITLS_SetMaxProtoVersion interface cannot be used to set other supported versions.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, object application failed.
 */
HITLS_Config *HITLS_CFG_NewDTLCPConfig(void);

/**
 * @ingroup hitls_config
 * @brief   Create DTLCP configuration items with provider, including the default settings. Same as HITLS_CFG_NewDTLCPConfig
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewDTLCPConfig(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Create a TLS12 configuration item, including the default configuration.
 *
 * The user can call the HITLS_CFG_SetXXX interface to modify the configuration.
 *
 * @attention   The default configuration is as follows:
    Version number: HITLS_VERSION_TLS12
    Algorithm suite: HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256, HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:secp256r1, secp384r1, secp521r1, x25519, x448
    Extended Master Key: Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    Renegotiation: Not supported
    This API is a version-specific API. After the configuration context is created,
    the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport, HITLS_CFG_SetVersionSupport,
    HITLS_SetMinProtoVersion, or HITLS_SetMaxProtoVersion interface cannot be used to set other supported versions.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, object application failed.
 */
HITLS_Config *HITLS_CFG_NewTLS12Config(void);

/**
 * @ingroup hitls_config
 * @brief   Create TLS12 configuration items with provider, including the default settings. Same as HITLS_CFG_NewTLS12Config
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewTLS12Config(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Creates the default TLS13 configuration.
 *
 * The HITLS_CFG_SetXXX interface can be used to modify the default TLS13 configuration.
 *
 * @attention   The default configuration is as follows:
    Version number: HITLS_VERSION_TLS13
    Algorithm suite: HITLS_AES_128_GCM_SHA256, HITLS_CHACHA20_POLY1305_SHA256, HITLS_AES_128_GCM_SHA256
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:secp256r1, secp384r1, secp521r1, x25519, x448
    Extended Master Key: Enabled
    Signature algorithm: rsa, ecdsa, eddsa
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    This API is a version-specific API. After the configuration context is created,
    the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport,
    HITLS_CFG_SetVersionSupport, HITLS_SetMinProtoVersion, and HITLS_SetMaxProtoVersion
    interface cannot be used to set other supported versions.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object
 */
HITLS_Config *HITLS_CFG_NewTLS13Config(void);

/**
 * @ingroup hitls_config
 * @brief   Create TLS13 configuration items with provider, including the default settings. Same as HITLS_CFG_NewTLS13Config
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewTLS13Config(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Create full TLS configurations. The HITLS_CFG_SetXXX interface can be used to modify the configurations.
 *
 * @attention   The default configuration is as follows:
    Version number: HITLS_VERSION_TLS12, HITLS_VERSION_TLS13
    Algorithm suite: HITLS_AES_128_GCM_SHA256, HITLS_CHACHA20_POLY1305_SHA256, HITLS_AES_128_GCM_SHA256
            HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            HITLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, HITLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            HITLS_DHE_RSA_WITH_AES_256_CBC_SHA, HITLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            HITLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, HITLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            HITLS_RSA_WITH_AES_256_CBC_SHA, HITLS_RSA_WITH_AES_128_CBC_SHA,
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:secp256r1, secp384r1, secp521r1, x25519, x448, brainpool256r1, brainpool384r1, brainpool521r1
    Extended Master Key: Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    This interface is a unified configuration interface. After a configuration context is created,
    it can be used with the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport,
    HITLS_CFG_SetVersionSupport, HITLS_SetMinProtoVersion, and HITLS_SetMaxProtoVersion are used together,
    Set the supported version. However, only the TLS configuration item is configured in this interface.
    Therefore, the DTLS version cannot be set.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, object application failed.
 */
HITLS_Config *HITLS_CFG_NewTLSConfig(void);

/**
 * @ingroup hitls_config
 * @brief   Create TLS configuration items with provider, including the default settings. Same as HITLS_CFG_NewTLSConfig
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewTLSConfig(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Create full DTLS configurations. The HITLS_CFG_SetXXX interface can be called
 * to modify the DTLS configuration.
 *
 * @attention   The default configuration is as follows:
    Version number: HITLS_VERSION_DTLS10, HITLS_VERSION_DTLS12
    Algorithm suite: HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            HITLS_DHE_DSS_WITH_AES_256_GCM_SHA384, HITLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            HITLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            HITLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, HITLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            HITLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    EC point format: HITLS_POINT_FORMAT_UNCOMPRESSED
    groups:secp256r1, secp384r1, secp521r1, x25519, x448, brainpool256r1, brainpool384r1, brainpool521r1
    Extended Master Key: Enabled
    Signature algorithm: All signature algorithms in the HITLS_SignHashAlgo table
    Dual-ended check: Disabled
    Allow Client No Certificate: Not Allowed
    This interface is a unified configuration interface. After a configuration context is created,
    it can be used with the HITLS_SetVersion, HITLS_CFG_SetVersion, HITLS_SetVersionSupport,
    HITLS_CFG_SetVersionSupport, HITLS_SetMinProtoVersion, and HITLS_SetMaxProtoVersion are used together,
    Set the supported version. However, only the DTLS configuration item is configured in this interface.
    Therefore, the TLS version cannot be set.
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, Object application failed.
 */
HITLS_Config *HITLS_CFG_NewDTLSConfig(void);

/**
 * @ingroup hitls_config
 * @brief   Create DTLS configuration items with provider, including the default settings. Same as HITLS_CFG_NewDTLSConfig
 * except that it requires libCtx and attribute parameters.
 *
 * @param[in] libCtx: The library context.
 * @param[in] attrName: The attribute name.
 *
 * @retval  HITLS_Config, object pointer succeeded.
 * @retval  NULL, failed to apply for the object.
 * @see HITLS_CFG_FreeConfig
 */
HITLS_Config *HITLS_CFG_ProviderNewDTLSConfig(HITLS_Lib_Ctx *libCtx, const char *attrName);

/**
 * @ingroup hitls_config
 * @brief   Release the config file.
 *
 * @param   config [OUT] Config handle.
 * @retval  void
 */
void HITLS_CFG_FreeConfig(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   The reference counter of config increases by 1.
 *
 * @param   config [OUT] Config handle.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_UpRef(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Set the supported version number range.
 *
 * @param   config      [OUT] Config handle
 * @param   minVersion  [IN] Minimum version number
 * @param   maxVersion  [IN] Maximum version number
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS.
 *              Currently, only DTLS 1.2.
 * HITLS_CFG_NewDTLSConfig, HITLS_CFG_NewTLSConfig can be used with full configuration interfaces.
 * If TLS full configuration is configured, only the TLS version can be set.
 * If DTLS full configuration is configured, only the DTLS version can be set.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetVersion(HITLS_Config *config, uint16_t minVersion, uint16_t maxVersion);

/**
 * @ingroup hitls_config
 * @brief   Setting the disabled version number.
 *
 * @param   config  [OUT] Config handle
 * @param   noversion [IN] Disabled version number.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetVersionForbid(HITLS_Config *config, uint32_t noVersion);

/**
 * @ingroup hitls_config
 * @brief   Set whether to support renegotiation.
 *
 * @param   config   [OUT] Config handle
 * @param   support  [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetRenegotiationSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Set whether to allow a renegotiate request from the client
 * @param   config   [OUT] Config handle
 * @param   support  [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetClientRenegotiateSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Set whether to abort handshake when server doesn't support SecRenegotiation
 * @param   config   [OUT] Config handle
 * @param   support  [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetLegacyRenegotiateSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Set whether to support session restoration during renegotiation.
 * By default, session restoration is not supported.
 * @param   config   [OUT] Config handle
 * @param   support  [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetResumptionOnRenegoSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Sets whether to verify the client certificate.
 *          Client: This setting has no impact
 *          Server: The certificate request will be sent.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Indicates whether the client certificate can be verified.True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, The config parameter is empty.
 * @attention The settings on the client are invalid. Only the settings on the server take effect.
 *             If this parameter is not set, single-ended verification is used by default.
 */
int32_t HITLS_CFG_SetClientVerifySupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Sets whether to allow the client certificate to be empty.
 *          This parameter takes effect only when client certificate verification is enabled.
 *          Client: This setting has no impact
 *          Server: Check whether the certificate passes the verification when receiving an empty
 *                certificate from the client. The verification fails by default.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Indicates whether the authentication is successful when no client certificate is available.
            true: The server still passes the verification when the certificate sent by the client is empty.
            false: The server fails to pass the verification when the certificate sent by the client is empty.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, The config parameter is empty.
 */
int32_t HITLS_CFG_SetNoClientCertSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Sets whether to forcibly support extended master keys.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Indicates whether to forcibly support extended master keys.
                         The options are as follows: True: yes; False: no. The default value is true.
 * @retval  HITLS_SUCCESS.
 * @retval  HITLS_NULL_INPUT, config is NULL
 */
int32_t HITLS_CFG_SetExtendedMasterSecretSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Set whether the DH parameter can be automatically selected by users.
 *
 * If the value is true, the DH parameter is automatically selected based on the length of the
 * certificate private key. If the value is false, the DH parameter needs to be set.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Whether to support the function. The options are as follows: True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetDhAutoSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Set the DH parameter specified by the user.
 *
 * @param   config  [OUT] Config handle
 * @param   dhPkey [IN] User-specified DH key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is empty, or dhPkey is empty.
 */
int32_t HITLS_CFG_SetTmpDh(HITLS_Config *config, HITLS_CRYPT_Key *dhPkey);

/**
 * @ingroup hitls_config
 * @brief   Query whether renegotiation is supported.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Whether to support renegotiation
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetRenegotiationSupport(const HITLS_Config *config, bool *isSupport);


/**
 * @ingroup hitls_config
 * @brief   Query whether the client certificate can be verified.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether to verify the client certificate.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetClientVerifySupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Query whether support there is no client certificate. This parameter takes effect
 * only when the client certificate is verified.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether to support the function of not having a client certificate.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetNoClientCertSupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Query whether extended master keys are supported.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether to support the extended master key.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetExtendedMasterSecretSupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Query whether the DH parameter can be automatically selected by the user. If yes,
 * the DH parameter will be automatically selected based on the length of the certificate private key.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether to support the function of automatically selecting the DH parameter.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetDhAutoSupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Setting whether to support post-handshake auth takes effect only for TLS1.3.
            client: If the client supports pha, the client sends pha extensions.
            Server: supports pha. After the handshake, the upper-layer interface HITLS_VerifyClientPostHandshake
               initiates certificate verification.
 *
 * @param   config  [OUT] Config handle
 * @param   support [IN] Whether to support pha
            True: pha is supported.
            False: pha is not supported.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, The config parameter is empty.
 * @attention Before enabling this function on the server, enable HITLS_CFG_SetClientVerifySupport.
 * Otherwise, the configuration does not take effect.
 */
int32_t HITLS_CFG_SetPostHandshakeAuthSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Query whether the post-handshake AUTH function is supported.
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether to support post-handshake AUTH.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetPostHandshakeAuthSupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Sets whether to support not perform dual-ended verification
 *
 * @param   support [IN] True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetVerifyNoneSupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Query whether not perform dual-ended verification is supported
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether not perform dual-ended verification is supported
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetVerifyNoneSupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Set whether request client certificate only once is supported
 *
 * @param   config  [OUT] TLS link configuration
 * @param   support [IN] True: yes; False: no.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetClientOnceVerifySupport(HITLS_Config *config, bool support);

/**
 * @ingroup hitls_config
 * @brief   Query whether request client certificate only once is supported
 *
 * @param   config   [IN] Config handle
 * @param   isSupport   [OUT] Indicates whether the client certificate can be requested only once.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetClientOnceVerifySupport(HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief  Set the supported cipher suites. The sequence of the cipher suites affects the priority of the selected
 * cipher suites. The cipher suite with the highest priority is the first.
 * @attention This setting will automatically filter out unsupported cipher suites.
 * @param   config [OUT] Config handle.
 * @param   cipherSuites [IN] cipher suite array, corresponding to the HITLS_CipherSuite enumerated value.
 * @param   cipherSuitesSize [IN] cipher suite array length.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetCipherSuites(HITLS_Config *config, const uint16_t *cipherSuites, uint32_t cipherSuitesSize);

/**
 * @ingroup hitls_config
 * @brief   Clear the TLS1.3 cipher suite.
 *
 * @param   config [IN] Config handle.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_ClearTLS13CipherSuites(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Set the format of the ec point.
 *
 * @attention Currently, this parameter can only be set to HITLS_ECPOINTFORMAT_UNCOMPRESSED.
 *
 * @param   config [OUT] Config context.
 * @param   pointFormats [IN] EC point format, corresponding to the HITLS_ECPointFormat enumerated value.
 * @param   pointFormatsSize [IN] EC point format length
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetEcPointFormats(HITLS_Config *config, const uint8_t *pointFormats, uint32_t pointFormatsSize);

/**
 * @ingroup hitls_config
 * @brief   Set the group supported during key exchange. The group supported
 * by HiTLS can be queried in HITLS_NamedGroup.
 *
 * @attention If a group is not supported, an error will be reported during configuration check.
 * @param   config [OUT] Config context.
 * @param   groups [IN] Key exchange group. Corresponds to the HITLS_NamedGroup enumerated value.
 * @param   groupsSize [IN] Group length
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetGroups(HITLS_Config *config, const uint16_t *groups, uint32_t groupsSize);

/**
 * @ingroup hitls_config
 * @brief   Set the signature algorithms supported during negotiation. The signature algorithms supported
 * by the HiTLS can be queried in the HITLS_SignHashAlgo file.
 *
 * @attention If an unsupported signature algorithm is set, an error will be reported during configuration check.
 * @param   config      [OUT] Config context
 * @param   signAlgs    [IN] Signature algorithm array, that is, the enumerated value of HITLS_SignHashAlgo.
 * @param   signAlgsSize [IN] Signature algorithm array length
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSignature(HITLS_Config *config, const uint16_t *signAlgs, uint16_t signAlgsSize);

/**
 * @ingroup hitls_config
 * @brief   Add the CA indicator, which is used when the peer certificate is requested.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   caType  [IN] CA indication type
 * @param   data [IN] CA indication data
 * @param   len [IN] Data length
 * @retval  HITLS_SUCCESS, if successful.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_AddCAIndication(HITLS_Config *config, HITLS_TrustedCAType caType, const uint8_t *data, uint32_t len);

/**
 * @ingroup hitls_config
 * @brief   Obtain the CA list.
 *
 * @param   config [OUT] TLS link configuration
 * @retval  CA list
 */
HITLS_TrustedCAList *HITLS_CFG_GetCAList(const HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Clear the CA list.
 * @param   config [OUT] TLS link configuration
 * @retval  CA list
 */
void HITLS_CFG_ClearCAList(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Set the key exchange mode, which is used by TLS1.3.
 *
 * @param   config  [OUT] TLS link configuration
 * @param   mode  [IN] PSK key exchange mode. Currently, only TLS13_KE_MODE_PSK_ONLY and TLS13_KE_MODE_PSK_WITH_DHE
 *                     are supported. The corresponding bit is set to 1.
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetKeyExchMode(HITLS_Config *config, uint32_t mode);

/**
 * @ingroup hitls_config
 * @brief   Obtain the key exchange mode, which is used by TLS1.3.
 *
 * @param   config  [OUT] TLS link configuration
 * @retval  Key exchange mode
 */
uint32_t HITLS_CFG_GetKeyExchMode(HITLS_Config *config);

/* If the ClientHello callback is successfully executed, the handshake continues */
#define HITLS_CONTINUE_HANDHSAKE 1
/* The  ClientHello callback fails. Send an alert message and terminate the handshake */
#define HITLS_ALERT_HANDSHAKE 0

/**
 * @ingroup hitls_config
 * @brief   ClientHello callback prototype for the server to process the callback.
 *
 * @param   ctx  [IN] Ctx context
 * @param   alert   [OUT] The callback that returns a failure should indicate the alert value to be sent in al.
 * @param   arg  [IN] Product input context
 * @retval  HITLS_CONTINUE_HANDHSAKE: successful. Other values are considered as failure.
 */
typedef int32_t (*HITLS_ClientHelloCb)(HITLS_Ctx *ctx, int32_t *alert, void *arg);

/**
 * @ingroup hitls_config
 * @brief   Set the ClientHello callback on the server.
 *
 * @param   config [OUT] Config context
 * @param   callback [IN] ClientHello callback
 * @param   arg  [IN] Product input context
 * @retval  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetClientHelloCb(HITLS_Config *config, HITLS_ClientHelloCb callback, void *arg);

/**
 * @ingroup hitls_config
 * @brief   DTLS callback prototype for obtaining the timeout interval
 * @param   ctx  [IN] Ctx context
 * @param   us   [IN] Current timeout interval, Unit: microsecond
 * @return  Obtained timeout interval
 */
typedef uint32_t (*HITLS_DtlsTimerCb)(HITLS_Ctx *ctx, uint32_t us);

/**
 * @ingroup hitls_config
 * @brief   Set the DTLS obtaining timeout interval callback.
 * @param   config [OUT] Config context
 * @param   callback [IN] DTLS callback for obtaining the timeout interval
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetDtlsTimerCb(HITLS_Config *config, HITLS_DtlsTimerCb callback);

/**
 * @ingroup hitls_config
 * @brief   Obtaining the Minimum Supported Version Number
 *
 * @param   config  [IN] Config context
 * @param   minVersion  [OUT] Minimum version supported
 * @retval  HITLS_SUCCESS is obtained successfully.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetMinVersion(const HITLS_Config *config, uint16_t *minVersion);

/**
 * @ingroup hitls_config
 * @brief   Obtaining the Maximum supported version number
 *
 * @param   config  [IN] Config context
 * @param   maxVersion  [OUT] Maximum supported version
 * @retval  HITLS_SUCCESS is obtained successfully.
 *          For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetMaxVersion(const HITLS_Config *config, uint16_t *maxVersion);

/**
 * @ingroup hitls_config
 * @brief   Obtain the symmetric encryption algorithm type based on the cipher suite.
 *
 * @param   cipher[IN] Cipher suite
 * @param   cipherAlg [OUT] Obtained symmetric encryption algorithm type.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetCipherId(const HITLS_Cipher *cipher, HITLS_CipherAlgo *cipherAlg);

/**
 * @ingroup hitls_config
 * @brief   Obtain the hash algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   hashAlg [OUT] Obtained hash algorithm type.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetHashId(const HITLS_Cipher *cipher, HITLS_HashAlgo *hashAlg);

/**
 * @ingroup hitls_config
 * @brief   Obtain the MAC algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   macAlg [OUT] Obtained MAC algorithm type.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetMacId(const HITLS_Cipher *cipher, HITLS_MacAlgo *macAlg);

/**
 * @ingroup hitls_config
 * @brief   Obtain the server authorization algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   authAlg [OUT] Obtained server authorization type.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetAuthId(const HITLS_Cipher *cipher, HITLS_AuthAlgo *authAlg);

/**
 * @ingroup hitls_config
 * @brief   Obtain the key exchange algorithm type based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   kxAlg [OUT] Obtained key exchange algorithm type.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetKeyExchId(const HITLS_Cipher *cipher, HITLS_KeyExchAlgo *kxAlg);

/**
 * @ingroup hitls_config
 * @brief   Obtain the cipher suite name based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @retval  "(NONE)" Invalid cipher suite.
 * @retval  Name of the given cipher suite
 */
const uint8_t* HITLS_CFG_GetCipherSuiteName(const HITLS_Cipher *cipher);

/**
 * @ingroup hitls_config
 * @brief   Obtain the RFC standard name of the cipher suite based on the cipher suite.
 *
 * @param   cipherSuite [IN] cipher suite
 *
 * @retval  "(NONE)" Invalid cipher suite.
 * @retval  RFC standard name for the given cipher suite
 */
const uint8_t* HITLS_CFG_GetCipherSuiteStdName(const HITLS_Cipher *cipher);

/**
 * @ingroup hitls_config
 * @brief Obtain the corresponding cipher suite pointer based on the RFC Standard Name.
 *
 * @param stdName [IN] RFC Standard Name
 *
 * @retval NULL. Failed to obtain the cipher suite.
 * @retval Pointer to the obtained cipher suite information.
 */
const HITLS_Cipher* HITLS_CFG_GetCipherSuiteByStdName(const uint8_t* stdName);

/**
 * @ingroup hitls_config
 * @brief   Outputs the description of the cipher suite as a string.
 *
 * @param   cipherSuite [IN] Cipher suite
 * @param   buf [OUT] Output the description.
 * @param   len [IN] Description length
 * @retval  NULL, Failed to obtain the description.
 * @retval  Description of the cipher suite
 */
int32_t HITLS_CFG_GetDescription(const HITLS_Cipher *cipher, uint8_t *buf, int32_t len);

/**
 * @ingroup hitls_config
 * @brief   Determine whether to use the AEAD algorithm based on the cipher suite information.
 *
 * @param   cipher [IN] Cipher suite information
 * @param   isAead [OUT] Indicates whether to use the AEAD algorithm.
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          HITLS_NULL_INPUT, the input parameter pointer is null.
 */
int32_t HITLS_CIPHER_IsAead(const HITLS_Cipher *cipher, bool *isAead);

/**
 * @ingroup hitls_config
 * @brief   Obtain the earliest TLS version supported by the cipher suite based on the cipher suite.
 *
 * @param   cipher [IN] Cipher suite
 * @param   version [OUT] Obtain the earliest TLS version supported by the cipher suite.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_GetCipherVersion(const HITLS_Cipher *cipher, int32_t *version);

/**
 * @ingroup hitls_config
 * @brief   Obtain the cipher suite pointer based on the cipher suite ID.
 *
 * @param   cipherSuite [IN] Cipher suite ID
 *
 * @retval  HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE, Unsupported cipher suites
 * @retval  Pointer to the obtained cipher suite information.
 */
const HITLS_Cipher *HITLS_CFG_GetCipherByID(uint16_t cipherSuite);

/**
 * @ingroup hitls_config
 * @brief   Obtain the encryption ID in the cipher suite.
 *
 * @param   cipher [IN] Cipher suite.
 * @param   cipherSuite [OUT] Cipher suite ID.
 *
 * @retval  HITLS_CONFIG_UNSUPPORT_CIPHER_SUITE, Unsupported cipher suites.
 * @retval  Minimum TLS version supported by the given cipher suite.
 */
int32_t HITLS_CFG_GetCipherSuite(const HITLS_Cipher *cipher, uint16_t *cipherSuite);

/**
 * @ingroup hitls_config
 * @brief   Obtain the supported version number.
 *
 * @param   config  [IN] Config handle
 * @param   version [OUT] Supported version number.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_GetVersionSupport(const HITLS_Config *config, uint32_t *version);

/**
 * @ingroup hitls_config
 * @brief   Set the supported version number.
 *
 * @param   config [OUT] Config handle
 * @param   version [IN] Supported version number.
 * @attention   The maximum version number and minimum version number must be both TLS and DTLS.
 * Currently, only DTLS 1.2 is supported. This function is used together with the full configuration interfaces,
 * such as HITLS_CFG_NewDTLSConfig and HITLS_CFG_NewTLSConfig.
 * If the TLS full configuration is configured, only the TLS version can be set.
 * If full DTLS configuration is configured, only the DTLS version can be set.
 * The versions must be consecutive. By default, the minimum and maximum versions are supported.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetVersionSupport(HITLS_Config *config, uint32_t version);

/**
 * @ingroup hitls_config
 * @brief   This interface is used to verify the version in the premaster secret.
 * This interface takes effect on the server. The version must be earlier than 1.0, including 1.0.
 *
 * @param   config  [OUT] Config handle.
 * @param   needCheck [IN] Indicates whether to perform verification.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, config is null.
 */
int32_t HITLS_CFG_SetNeedCheckPmsVersion(HITLS_Config *config, bool needCheck);

/**
 * @ingroup hitls_config
 * @brief   Set the quiet disconnection mode.
 *
 * @param   config [IN] TLS link configuration
 * @param   mode [IN] Mode type. The value 0 indicates that the quiet disconnection mode is disabled,
 * and the value 1 indicates that the quiet disconnection mode is enabled.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  For other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetQuietShutdown(HITLS_Config *config, int32_t mode);

/**
 * @ingroup hitls_config
 * @brief   Obtain the current quiet disconnection mode.
 *
 * @param   config [IN] TLS link configuration
 * @param   mode [OUT] Current quiet disconnection mode
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetQuietShutdown(const HITLS_Config *config, int32_t *mode);

/**
 * @ingroup hitls_config
 * @brief   Set the timeout period after the DTLS over UDP connection is complete.
 * If the timer expires, the system does not receive the finished message resent by the peer end.
 * If this parameter is set to 0, the default value 240 seconds is used.
 *
 * @param   config [IN] TLS link configuration
 * @param   timeoutVal [IN] Timeout time
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetDtlsPostHsTimeoutVal(HITLS_Config *config, uint32_t timeoutVal);

/**
 * @ingroup hitls_config
 * @brief   Set the Encrypt-Then-Mac mode.
 *
 * @param   config [IN] TLS link configuration
 * @param   encryptThenMacType [IN] Current Encrypt-Then-Mac mode.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetEncryptThenMac(HITLS_Config *config, bool encryptThenMacType);

/**
 * @ingroup hitls_config
 * @brief   Obtain the Encrypt-Then-Mac type.
 *
 * @param   config [IN] TLS link configuration
 * @param   encryptThenMacType [OUT] Current Encrypt-Then-Mac mode
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetEncryptThenMac(const HITLS_Config *config, bool *encryptThenMacType);

/**
 * @ingroup hitls_config
 * @brief   Obtain the user data from the HiTLS Config object.
 * Generally, this function is called during the callback registered with the HiTLS.
 *
 * @attention must be called before HITLS_Connect and HITLS_Accept.
 *            The life cycle of the user identifier must be longer than that of the TLS object.
 * @param   config [OUT] TLS connection handle.
 * @param   userData [IN] User identifier.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, The TLS object pointer of the input parameter is null.
 */
void *HITLS_CFG_GetConfigUserData(const HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   User data is stored in the HiTLS Config. The user data can be obtained
 * from the callback registered with the HiTLS.
 *
 * @attention  must be called before HITLS_Connect and HITLS_Accept.
 * The life cycle of the user identifier must be longer than that of the TLS object.
 * If the user data needs to be cleared, the HITLS_SetUserData(ctx, NULL) interface can be called directly.
 * The Clean interface is not provided separately.
 * @param   config [OUT] TLS connection handle.
 * @param   userData [IN] User identifier.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, The TLS object pointer of the input parameter is null.
 */
int32_t HITLS_CFG_SetConfigUserData(HITLS_Config *config, void *userData);

/**
 * @ingroup hitls_config
 * @brief   UserData free callback
 */
typedef void (*HITLS_ConfigUserDataFreeCb)(void *);

/**
 * @ingroup hitls_config
 * @brief   Sets the UserData free callback
 *
 * @param   config [OUT] TLS connection handle
 * @param   userData [IN] User Data
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_NULL_INPUT The input pointer is null
 */
int32_t HITLS_CFG_SetConfigUserDataFreeCb(HITLS_Config *config, HITLS_ConfigUserDataFreeCb callback);

/**
 * @ingroup hitls_config
 * @brief   Determine whether to use DTLS.
 *
 * @param   config [IN] TLS link configuration.
 * @param   isDtls [OUT] Indicates whether to use DTLS.
 * @retval  HITLS_SUCCESS, obtained successfully.
 *          HITLS_NULL_INPUT, the input parameter pointer is null.
 */
int32_t HITLS_CFG_IsDtls(const HITLS_Config *config, bool *isDtls);

/**
 * @ingroup hitls_config
 * @brief   cipher suites are preferentially selected from the list of algorithms supported by the server.
 *
 * @param   config [IN] TLS link configuration.
 * @param   isSupport [IN] Support or not.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetCipherServerPreference(HITLS_Config *config, bool isSupport);

/**
 * @ingroup hitls_config
 * @brief   Obtains whether the current cipher suite supports preferential selection from the list of
 * algorithms supported by the server.
 *
 * @param   config [IN] TLS link configuration
 * @param   isSupport [OUT] Support or not
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetCipherServerPreference(const HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Set whether to send handshake messages by route.
 *
 * @param   config [IN/OUT] TLS link configuration
 * @param   isEnable [IN] Indicates whether to enable the function of sending handshake information by range.
 * 0 indicates that the function is disabled. Other values indicate that the function is enabled.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetFlightTransmitSwitch(HITLS_Config *config, bool isEnable);

/**
 * @ingroup hitls_config
 * @brief   Obtains the status of whether to send handshake information according to the route.
 *
 * @param   config [IN] TLS link configuration.
 * @param   isEnable [OUT] Indicates whether to send handshake information by route.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetFlightTransmitSwitch(const HITLS_Config *config, bool *isEnable);

/**
 * @ingroup hitls_config
 * @brief   Set whether to send hello verify request message.
 *
 * @param   config [IN] TLS link configuration.
 * @param   isSupport [IN] Indicates whether to send hello verify request message.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetDtlsCookieExchangeSupport(HITLS_Config *config, bool isSupport);

/**
 * @ingroup hitls_config
 * @brief   Obtains the status of whether to send hello verify request message.
 *
 * @param   config [IN] TLS link configuration.
 * @param   isSupport [OUT] Indicates whether to send hello verify request message.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetDtlsCookieExchangeSupport(const HITLS_Config *config, bool *isSupport);

/**
 * @ingroup hitls_config
 * @brief   Set the max empty records number can be received
 *
 * @param   config [IN/OUT] TLS link configuration
 * @param   emptyNum [IN] Indicates the max number of empty records can be received
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetEmptyRecordsNum(HITLS_Config *config, uint32_t emptyNum);

/**
 * @ingroup hitls_config
 * @brief   Obtain the max empty records number can be received
 *
 * @param   config [IN] TLS link configuration.
 * @param   emptyNum [OUT] Indicates the max number of empty records can be received
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetEmptyRecordsNum(const HITLS_Config *config, uint32_t *emptyNum);

/**
 * @ingroup hitls_config
 * @brief   Set the maximum size of the certificate chain that can be sent by the peer end.
 *
 * @param   config [IN/OUT] TLS link configuration.
 * @param   maxSize [IN] Set the maximum size of the certificate chain that can be sent by the peer end.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetMaxCertList(HITLS_Config *config, uint32_t maxSize);

/**
 * @ingroup hitls_config
 * @brief   Obtain the maximum size of the certificate chain that can be sent by the peer end.
 *
 * @param   config [IN] TLS link configuration
 * @param   maxSize [OUT] Maximum size of the certificate chain that can be sent by the peer end.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetMaxCertList(const HITLS_Config *config, uint32_t *maxSize);

typedef HITLS_CRYPT_Key *(*HITLS_DhTmpCb)(HITLS_Ctx *ctx, int32_t isExport, uint32_t keyLen);

/**
 * @ingroup hitls_config
 * @brief   Set the TmpDh callback, cb can be NULL.
 * @param   config [OUT] Config Context.
 * @param   callback [IN] TmpDh Callback.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetTmpDhCb(HITLS_Config *config, HITLS_DhTmpCb callback);

typedef uint64_t (*HITLS_RecordPaddingCb)(HITLS_Ctx *ctx, int32_t type, uint64_t length, void *arg);

/**
 * @ingroup hitls_config
 * @brief   Set the RecordPadding callback.
 *
 * @param   config [OUT] Config context
 * @param   callback [IN] RecordPadding Callback
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetRecordPaddingCb(HITLS_Config *config, HITLS_RecordPaddingCb callback);

/**
 * @ingroup hitls_config
 * @brief   Obtains the RecordPadding callback function.
 *
 * @param   config [OUT] Config context
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
HITLS_RecordPaddingCb HITLS_CFG_GetRecordPaddingCb(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Sets the parameters arg required by the RecordPadding callback function.
 *
 * @param   config [OUT] Config context
 * @param   arg [IN] Related parameters arg
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetRecordPaddingCbArg(HITLS_Config *config, void *arg);

/**
 * @ingroup hitls_config
 * @brief   Obtains the parameter arg required by the RecordPadding callback function.
 *
 * @param   config [OUT] Config context
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
void *HITLS_CFG_GetRecordPaddingCbArg(HITLS_Config *config);

/**
 * @ingroup hitls_config
 * @brief   Disables the verification of keyusage in the certificate. This function is enabled by default.
 *
 * @param   config [OUT] Config context
 * @param   isCheck [IN] Sets whether to check key usage.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetCheckKeyUsage(HITLS_Config *config, bool isCheck);

/**
 * @ingroup hitls_config
 * @brief   Set read ahead flag to indicate whether read more data than user required to buffer in advance
 * @param   config [OUT] Hitls config
 * @param   onOff [IN] Read ahead flag, nonzero value indicates open, zero indicates close
 * @retval  HITLS_NULL_INPUT
 * @retval  HITLS_SUCCESS
 */
int32_t HITLS_CFG_SetReadAhead(HITLS_Config *config, int32_t onOff);

/**
 * @ingroup hitls_config
 * @brief   Get whether reading ahead has been set or not
 *
 * @param   config [IN] Hitls config
 * @param   onOff [OUT] Read ahead flag
 * @retval  HITLS_NULL_INPUT
 * @retval  HITLS_SUCCESS
 */
int32_t HITLS_CFG_GetReadAhead(HITLS_Config *config, int32_t *onOff);

/**
 * @ingroup hitls_config
 * @brief   Set the function to support the specified feature.
 *
 * @param   config [OUT] Config context
 * @param   mode [IN] Mode features to enabled.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_SetModeSupport(HITLS_Config *config, uint32_t mode);

/**
 * @ingroup hitls_config
 * @brief   Disable the specified feature.
 *
 * @param   config [OUT] Config context
 * @param   mode [IN] Mode features to disabled.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_ClearModeSupport(HITLS_Config *config, uint32_t mode);

/**
 * @ingroup hitls_config
 * @brief   Obtain the mode of the function feature in the config file.
 *
 * @param   config [OUT] Config context
 * @param   mode [OUT] Mode obtain the output parameters of the mode.
 * @retval  HITLS_NULL_INPUT, the input parameter pointer is null.
 * @retval  HITLS_SUCCESS, if successful.
 */
int32_t HITLS_CFG_GetModeSupport(const HITLS_Config *config, uint32_t *mode);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CONFIG_H */
