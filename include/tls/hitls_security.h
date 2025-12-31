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
 * @defgroup hitls_security
 * @ingroup hitls
 * @brief TLS security features
 */

#ifndef HITLS_SECURITY_H
#define HITLS_SECURITY_H

#include <stdint.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup hitls_security
 * @brief HiTLS default level of security.
 * HiTLS default level of security. You can configure the default level by using the compilation macro.
 * If the compilation macro is not defined, the default level 1 is used.
 */
#ifndef HITLS_DEFAULT_SECURITY_LEVEL
#define HITLS_DEFAULT_SECURITY_LEVEL 1
#endif

/**
 * @ingroup hitls_security
 * @brief   Security level
 */
#define HITLS_SECURITY_LEVEL_ZERO 0
#define HITLS_SECURITY_LEVEL_ONE 1
#define HITLS_SECURITY_LEVEL_TWO 2
#define HITLS_SECURITY_LEVEL_THREE 3
#define HITLS_SECURITY_LEVEL_FOUR 4
#define HITLS_SECURITY_LEVEL_FIVE 5
#define HITLS_SECURITY_LEVEL_MIN HITLS_SECURITY_LEVEL_ZERO
#define HITLS_SECURITY_LEVEL_MAX HITLS_SECURITY_LEVEL_FIVE

/**
 * @ingroup hitls_security
 * @brief   Security strength
 */
#define HITLS_SECURITY_LEVEL_ONE_SECBITS 80
#define HITLS_SECURITY_LEVEL_TWO_SECBITS 112
#define HITLS_SECURITY_LEVEL_THREE_SECBITS 128
#define HITLS_SECURITY_LEVEL_FOUR_SECBITS 192
#define HITLS_SECURITY_LEVEL_FIVE_SECBITS 256

/* What the "other" parameter contains in security callback */
/* Mask for type */
# define HITLS_SECURITY_SECOP_OTHER_TYPE    0xffff0000
# define HITLS_SECURITY_SECOP_OTHER_NONE    0
# define HITLS_SECURITY_SECOP_OTHER_CIPHER  (1 << 16)
# define HITLS_SECURITY_SECOP_OTHER_CURVE   (2 << 16)
# define HITLS_SECURITY_SECOP_OTHER_DH      (3 << 16)
# define HITLS_SECURITY_SECOP_OTHER_PKEY    (4 << 16)
# define HITLS_SECURITY_SECOP_OTHER_SIGALG  (5 << 16)
# define HITLS_SECURITY_SECOP_OTHER_CERT    (6 << 16)

/**
 * @ingroup hitls_security
 * @brief   Indicated operation refers to peer key or certificate
 */
# define HITLS_SECURITY_SECOP_PEER          0x1000

/* Called to filter ciphers */
/* Ciphers client supports */
# define HITLS_SECURITY_SECOP_CIPHER_SUPPORTED      (1 | HITLS_SECURITY_SECOP_OTHER_CIPHER)
/* Cipher shared by client/server */
# define HITLS_SECURITY_SECOP_CIPHER_SHARED         (2 | HITLS_SECURITY_SECOP_OTHER_CIPHER)
/* Sanity check of cipher server selects */
# define HITLS_SECURITY_SECOP_CIPHER_CHECK          (3 | HITLS_SECURITY_SECOP_OTHER_CIPHER)
/* Curves supported by client */
# define HITLS_SECURITY_SECOP_CURVE_SUPPORTED       (4 | HITLS_SECURITY_SECOP_OTHER_CURVE)
/* Curves shared by client/server */
# define HITLS_SECURITY_SECOP_CURVE_SHARED          (5 | HITLS_SECURITY_SECOP_OTHER_CURVE)
/* Sanity check of curve server selects */
# define HITLS_SECURITY_SECOP_CURVE_CHECK           (6 | HITLS_SECURITY_SECOP_OTHER_CURVE)
/* Temporary DH key */
# define HITLS_SECURITY_SECOP_TMP_DH                (7 | HITLS_SECURITY_SECOP_OTHER_PKEY)
/* SSL/TLS version */
# define HITLS_SECURITY_SECOP_VERSION               (9 | HITLS_SECURITY_SECOP_OTHER_NONE)
/* Session tickets */
# define HITLS_SECURITY_SECOP_TICKET                (10 | HITLS_SECURITY_SECOP_OTHER_NONE)
/* Supported signature algorithms sent to peer */
# define HITLS_SECURITY_SECOP_SIGALG_SUPPORTED      (11 | HITLS_SECURITY_SECOP_OTHER_SIGALG)
/* Shared signature algorithm */
# define HITLS_SECURITY_SECOP_SIGALG_SHARED         (12 | HITLS_SECURITY_SECOP_OTHER_SIGALG)
/* Sanity check signature algorithm allowed */
# define HITLS_SECURITY_SECOP_SIGALG_CHECK          (13 | HITLS_SECURITY_SECOP_OTHER_SIGALG)
/* Used to get mask of supported public key signature algorithms */
# define HITLS_SECURITY_SECOP_SIGALG_MASK           (14 | HITLS_SECURITY_SECOP_OTHER_SIGALG)
/* Use to see if compression is allowed */
# define HITLS_SECURITY_SECOP_COMPRESSION           (15 | HITLS_SECURITY_SECOP_OTHER_NONE)
/* EE key in certificate */
# define HITLS_SECURITY_SECOP_EE_KEY                (16 | HITLS_SECURITY_SECOP_OTHER_CERT)
/* CA key in certificate */
# define HITLS_SECURITY_SECOP_CA_KEY                (17 | HITLS_SECURITY_SECOP_OTHER_CERT)
/* CA digest algorithm in certificate */
# define HITLS_SECURITY_SECOP_CA_MD                 (18 | HITLS_SECURITY_SECOP_OTHER_CERT)
/* Peer EE key in certificate */
# define HITLS_SECURITY_SECOP_PEER_EE_KEY           (HITLS_SECURITY_SECOP_EE_KEY | HITLS_SECURITY_SECOP_PEER)
/* Peer CA key in certificate */
# define HITLS_SECURITY_SECOP_PEER_CA_KEY           (HITLS_SECURITY_SECOP_CA_KEY | HITLS_SECURITY_SECOP_PEER)
/* Peer CA digest algorithm in certificate */
# define HITLS_SECURITY_SECOP_PEER_CA_MD            (HITLS_SECURITY_SECOP_CA_MD | HITLS_SECURITY_SECOP_PEER)

/**
 * @ingroup hitls_security
 * @brief   Secure Callback Function Prototype
 *
 * @param   ctx    [IN] context
 * @param   config [IN] context
 * @param   option [IN] indicates the options to be checked, such as the version, certificate, temporary key,
 * signature algorithm, support group, and session ticket...
 * @param   bits   [IN] Number of security bits, which is used to check the level of security of the key.
 * @param   id     [IN] Indicates the ID to be checked, such as the version ID, signature algorithm ID,
 * and support group ID. Input based on the options that need to be checked.
 * @param   other  [IN] Parameters to be checked, such as cipher suites, certificates, and signature algorithms.
 * @param   exData [IN] Input the data as required.
 * @return  1: success; others: failure
 */
typedef int32_t (*HITLS_SecurityCb)(const HITLS_Ctx *ctx, const HITLS_Config *config, int32_t option,
    int32_t bits, int32_t id, void *other, void *exData);

/**
 * @ingroup hitls_security
 * @brief   Configure the security level
 *
 * @param   config        [IN/OUT] Config context
 * @param   securityLevel [IN] Security level
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_SetSecurityLevel(HITLS_Config *config, int32_t securityLevel);

/**
 * @ingroup hitls_security
 * @brief   Obtain the configured security level.
 *
 * @param   config        [IN] Config context
 * @param   securityLevel [OUT] Security Context
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_GetSecurityLevel(const HITLS_Config *config, int32_t *securityLevel);

/**
 * @ingroup hitls_security
 * @brief   Configure the security callback function.
 *
 * @param   config     [IN/OUT] Config context
 * @param   securityCb [IN] Security callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h.
 */
int32_t HITLS_CFG_SetSecurityCb(HITLS_Config *config, HITLS_SecurityCb securityCb);

/**
 * @ingroup hitls_security
 * @brief   Obtain the configured security callback function
 *
 * @param   config [IN] Config context
 * @retval  Security callback function HITLS_SecurityCb.
 */
HITLS_SecurityCb HITLS_CFG_GetSecurityCb(const HITLS_Config *config);

/**
 * @ingroup hitls_security
 * @brief   Configuring the Security ExData
 *
 * @param   config [IN/OUT] Config context
 * @param   securityExData [IN] Security ExData
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_CFG_SetSecurityExData(HITLS_Config *config, void *securityExData);

/**
 * @ingroup hitls_security
 * @brief   Obtain the configured Security ExData
 *
 * @param   config [IN] Config context
 * @return  Security ExData
 */
void *HITLS_CFG_GetSecurityExData(const HITLS_Config *config);

/**
 * @ingroup hitls_security
 * @brief   Set the link security level
 *
 * @param   ctx           [IN/OUT] Ctx context
 * @param   securityLevel [IN] Security level
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_SetSecurityLevel(HITLS_Ctx *ctx, int32_t securityLevel);

/**
 * @ingroup hitls_security
 * @brief   Obtain the link security level
 *
 * @param   ctx           [IN] Ctx context
 * @param   securityLevel [OUT] Security level
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_GetSecurityLevel(const HITLS_Ctx *ctx, int32_t *securityLevel);

/**
 * @ingroup hitls_security
 * @brief   Callback function for setting link security
 *
 * @param   ctx        [IN/OUT] Ctx context
 * @param   securityCb [IN] Security callback function
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, see hitls_error.h
 */
int32_t HITLS_SetSecurityCb(HITLS_Ctx *ctx, HITLS_SecurityCb securityCb);

/**
 * @ingroup hitls_security
 * @brief   Obtain the Security callback function of the link
 *
 * @param   ctx [IN] Ctx context
 * @retval  Security callback HITLS_SecurityCb.
 */
HITLS_SecurityCb HITLS_GetSecurityCb(const HITLS_Ctx *ctx);

/**
 * @ingroup hitls_security
 * @brief   Setting Security ExData for the Link
 *
 * @param   ctx            [IN/OUT] Ctx context
 * @param   securityExData [IN] Security ExData
 * @return  HITLS_SUCCESS, if successful.
 *          For details about other error codes, hitls_error.h
 */
int32_t HITLS_SetSecurityExData(HITLS_Ctx *ctx, void *securityExData);

/**
 * @ingroup hitls_security
 * @brief   Obtains the configured Security ExData.
 *
 * @param   ctx [IN] Ctx context
 * @return  Security ExData
 */
void *HITLS_GetSecurityExData(const HITLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end HITLS_SECURITY_H */