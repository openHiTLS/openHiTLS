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

#ifndef RECV_COMMON_H
#define RECV_COMMON_H

#include <stdint.h>
#include "tls.h"
#include "cipher_suite.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Information used to describe the expected certificate */
typedef struct {
    /* The server must select the certificate matching the cipher suite. The client has no such restriction. */
    CERT_Type certType;
    uint16_t *signSchemeList;       /* certificate signature algorithm list */
    uint32_t signSchemeNum;         /* number of certificate signature algorithms */
    uint16_t *ellipticCurveList;    /* EC curve ID list */
    uint32_t ellipticCurveNum;      /* number of EC curve IDs */
    uint8_t *ecPointFormatList;     /* EC point format list */
    uint32_t ecPointFormatNum;      /* number of EC point formats */
    HITLS_TrustedCAList *caList;    /* trusted CA list */
} CERT_ExpectInfo;

/**
 * @brief Check the certificate information.
 *
 * @param ctx [IN] TLS context
 * @param expectCertInfo [IN] Expected certificate information
 * @param cert [IN] Certificate
 * @param isNegotiateSignAlgo [IN] Indicates whether to select the signature algorithm used in handshake messages.
 * @param signCheck [IN] Indicates whether to check the certificate signature information.
 *
 * @retval HITLS_SUCCESS                            succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK              No callback is set.
 * @retval HITLS_CERT_CTRL_ERR_GET_PUB_KEY          Failed to obtain the public key.
 * @retval HITLS_CERT_KEY_CTRL_ERR_GET_TYPE         Failed to obtain the public key type.
 * @retval HITLS_CERT_ERR_UNSUPPORT_CERT_TYPE       The certificate type does not match.
 * @retval HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH      signature algorithm mismatch
 * @retval HITLS_CERT_ERR_NO_CURVE_MATCH            elliptic curve mismatch
 * @retval HITLS_CERT_ERR_NO_POINT_FORMAT_MATCH     Point format mismatch
 */
int32_t HS_CheckCertInfo(HITLS_Ctx *ctx, const CERT_ExpectInfo *expectCertInfo, HITLS_CERT_X509 *cert,
    bool isNegotiateSignAlgo, bool signCheck);

/**
 * @brief Select the certificate chain to be sent to the peer end.
 *
 * @param ctx  [IN] tls Context
 * @param info [IN] Expected certificate information
 *
 * @retval HITLS_SUCCESS                            succeeded.
 * @retval HITLS_UNREGISTERED_CALLBACK              No callback is set.
 * @retval HITLS_CERT_ERR_SELECT_CERTIFICATE        Failed to select the certificate.
 */
int32_t HS_SelectCertByInfo(HITLS_Ctx *ctx, CERT_ExpectInfo *info);

CERT_Type CertKeyType2CertType(HITLS_CERT_KeyType keyType);

#ifdef __cplusplus
}
#endif

#endif
