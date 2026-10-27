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
#include "hitls_build.h"
#if defined(HITLS_TLS_FEATURE_STATUS_REQUEST)
#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_cert_type.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_errno.h"
#include "crypt_eal_md.h"
#include "crypt_errno.h"
#include "tls.h"
#include "config_type.h"
#include "cert_method.h"

/* Free a parsed OCSP response handle (NULL is a no-op). */
void SAL_CERT_OcspRespFree(HITLS_CERT_OcspResp *resp)
{
    HITLS_OCSP_RespFree((HITLS_OCSP_Resp *)resp);
}

/* Parse a DER-encoded OCSPResponse into an opaque response handle. */
int32_t SAL_CERT_OcspRespParseBuff(const HITLS_Ctx *ctx, const BSL_Buffer *der, HITLS_CERT_OcspResp **resp)
{
    (void)ctx;
    if (der == NULL || resp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    *resp = NULL;
    HITLS_OCSP_Resp *pkiResp = NULL;
    if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, der, &pkiResp) != HITLS_PKI_SUCCESS || pkiResp == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_OCSP_STATUS_ERR);
        return HITLS_MSG_HANDLE_OCSP_STATUS_ERR;
    }
    *resp = (HITLS_CERT_OcspResp *)pkiResp;
    return HITLS_SUCCESS;
}

/* Encode an OCSP response handle back to DER (caller frees der->data). */
int32_t SAL_CERT_OcspRespGenBuff(const HITLS_CERT_OcspResp *resp, BSL_Buffer *der)
{
    if (resp == NULL || der == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    return HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, (const HITLS_OCSP_Resp *)resp, der);
}

/* Extract the normalized serial number and the issuer DN (DER) from a server
 * certificate through the cert method adapter. Output buffers are freshly
 * allocated; the caller must free serial->data and issuerDn->data. */
static int32_t ExtractCertSerialAndIssuerDn(const TLS_Ctx *ctx, HITLS_CERT_X509 *cert, BSL_Buffer *serial,
                                            BSL_Buffer *issuerDn)
{
    /* Serial number (borrowed inside the cert; copy the normalized DER form). */
    BSL_Buffer tmpSerial = {0};
    int32_t ret = SAL_CERT_X509Ctrl((HITLS_Config *)(uintptr_t)&ctx->config.tlsConfig, cert,
                                    CERT_CTRL_GET_SERIALNUM, NULL, &tmpSerial);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    if (tmpSerial.data == NULL || tmpSerial.dataLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_INVALID_INPUT);
        return HITLS_INVALID_INPUT;
    }
    /* Normalize the DER INTEGER serial (strip redundant leading 0x00) to match the
     * OCSP CertID serial encoding (RFC 6960 uses the minimal DER integer). A leading
     * 0xFF denotes a negative INTEGER and is not padding: it must not be stripped,
     * or 0xFF80 would alias 0x80. */
    uint8_t *serialData = tmpSerial.data;
    uint32_t serialLen = tmpSerial.dataLen;
    while (serialLen > 1 && serialData[0] == 0x00) {
        serialData++;
        serialLen--;
    }
    serial->data = (uint8_t *)BSL_SAL_Dump(serialData, serialLen);
    serial->dataLen = serialLen;
    if (serial->data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }

    /* Issuer DN as DER (freshly allocated by the encoder; caller frees it). */
    ret = SAL_CERT_X509Ctrl((HITLS_Config *)(uintptr_t)&ctx->config.tlsConfig, cert,
                            CERT_CTRL_GET_ENCODE_ISSUER_DN, NULL, issuerDn);
    if (ret != HITLS_SUCCESS) {
        /* Propagate the encoder error; the caller only treats any non-success
         * as "not matching". */
        BSL_SAL_FREE(serial->data);
        return ret;
    }
    return HITLS_SUCCESS;
}

/* Check whether a CertID belongs to the certificate: its serialNumber must match
 * and its issuerNameHash (computed over the certificate's issuer DN with the
 * CertID hash algorithm) must match. Returns HITLS_SUCCESS on match,
 * HITLS_OCSP_ERR_CERTID_NOT_FOUND when the serial differs (this SingleResponse
 * is not for the certificate; the caller keeps looking), and a real error code
 * on failure. */
static int32_t OcspCertIdMatchesCert(const HITLS_OCSP_CertId *certId, const BSL_Buffer *serial,
                                     const BSL_Buffer *issuerDn)
{
    CRYPT_MD_AlgId hashAlg = CRYPT_MD_SHA1;
    BSL_Buffer respIssuerHash = {0};
    BSL_Buffer respSerial = {0};
    int32_t ret = HITLS_OCSP_CertIdGetInfo(certId, &hashAlg, &respIssuerHash, NULL, &respSerial);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    if (respSerial.dataLen != serial->dataLen || memcmp(respSerial.data, serial->data, serial->dataLen) != 0) {
        return HITLS_OCSP_ERR_CERTID_NOT_FOUND;
    }
    /* Hash the certificate's issuer DN with the same algorithm as the CertID. */
    CRYPT_EAL_MdCtx *md = CRYPT_EAL_MdNewCtx(hashAlg);
    if (md == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return HITLS_MEMALLOC_FAIL;
    }
    uint8_t digest[64] = {0}; /* SHA-512 is the largest supported digest */
    uint32_t digestLen = sizeof(digest);
    int32_t hr = CRYPT_EAL_MdInit(md);
    if (hr == CRYPT_SUCCESS) {
        hr = CRYPT_EAL_MdUpdate(md, issuerDn->data, issuerDn->dataLen);
    }
    if (hr == CRYPT_SUCCESS) {
        hr = CRYPT_EAL_MdFinal(md, digest, &digestLen);
    }
    CRYPT_EAL_MdFreeCtx(md);
    if (hr != CRYPT_SUCCESS) {
        return hr;
    }
    return (respIssuerHash.dataLen == digestLen && memcmp(respIssuerHash.data, digest, digestLen) == 0) ?
               HITLS_SUCCESS :
               HITLS_OCSP_ERR_CERTID_NOT_FOUND;
}

/* Decide whether a prepared OCSP response should be stapled for the given
 * certificate. Returns true when the response is delivered: it matches the
 * certificate, or it cannot be validated against it (a non-successful status,
 * a missing BasicOCSPResponse/SingleResponse, or an extraction failure -- such
 * a response is still handed to the client). Returns false only when the
 * response is valid but contains no CertID matching this certificate (a
 * genuine non-match, so the caller skips stapling for this certificate). */
bool SAL_CERT_OcspRespMatchCert(const HITLS_Ctx *ctx, const HITLS_CERT_OcspResp *resp, HITLS_CERT_X509 *cert)
{
    const TLS_Ctx *tlsCtx = (const TLS_Ctx *)(uintptr_t)ctx;
    /* This helper is best-effort: a failure to validate the response must not
     * surface as an error, since the response is still delivered (return true).
     * Drop any error-stack contribution pushed by the OCSP getters below so a
     * match/fallback decision does not leak stale errors to the caller. */
    BSL_ERR_SET_MARK();
    int32_t status = -1;
    if (HITLS_OCSP_RespCtrl((HITLS_OCSP_Resp *)(uintptr_t)resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)) !=
        HITLS_PKI_SUCCESS) {
        BSL_ERR_POP_TO_MARK();
        return true;
    }
    if (status != HITLS_OCSP_RESP_STATUS_SUCCESSFUL) {
        BSL_ERR_POP_TO_MARK();
        return true;
    }
    HITLS_OCSP_BasicResp *bs = NULL;
    if (HITLS_OCSP_RespCtrl((HITLS_OCSP_Resp *)(uintptr_t)resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)) !=
        HITLS_PKI_SUCCESS) {
        BSL_ERR_POP_TO_MARK();
        return true;
    }
    if (bs == NULL) {
        BSL_ERR_POP_TO_MARK();
        return true;
    }
    BSL_Buffer serial = {0};
    BSL_Buffer issuerDn = {0};
    if (ExtractCertSerialAndIssuerDn(tlsCtx, cert, &serial, &issuerDn) != HITLS_SUCCESS) {
        BSL_ERR_POP_TO_MARK();
        return true;
    }
    /* Only a genuine non-match (a valid BasicOCSPResponse whose SingleResponses
     * all carry a CertID for another certificate) returns false; any failure to
     * validate keeps the default true so the response is still delivered. */
    bool result = true;
    uint32_t count = 0;
    if (HITLS_OCSP_BasicRespGetRespCount(bs, &count) == HITLS_PKI_SUCCESS) {
        for (uint32_t i = 0; i < count; i++) {
            HITLS_OCSP_SingleResp *single = NULL;
            if (HITLS_OCSP_BasicRespGetRespByIndex(bs, i, &single) != HITLS_PKI_SUCCESS) {
                goto EXIT;
            }
            if (single == NULL) {
                goto EXIT;
            }
            HITLS_OCSP_CertId *certId = NULL;
            if (HITLS_OCSP_SingleRespCtrl(single, HITLS_OCSP_SINGLERESP_GET_CERTID, &certId, sizeof(certId)) !=
                HITLS_PKI_SUCCESS) {
                goto EXIT;
            }
            if (certId == NULL) {
                goto EXIT;
            }
            int32_t ret = OcspCertIdMatchesCert(certId, &serial, &issuerDn);
            if (ret == HITLS_SUCCESS) {
                goto EXIT;
            }
            if (ret != HITLS_OCSP_ERR_CERTID_NOT_FOUND) {
                goto EXIT;
            }
            /* CERTID_NOT_FOUND: this SingleResponse is for another certificate;
             * keep looking at the remaining ones. */
        }
        result = false;
    }
EXIT:
    BSL_SAL_FREE(serial.data);
    BSL_SAL_FREE(issuerDn.data);
    BSL_ERR_POP_TO_MARK();
    return result;
}

#endif /* HITLS_TLS_FEATURE_STATUS_REQUEST */
