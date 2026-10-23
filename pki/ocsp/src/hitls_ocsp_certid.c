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
#ifdef HITLS_PKI_OCSP

#include <string.h>
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_codecskey.h"
#include "crypt_errno.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_x509.h"
#include "hitls_cert_local.h"
#include "hitls_x509_local.h"
#include "hitls_ocsp_local.h"

static int32_t OcspHashData(CRYPT_EAL_MdCtx *mdCtx, const uint8_t *data, uint32_t dataLen,
                            uint8_t *out, uint32_t *outLen)
{
    if (mdCtx == NULL || data == NULL || dataLen == 0 || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    int32_t ret = CRYPT_EAL_MdInit(mdCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_MdUpdate(mdCtx, data, dataLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_MdFinal(mdCtx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = HITLS_PKI_SUCCESS;
EXIT:
    /* Release the internal hash state on every branch after a successful Init;
     * the caller keeps ownership of mdCtx (it can MdInit again or MdFreeCtx). */
    (void)CRYPT_EAL_MdDeinit(mdCtx);
    return ret;
}

int32_t OcspGetIssuerNameHash(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *issuer,
                             uint8_t *out, uint32_t *outLen)
{
    BSL_Buffer dnDer = {0};
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)issuer, HITLS_X509_GET_ENCODE_SUBJECT_DN,
                                      &dnDer, sizeof(BSL_Buffer *));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = OcspHashData(mdCtx, (const uint8_t *)dnDer.data, dnDer.dataLen, out, outLen);
    BSL_SAL_Free(dnDer.data);
    /* OcspHashData has already pushed the error; propagate it without re-pushing. */
    return ret;
}

/* Encode the cert's public key (SUBKEY) and extract the raw key bytes: the BIT STRING
 * content after the unused-bits prefix byte.
 * Output borrows into spkiContent; caller frees spkiContent.data. */
static int32_t OcspExtractPubKeyContent(const HITLS_X509_Cert *cert, BSL_Buffer *spkiContent, uint8_t **keyOut,
                                        uint32_t *keyLen)
{
    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_EncodePubKeyBuffInternal(pubKey, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, false, spkiContent);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* CRYPT_PUBKEY_SUBKEY outputs: AlgorithmIdentifier SEQUENCE + BIT STRING (no outer SEQUENCE). */
    uint8_t *p = (uint8_t *)spkiContent->data;
    uint32_t remaining = spkiContent->dataLen;
    uint32_t vLen = 0;

    /* Skip AlgorithmIdentifier SEQUENCE */
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, &p, &remaining, &vLen);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    p += vLen;
    remaining -= vLen;

    /* Decode BIT STRING */
    ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_BITSTRING, &p, &remaining, &vLen);
    if (ret != BSL_SUCCESS) {
        goto EXIT;
    }
    /* BIT STRING must be the last element: no trailing data after it */
    if (remaining != vLen) {
        ret = HITLS_OCSP_ERR_INVALID_PARAM;
        goto EXIT;
    }
    /* Skip unused-bits prefix byte. DER requires it to be 0x00 for byte-aligned keys;
     * reject non-zero values loudly instead of silently producing a wrong hash. */
    if (vLen < 1) {
        ret = HITLS_OCSP_ERR_INVALID_PARAM;
        goto EXIT;
    }
    if (*p != 0x00) {
        ret = HITLS_OCSP_ERR_INVALID_PARAM;
        goto EXIT;
    }
    p++;
    vLen--;
    if (vLen == 0) {
        ret = HITLS_OCSP_ERR_INVALID_PARAM;
        goto EXIT;
    }

    *keyOut = p;
    *keyLen = vLen;
    return HITLS_PKI_SUCCESS;

EXIT:
    BSL_SAL_Free(spkiContent->data);
    spkiContent->data = NULL;
    spkiContent->dataLen = 0;
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t OcspGetPubKeyHash(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *cert, uint8_t *out, uint32_t *outLen)
{
    /* Hash the raw public key bytes (BIT STRING content after the unused-bits byte),
     * not the full SPKI DER. */
    BSL_Buffer spkiContent = {0};
    uint8_t *keyData = NULL;
    uint32_t keyLen = 0;
    int32_t ret = OcspExtractPubKeyContent(cert, &spkiContent, &keyData, &keyLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = OcspHashData(mdCtx, keyData, keyLen, out, outLen);
    BSL_SAL_Free(spkiContent.data);
    /* OcspHashData has already pushed the error; propagate it without re-pushing. */
    return ret;
}

/* Get the serial number from cert and store it into certId->serialNumber (deep copy). */
static int32_t OcspSetCertIdSerial(const HITLS_X509_Cert *cert, HITLS_OCSP_CertId_Internal *certId)
{
    BSL_Buffer serial = {0};
    int32_t ret =
        HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert, HITLS_X509_GET_SERIALNUM, &serial, sizeof(BSL_Buffer));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (serial.dataLen == 0 || serial.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    /* Normalize the DER INTEGER serial exactly like OcspParseCertIdSerial (strip redundant
     * leading 0x00 for positive / 0xFF for negative) so CertIdCmp sees identical bytes
     * whether the CertID came from construction or parsing. */
    uint8_t *serialData = serial.data;
    uint32_t serialLen = serial.dataLen;
    bool negative = (serialData[0] & 0x80) != 0;
    while (serialLen > 1) {
        if (serialData[0] == 0x00 && !negative && (serialData[1] & 0x80) == 0) {
            serialData++;
            serialLen--;
        } else if (serialData[0] == 0xFF && negative && (serialData[1] & 0x80) != 0) {
            serialData++;
            serialLen--;
        } else {
            break;
        }
    }
    certId->serialNumber.buff = BSL_SAL_Dump(serialData, serialLen);
    if (certId->serialNumber.buff == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    certId->serialNumber.len = serialLen;
    certId->serialNumber.tag = BSL_ASN1_TAG_INTEGER;
    return HITLS_PKI_SUCCESS;
}

HITLS_OCSP_CertId *HITLS_OCSP_CertIdNewFromCert(CRYPT_EAL_MdCtx *mdCtx, const HITLS_X509_Cert *cert,
                                                 const HITLS_X509_Cert *issuer)
{
    if (mdCtx == NULL || cert == NULL || issuer == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return NULL;
    }

    CRYPT_MD_AlgId mdId = (CRYPT_MD_AlgId)CRYPT_EAL_MdGetId(mdCtx);
    if (mdId != CRYPT_MD_SHA1 && mdId != CRYPT_MD_SHA256) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MD_UNSUPPORT);
        return NULL;
    }

    HITLS_OCSP_CertId_Internal *certId = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_CertId_Internal));
    if (certId == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return NULL;
    }

    uint8_t hash[32];
    uint32_t hashLen = sizeof(hash);

    int32_t ret = OcspGetIssuerNameHash(mdCtx, issuer, hash, &hashLen);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT; /* error already pushed by the callee */
    }

    certId->hashAlg = mdId;

    ret = OcspSetHashField(mdId, &certId->issuerNameHash, hash, hashLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    /* hash/hashLen are reused for the key hash (OcspSetHashField deep-copies each time). */
    hashLen = sizeof(hash);
    ret = OcspGetPubKeyHash(mdCtx, issuer, hash, &hashLen);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT; /* error already pushed by the callee */
    }

    ret = OcspSetHashField(mdId, &certId->issuerKeyHash, hash, hashLen);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = OcspSetCertIdSerial(cert, certId);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    return (HITLS_OCSP_CertId *)certId;

EXIT:
    HITLS_OCSP_CertIdFree((HITLS_OCSP_CertId *)certId);
    return NULL;
}

#define HITLS_OCSP_CMP_NOT_EQUAL 1

/* Compare the issuer parts (hashAlg + issuerNameHash + issuerKeyHash) of two CertIDs.
 * Returns true if they match (same issuer), false otherwise. */
bool OcspCertIdIssuerMatch(const HITLS_OCSP_CertId_Internal *a, const HITLS_OCSP_CertId_Internal *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->hashAlg != b->hashAlg) {
        return false;
    }
    if (a->issuerNameHash.len != b->issuerNameHash.len ||
        (a->issuerNameHash.len != 0 &&
         memcmp(a->issuerNameHash.buff, b->issuerNameHash.buff, a->issuerNameHash.len) != 0)) {
        return false;
    }
    if (a->issuerKeyHash.len != b->issuerKeyHash.len ||
        (a->issuerKeyHash.len != 0 &&
         memcmp(a->issuerKeyHash.buff, b->issuerKeyHash.buff, a->issuerKeyHash.len) != 0)) {
        return false;
    }
    return true;
}

int32_t HITLS_OCSP_CertIdCmp(const HITLS_OCSP_CertId *a, const HITLS_OCSP_CertId *b)
{
    if (a == NULL || b == NULL) {
        return HITLS_OCSP_CMP_NOT_EQUAL;
    }
    const HITLS_OCSP_CertId_Internal *ia = (const HITLS_OCSP_CertId_Internal *)a;
    const HITLS_OCSP_CertId_Internal *ib = (const HITLS_OCSP_CertId_Internal *)b;
    if (!OcspCertIdIssuerMatch(ia, ib)) {
        return HITLS_OCSP_CMP_NOT_EQUAL;
    }
    if (ia->serialNumber.len != ib->serialNumber.len ||
        (ia->serialNumber.len != 0 &&
         memcmp(ia->serialNumber.buff, ib->serialNumber.buff, ia->serialNumber.len) != 0)) {
        return HITLS_OCSP_CMP_NOT_EQUAL;
    }
    return HITLS_PKI_SUCCESS;
}

void HITLS_OCSP_CertIdFree(HITLS_OCSP_CertId *certId)
{
    if (certId == NULL) {
        return;
    }
    HITLS_OCSP_CertId_Internal *internal = (HITLS_OCSP_CertId_Internal *)certId;
    BSL_SAL_FREE(internal->issuerNameHash.buff);
    BSL_SAL_FREE(internal->issuerKeyHash.buff);
    BSL_SAL_FREE(internal->serialNumber.buff);
    BSL_SAL_Free(internal);
}

int32_t HITLS_OCSP_CertIdGetInfo(const HITLS_OCSP_CertId *certId, CRYPT_MD_AlgId *hashAlg,
                                 BSL_Buffer *issuerNameHash, BSL_Buffer *issuerKeyHash,
                                 BSL_Buffer *serialNumber)
{
    if (certId == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_CertId_Internal *internal = (const HITLS_OCSP_CertId_Internal *)certId;
    if (hashAlg != NULL) {
        *hashAlg = internal->hashAlg;
    }
    if (issuerNameHash != NULL) {
        issuerNameHash->data = internal->issuerNameHash.buff;
        issuerNameHash->dataLen = internal->issuerNameHash.len;
    }
    if (issuerKeyHash != NULL) {
        issuerKeyHash->data = internal->issuerKeyHash.buff;
        issuerKeyHash->dataLen = internal->issuerKeyHash.len;
    }
    if (serialNumber != NULL) {
        serialNumber->data = internal->serialNumber.buff;
        serialNumber->dataLen = internal->serialNumber.len;
    }
    return HITLS_PKI_SUCCESS;
}

/* ==================== ResponderId ==================== */

void OcspResponderIdFree(HITLS_OCSP_ResponderId *responderId)
{
    if (responderId == NULL) {
        return;
    }
    if (responderId->type == HITLS_OCSP_RESPONDERID_BY_NAME) {
        BSL_SAL_FREE(responderId->value.byName.data);
    } else if (responderId->type == HITLS_OCSP_RESPONDERID_BY_KEY) {
        BSL_SAL_FREE(responderId->value.byKey.data);
    } else {
        /* Unknown type: nothing to release, just drop the object. */
    }
    BSL_SAL_Free(responderId);
}

#endif // HITLS_PKI_OCSP
