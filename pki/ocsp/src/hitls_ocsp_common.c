/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_PKI_OCSP

#include <string.h>
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_err_internal.h"
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "bsl_obj_internal.h"
#include "crypt_errno.h"
#include "hitls_pki_errno.h"
#include "hitls_ocsp_local.h"

/* ==================== ASN.1 encode/decode templates ==================== */

/* CertID ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier                    depth=0
 *         AlgorithmIdentifier ::= SEQUENCE {
 *             algorithm   OBJECT IDENTIFIER                 depth=1
 *             parameters  ANY OPTIONAL                      depth=1
 *         }
 *     issuerNameHash OCTET STRING                           depth=0
 *     issuerKeyHash  OCTET STRING                           depth=0
 *     serialNumber   CertificateSerialNumber (INTEGER) }    depth=0
 * Shared by the encode and decode paths. The parameters leaf is ANY so decoding
 * accepts any encoding, while encoding emits NULL (the caller supplies the tag,
 * and the template engine defers to the buffer tag for an ANY leaf).
 * Leaf indices: [0]=algOID, [1]=algParams, [2]=nameHash, [3]=keyHash, [4]=serial
 */
static BSL_ASN1_TemplateItem g_ocspCertIdTempl[] = {
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* CertID */
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},                       /* algorithm */
        {BSL_ASN1_TAG_ANY, BSL_ASN1_FLAG_OPTIONAL, 1},        /* parameters */
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},                         /* issuerNameHash */
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},                         /* issuerKeyHash */
    {BSL_ASN1_TAG_INTEGER, 0, 0},                              /* serialNumber */
};

enum { CERTID_LEAF_NUM = 5 }; /* leaf count (shared by encode and decode). */

enum {
    CERTID_DEC_ALG_OID_IDX = 0,
    CERTID_DEC_ALG_PARAM_IDX,
    CERTID_DEC_NAMEHASH_IDX,
    CERTID_DEC_KEYHASH_IDX,
    CERTID_DEC_SERIAL_IDX,
    CERTID_DEC_MAX_IDX,
};

/* Normalize the DER INTEGER serial number (strip leading 0x00/0xFF padding) and deep-copy it
 * into certId->serialNumber. */
static int32_t OcspParseCertIdSerial(const BSL_ASN1_Buffer *serialAsn, HITLS_OCSP_CertId_Internal *certId)
{
    if (serialAsn == NULL || serialAsn->buff == NULL || serialAsn->len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MALFORMED);
        return HITLS_OCSP_ERR_MALFORMED;
    }
    uint8_t *serialData = serialAsn->buff;
    uint32_t serialLen = serialAsn->len;
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

int32_t OcspParseCertId(const BSL_ASN1_Buffer *asn, HITLS_OCSP_CertId_Internal *certId)
{
     if (asn == NULL || asn->buff == NULL || certId == NULL) {
         BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
         return HITLS_OCSP_ERR_INVALID_PARAM;
     }

    BSL_ASN1_Buffer asns[CERTID_DEC_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_ocspCertIdTempl, sizeof(g_ocspCertIdTempl) / sizeof(g_ocspCertIdTempl[0])};
    uint8_t *buff = asn->buff;
    uint32_t len = asn->len;
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, OcspTagGetOrCheck, &buff, &len, asns, CERTID_DEC_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MALFORMED);
        return HITLS_OCSP_ERR_MALFORMED;
    }

    BslCid cid = BSL_OBJ_GetCidFromOidBuff(asns[CERTID_DEC_ALG_OID_IDX].buff, asns[CERTID_DEC_ALG_OID_IDX].len);
    switch (cid) {
        case BSL_CID_SHA1:
        case BSL_CID_SHA224:
        case BSL_CID_SHA256:
        case BSL_CID_SHA384:
        case BSL_CID_SHA512:
            certId->hashAlg = (CRYPT_MD_AlgId)cid;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MD_UNSUPPORT);
            return HITLS_OCSP_ERR_MD_UNSUPPORT;
    }

    ret = OcspSetHashField(certId->hashAlg, &certId->issuerNameHash, asns[CERTID_DEC_NAMEHASH_IDX].buff,
                           asns[CERTID_DEC_NAMEHASH_IDX].len);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    ret = OcspSetHashField(certId->hashAlg, &certId->issuerKeyHash, asns[CERTID_DEC_KEYHASH_IDX].buff,
                           asns[CERTID_DEC_KEYHASH_IDX].len);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    ret = OcspParseCertIdSerial(&asns[CERTID_DEC_SERIAL_IDX], certId);
    if (ret != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    return HITLS_PKI_SUCCESS;

EXIT:
    BSL_SAL_FREE(certId->issuerNameHash.buff);
    BSL_SAL_FREE(certId->issuerKeyHash.buff);
    BSL_SAL_FREE(certId->serialNumber.buff);
    return ret;
}

/* CertID ::= SEQUENCE { hashAlgorithm AlgId, issuerNameHash, issuerKeyHash, serialNumber } */
int32_t OcspEncodeCertId(const HITLS_OCSP_CertId *certId, BSL_ASN1_Buffer *out)
{
    if (certId == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const HITLS_OCSP_CertId_Internal *ci = (const HITLS_OCSP_CertId_Internal *)certId;
    BslCid cid;
    switch (ci->hashAlg) {
        case CRYPT_MD_SHA1:
            cid = BSL_CID_SHA1;
            break;
        case CRYPT_MD_SHA224:
            cid = BSL_CID_SHA224;
            break;
        case CRYPT_MD_SHA256:
            cid = BSL_CID_SHA256;
            break;
        case CRYPT_MD_SHA384:
            cid = BSL_CID_SHA384;
            break;
        case CRYPT_MD_SHA512:
            cid = BSL_CID_SHA512;
            break;
        default:
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MD_UNSUPPORT);
            return HITLS_OCSP_ERR_MD_UNSUPPORT;
    }
    BslOidString *oidStr = BSL_OBJ_GetOID(cid);
    if (oidStr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MD_UNSUPPORT);
        return HITLS_OCSP_ERR_MD_UNSUPPORT;
    }
    BSL_ASN1_Buffer asns[CERTID_LEAF_NUM] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidStr->octetLen, (uint8_t *)oidStr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_OCTETSTRING, ci->issuerNameHash.len, ci->issuerNameHash.buff},
        {BSL_ASN1_TAG_OCTETSTRING, ci->issuerKeyHash.len, ci->issuerKeyHash.buff},
        {BSL_ASN1_TAG_INTEGER, ci->serialNumber.len, ci->serialNumber.buff},
    };
    BSL_ASN1_Template templ = {g_ocspCertIdTempl, sizeof(g_ocspCertIdTempl) / sizeof(g_ocspCertIdTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asns, CERTID_LEAF_NUM, &out->buff, &out->len);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    out->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

int32_t OcspStripTlv(const BSL_ASN1_Buffer *in, BSL_ASN1_Buffer *out)
{
    if (in == NULL || out == NULL || in->buff == NULL || in->len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    out->tag = in->tag;
    out->buff = in->buff;
    out->len = in->len;
    uint32_t valLen = 0;
    if (BSL_ASN1_DecodeTagLen(in->tag, &out->buff, &out->len, &valLen) != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_ASN1_ERR_DECODE_LEN);
        return BSL_ASN1_ERR_DECODE_LEN;
    }
    out->len = valLen;
    return HITLS_PKI_SUCCESS;
}

int32_t OcspTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    (void)idx;
    if (type == BSL_ASN1_TYPE_CHECK_CHOICE_TAG) {
        /* data = &realTag (actual byte from DER).
         * The OCSP module has two CHOICE contexts sharing this callback:
         *   CertStatus  : good [0] (0x80), revoked [1] (0xa1), unknown [2] (0x82)
         *   ResponderID : byName [1] (0xa1), byKey [2] (0xa2)
         * RFC 6960: revoked is [1] IMPLICIT RevokedInfo (a SEQUENCE), so its tag is the
         * constructed 0xa1, not 0x81. The union below accepts only the valid tags from
         * both CHOICE sets. Downstream parsers switch on the concrete tag and reject
         * a tag that is invalid for their own context, so cross-context DER is refused
         * at interpretation time even though the tag check accepts it. */
        if (data == NULL || expVal == NULL) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        uint8_t realTag = *(uint8_t *)data;
        switch (realTag) {
            case 0x80: /* good    [0] IMPLICIT NULL        */
            case 0xa1: /* revoked [1] IMPLICIT RevokedInfo / byName [1] */
            case 0x82: /* unknown [2] IMPLICIT UnknownInfo */
            case 0xa2: /* byKey   [2]                     */
                *(uint8_t *)expVal = realTag;
                return BSL_SUCCESS;
            default:
                return BSL_ASN1_ERR_MISMATCH_TAG;
        }
    }
    if (type == BSL_ASN1_TYPE_GET_ANY_TAG) {
        /* data = &previousAsn (BSL_ASN1_Buffer *) — determine expected tag from previous OID */
        if (expVal == NULL) {
            return BSL_ASN1_ERR_MISMATCH_TAG;
        }
        BSL_ASN1_Buffer *prev = (BSL_ASN1_Buffer *)data;
        if (prev == NULL || prev->buff == NULL || prev->len == 0) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
            return BSL_SUCCESS;
        }
        BslCid cid = BSL_OBJ_GetCidFromOidBuff(prev->buff, prev->len);
        if (cid == BSL_CID_RSASSAPSS) {
            *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
        } else {
            *(uint8_t *)expVal = BSL_ASN1_TAG_NULL;
        }
        return BSL_SUCCESS;
    }
    return BSL_ASN1_FAIL;
}

int32_t OcspSetNonce(HITLS_X509_Ext **ext, uint8_t *data, uint32_t dataLen)
{
    if (ext == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }

    if (dataLen == 0 || dataLen > HITLS_OCSP_NONCE_MAX_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_OCSP_NONCE_LEN);
        return HITLS_X509_ERR_EXT_OCSP_NONCE_LEN;
    }

    HITLS_X509_Ext *extTmp = *ext;
    if (extTmp == NULL) {
        extTmp = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_OCSP);
        if (extTmp == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    HITLS_X509_ExtOcspNonce ocspExt = {0};
    ocspExt.nonce.data = data;
    ocspExt.nonce.dataLen = dataLen;

    int32_t ret = HITLS_X509_ExtCtrl(extTmp, HITLS_X509_EXT_SET_OCSP_NONCE,
                                     &ocspExt, sizeof(HITLS_X509_ExtOcspNonce));
    if (ret != HITLS_PKI_SUCCESS) {
        if (*ext == NULL) {
            HITLS_X509_ExtFree(extTmp);
        }
        return ret;
    }
    *ext = extTmp;
    return HITLS_PKI_SUCCESS;
}

/* Get the nonce into *val (a BSL_Buffer).
 * Note: the returned data is a BORROWED pointer into the extension object's
 * internal storage. The caller MUST NOT free it, and it becomes invalid once
 * the HITLS_X509_Ext (and hence the enclosing request/response) is freed.
 * This matches the borrowing convention of the other GET ctrl commands. */
int32_t OcspGetNonce(HITLS_X509_Ext *ext, BSL_Buffer *val, uint32_t valLen)
{
    if (ext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_EXT_NOT_FOUND);
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }
    if (val == NULL || valLen < sizeof(BSL_Buffer)) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_INVALID_PARAM);
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    HITLS_X509_ExtOcspNonce nonceExt = {0};
    int ret = HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_GET_OCSP_NONCE,
                                 &nonceExt, sizeof(HITLS_X509_ExtOcspNonce));
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    val->data = nonceExt.nonce.data;
    val->dataLen = nonceExt.nonce.dataLen;
    return HITLS_PKI_SUCCESS;
}

int32_t OcspEncodeExt(HITLS_X509_Ext *ext, uint8_t tag, BSL_ASN1_Buffer *extData)
{
    if (ext == NULL) {
        if (extData != NULL) {
            extData->tag = 0;
            extData->len = 0;
            extData->buff = NULL;
        }
        return HITLS_PKI_SUCCESS;
    }
    return HITLS_X509_EncodeExt(tag, ext->extList, extData);
}

int32_t OcspDecodeExt(BSL_ASN1_Buffer *extSeqof, HITLS_X509_Ext **ext)
{
    HITLS_X509_Ext *extTmp = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_OCSP);
    if (extTmp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_X509_ParseExt(extSeqof, extTmp);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_ExtFree(extTmp);
        return ret;
    }
    *ext = extTmp;
    return HITLS_PKI_SUCCESS;
}

/* Collect the DER encoding of each cert (borrowed pointers into cert->rawData) into certData,
 * and accumulate the total length. On failure certData is freed and returned via the caller. */
static int32_t OcspCollectCertData(const BslList *certs, BSL_Buffer **outCertData, uint32_t *outCount,
                                   uint32_t *outTotalLen)
{
    uint32_t certCount = BSL_LIST_COUNT(certs);
    BSL_Buffer *certData = BSL_SAL_Calloc(certCount, sizeof(BSL_Buffer));
    if (certData == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    uint32_t ci = 0;
    uint32_t totalLen = 0;
    int32_t ret = HITLS_PKI_SUCCESS;
    BslListNode *node = BSL_LIST_FirstNode(certs);
    while (node != NULL) {
        HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODELEN, &certData[ci].dataLen, sizeof(uint32_t));
        if (ret != HITLS_PKI_SUCCESS) {
            break;
        }
        /* HITLS_X509_GET_ENCODE returns a borrowed pointer into cert->rawData;
         * only the certData array itself is owned here. */
        ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_ENCODE, &certData[ci].data, 0);
        if (ret != HITLS_PKI_SUCCESS) {
            break;
        }
        if (certData[ci].dataLen > UINT32_MAX - totalLen) {
            ret = BSL_ASN1_ERR_LEN_OVERFLOW;
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }

        totalLen += certData[ci].dataLen;
        ci++;
        node = BSL_LIST_GetNextNode(certs, node);
    }
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_SAL_Free(certData);
        return ret;
    }
    *outCertData = certData;
    *outCount = ci;
    *outTotalLen = totalLen;
    return HITLS_PKI_SUCCESS;
}

/* Encode a list of certs into a SEQUENCE OF Certificate TLV.
 * An empty/NULL list yields a zeroed certsV (tag 0), meaning "no certs".
 * The caller frees certsV.buff. */
int32_t OcspEncodeCerts(BslList *certs, BSL_ASN1_Buffer *certsV)
{
    if (certsV == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (certs == NULL || BSL_LIST_COUNT(certs) == 0) {
        certsV->tag = 0;
        certsV->len = 0;
        certsV->buff = NULL;
        return HITLS_PKI_SUCCESS;
    }

    BSL_Buffer *certData = NULL;
    uint32_t ci = 0;
    uint32_t totalLen = 0;
    int32_t ret = OcspCollectCertData(certs, &certData, &ci, &totalLen);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    uint8_t *seqV = BSL_SAL_Malloc(totalLen);
    if (seqV == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        BSL_SAL_Free(certData);
        return BSL_MALLOC_FAIL;
    }
    uint32_t offset = 0;
    for (uint32_t j = 0; j < ci; j++) {
        memcpy(seqV + offset, certData[j].data, certData[j].dataLen);
        offset += certData[j].dataLen;
    }
    BSL_ASN1_Buffer seqAsn = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, totalLen, seqV};
    BSL_ASN1_TemplateItem seqItem = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
    BSL_ASN1_Template seqTmpl = {&seqItem, 1};
    ret = BSL_ASN1_EncodeTemplate(&seqTmpl, &seqAsn, 1, &certsV->buff, &certsV->len);
    BSL_SAL_Free(seqV);
    BSL_SAL_Free(certData);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(certsV->buff);
        certsV->tag = 0;
        certsV->len = 0;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    certsV->tag = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
    return HITLS_PKI_SUCCESS;
}

/* Parse a cert chain from an ASN.1 buffer holding the [0] EXPLICIT content
 * (the SEQUENCE OF Certificate TLV). Allocates and fills *certs on success. */
int32_t OcspParseCerts(BSL_ASN1_Buffer *certsAsn, BslList **certs)
{
    if (certsAsn == NULL || certsAsn->buff == NULL || certs == NULL || *certs != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    uint8_t *buff = certsAsn->buff;
    uint32_t len = certsAsn->len;
    uint32_t valLen = 0;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
                                        &buff, &len, &valLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (len != valLen) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MALFORMED);
        return HITLS_OCSP_ERR_MALFORMED;
    }

    BslList *certList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (certList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    uint32_t pos = 0;
    while (pos < valLen) {
        uint32_t dataLen = valLen - pos;
        ret = BSL_ASN1_GetCompleteLen(buff + pos, &dataLen);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            break;
        }
        if (dataLen == 0 || dataLen > valLen - pos) {
            BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_MALFORMED);
            ret = HITLS_OCSP_ERR_MALFORMED;
            break;
        }
        BSL_Buffer certBuff = {buff + pos, dataLen};
        HITLS_X509_Cert *cert = NULL;
        ret = HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &certBuff, &cert);
        if (ret != HITLS_PKI_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            HITLS_X509_CertFree(cert);
            break;
        }
        ret = BSL_LIST_AddElement(certList, cert, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            HITLS_X509_CertFree(cert);
            break;
        }
        pos += dataLen;
    }

    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(certList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    *certs = certList;
    return HITLS_PKI_SUCCESS;
}

/* Validate the signing key before signing: SM2 keys are rejected (OCSP no longer supports
 * SM2), and the private key must match the signer certificate. Shared by request/response. */
int32_t OcspCheckSignKey(const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_Cert *signerCert)
{
    if (prvKey == NULL || signerCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    if (CRYPT_EAL_PkeyGetId(prvKey) == CRYPT_PKEY_SM2) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_ALG_UNSUPPORT);
        return HITLS_X509_ERR_ALG_UNSUPPORT;
    }

    CRYPT_EAL_PkeyCtx *pubKey = NULL;
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)signerCert, HITLS_X509_GET_PUBKEY, &pubKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = CRYPT_EAL_PkeyPairCheck(pubKey, (CRYPT_EAL_PkeyCtx *)(uintptr_t)prvKey);
    CRYPT_EAL_PkeyFreeCtx(pubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

int32_t OcspRefUpSignerCerts(const HITLS_X509_Cert *signerCert, const HITLS_X509_List *src, HITLS_X509_List **dst)
{
    if (signerCert == NULL || dst == NULL || *dst != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    BslList *newList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (newList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    int32_t ret = HITLS_PKI_SUCCESS;
    int32_t ref = 0;
    ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)signerCert, HITLS_X509_REF_UP, &ref, sizeof(int));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_LIST_FREE(newList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    ret = BSL_LIST_AddElement(newList, (void *)(uintptr_t)signerCert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        HITLS_X509_CertFree((HITLS_X509_Cert *)(uintptr_t)signerCert); /* release the just-taken reference */
        BSL_LIST_FREE(newList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }

    if (src != NULL) {
        BslListNode *node = BSL_LIST_FirstNode(src);
        while (node != NULL) {
            HITLS_X509_Cert *cert = (HITLS_X509_Cert *)BSL_LIST_GetData(node);
            ref = 0;
            ret = HITLS_X509_CertCtrl(cert, HITLS_X509_REF_UP, &ref, sizeof(int));
            if (ret != HITLS_PKI_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                break;
            }
            ret = BSL_LIST_AddElement(newList, cert, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                HITLS_X509_CertFree(cert); /* release the just-taken reference */
                break;
            }
            node = BSL_LIST_GetNextNode(src, node);
        }
    }

    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(newList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
        return ret;
    }
    *dst = newList;
    return HITLS_PKI_SUCCESS;
}

/* ==================== Enum to string ==================== */

const char *HITLS_OCSP_RevocationReasonToStr(int32_t reason)
{
    switch (reason) {
        case HITLS_X509_REVOKED_REASON_UNSPECIFIED:
            return "unspecified";
        case HITLS_X509_REVOKED_REASON_KEY_COMPROMISE:
            return "keyCompromise";
        case HITLS_X509_REVOKED_REASON_CA_COMPROMISE:
            return "cACompromise";
        case HITLS_X509_REVOKED_REASON_AFFILIATION_CHANGED:
            return "affiliationChanged";
        case HITLS_X509_REVOKED_REASON_SUPERSEDED:
            return "superseded";
        case HITLS_X509_REVOKED_REASON_CESSATION_OF_OPERATION:
            return "cessationOfOperation";
        case HITLS_X509_REVOKED_REASON_CERTIFICATE_HOLD:
            return "certificateHold";
        case HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL:
            return "removeFromCRL";
        case HITLS_X509_REVOKED_REASON_PRIVILEGE_WITHDRAWN:
            return "privilegeWithdrawn";
        case HITLS_X509_REVOKED_REASON_AA_COMPROMISE:
            return "aACompromise";
        default:
            return NULL;
    }
}

const char *HITLS_OCSP_CertStatusToStr(HITLS_OCSP_CertStatus status)
{
    switch (status) {
        case HITLS_OCSP_CERT_STATUS_GOOD:
            return "good";
        case HITLS_OCSP_CERT_STATUS_REVOKED:
            return "revoked";
        case HITLS_OCSP_CERT_STATUS_UNKNOWN:
            return "unknown";
        default:
            return NULL;
    }
}

const char *HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RespStatus status)
{
    switch (status) {
        case HITLS_OCSP_RESP_STATUS_SUCCESSFUL:
            return "successful";
        case HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST:
            return "malformedRequest";
        case HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR:
            return "internalError";
        case HITLS_OCSP_RESP_STATUS_TRY_LATER:
            return "tryLater";
        case HITLS_OCSP_RESP_STATUS_SIG_REQUIRED:
            return "sigRequired";
        case HITLS_OCSP_RESP_STATUS_UNAUTHORIZED:
            return "unauthorized";
        default:
            return NULL;
    }
}

/* ==================== OCSP URLs from certificate ==================== */

static void OcspFreeUrl(void *value)
{
    if (value != NULL) {
        BSL_Buffer *uri = (BSL_Buffer *)value;
        BSL_SAL_Free(uri->data);
        BSL_SAL_Free(uri);
    }
}

/* Collect the OCSP responder URIs from the AIA descriptions into urlList.
 * urlList must be a valid list; on failure it is freed by the caller. */
static int32_t OcspCollectOcspUrls(const BslList *descriptions, BslList *urlList)
{
    BslListNode *node = BSL_LIST_FirstNode(descriptions);
    while (node != NULL) {
        HITLS_X509_AccessDescription *ad = (HITLS_X509_AccessDescription *)BSL_LIST_GetData(node);
        if (ad != NULL && ad->oid.data != NULL && ad->oid.dataLen > 0 &&
            BSL_OBJ_GetCidFromOidBuff(ad->oid.data, ad->oid.dataLen) == BSL_CID_AD_OCSP &&
            ad->location.type == HITLS_X509_GN_URI && ad->location.value.data != NULL &&
            ad->location.value.dataLen > 0) {
            BSL_Buffer *uri = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
            if (uri == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                return BSL_MALLOC_FAIL;
            }
            uri->data = BSL_SAL_Dump(ad->location.value.data, ad->location.value.dataLen);
            if (uri->data == NULL) {
                BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
                BSL_SAL_Free(uri);
                return BSL_MALLOC_FAIL;
            }
            uri->dataLen = ad->location.value.dataLen;
            int32_t ret = BSL_LIST_AddElement(urlList, uri, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                BSL_ERR_PUSH_ERROR(ret);
                BSL_SAL_Free(uri->data);
                BSL_SAL_Free(uri);
                return ret;
            }
        }
        node = BSL_LIST_GetNextNode(descriptions, node);
    }
    return HITLS_PKI_SUCCESS;
}

int32_t HITLS_OCSP_GetCertOcspUrls(const HITLS_X509_Cert *cert, BslList **urls)
{
    if (cert == NULL || urls == NULL || *urls != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NULL_POINTER);
        return HITLS_OCSP_ERR_NULL_POINTER;
    }

    HITLS_X509_ExtAia aia = {0};
    int32_t ret = HITLS_X509_CertCtrl((HITLS_X509_Cert *)(uintptr_t)cert, HITLS_X509_EXT_GET_AIA,
                                      &aia, sizeof(HITLS_X509_ExtAia));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_OCSP_URL);
        return HITLS_OCSP_ERR_NO_OCSP_URL;
    }

    if (aia.descriptions == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_OCSP_URL);
        HITLS_X509_ClearAia(&aia);
        return HITLS_OCSP_ERR_NO_OCSP_URL;
    }

    BslList *urlList = BSL_LIST_New(sizeof(BSL_Buffer *));
    if (urlList == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        HITLS_X509_ClearAia(&aia);
        return BSL_MALLOC_FAIL;
    }

    ret = OcspCollectOcspUrls(aia.descriptions, urlList);
    HITLS_X509_ClearAia(&aia);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_LIST_FREE(urlList, (BSL_LIST_PFUNC_FREE)OcspFreeUrl);
        return ret;
    }
    if (BSL_LIST_COUNT(urlList) == 0) {
        BSL_LIST_FREE(urlList, (BSL_LIST_PFUNC_FREE)OcspFreeUrl);
        BSL_ERR_PUSH_ERROR(HITLS_OCSP_ERR_NO_OCSP_URL);
        return HITLS_OCSP_ERR_NO_OCSP_URL;
    }

    *urls = urlList;
    return HITLS_PKI_SUCCESS;
}

#endif // HITLS_PKI_OCSP
