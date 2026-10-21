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

/* BEGIN_HEADER */
#include "bsl_asn1.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "bsl_obj.h"
#include "bsl_err.h"
#include "bsl_uio.h"
#include "bsl_params.h"
#include "bsl_init.h"
#include "stub_utils.h"
#include "crypto_test_util.h"
#include "test.h"
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_ocsp_http.h"
#include "hitls_pki_types.h"
#include "hitls_ocsp_local.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "http_test_stub.h"
#include "bsl/bsl_sal.h"
#include "bsl/bsl_types.h"
#include "bsl/bsl_err.h"
#include "bsl/bsl_obj.h"
#include "crypto/crypt_algid.h"
#include "crypto/crypt_eal_init.h"
#include "crypto/crypt_eal_md.h"
#include "crypto/crypt_eal_pkey.h"
#include "crypto/crypt_eal_codecs.h"
#include "crypto/crypt_errno.h"
#include "pki/hitls_pki_cert.h"
#include "pki/hitls_pki_errno.h"
#include "pki/hitls_pki_ocsp.h"
#include "pki/hitls_pki_types.h"
#include "pki/hitls_pki_utils.h"
#include "bsl/bsl_uio.h"
#include "bsl_buffer.h"
// #include "tls/hitls_cert_init.h"
// #include "tls/hitls_crypt_init.h"

// 遗留问题
// （1）g_basicRespEncTempl 和 g_basicRespParseTempl未归一
// 解析basicResp时算法oid和参数，与其他字段一起解析
// 编码时先将算法oid和参数编码，然后作为一个整体再编码到basicResp中

#define OCSP_TEST_MAX_CERTS 4

typedef struct {
    HITLS_X509_Cert *root;
    HITLS_X509_Cert *intermediate;
    HITLS_X509_Cert *ee;
    CRYPT_EAL_PkeyCtx *rootKey;
    CRYPT_EAL_PkeyCtx *intermediateKey;
    CRYPT_EAL_PkeyCtx *eeKey;
} OcspTestCertChain;

static int32_t OcspTestInit(void)
{
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS) {
        return -1;
    }
    BSL_GLOBAL_Init();
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    return 0;
}

static void FreeListData(void *data)
{
    (void)data;
    return;
}

/* Frees the certificates themselves, for lists that own their entries. */
static void FreeCertListData(void *data)
{
    HITLS_X509_CertFree((HITLS_X509_Cert *)data);
}

static int32_t OcspTestGenKey(CRYPT_EAL_PkeyCtx **key)
{
    *key = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (*key == NULL) {
        return -1;
    }
    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = sizeof(e);
    para.para.rsaPara.bits = 1024;
    int32_t ret = CRYPT_EAL_PkeySetPara(*key, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(*key);
        *key = NULL;
        return -1;
    }
    ret = CRYPT_EAL_PkeyGen(*key);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(*key);
        *key = NULL;
        return -1;
    }
    return 0;
}

static int32_t OcspTestCreateCertEx(HITLS_X509_Cert **cert, CRYPT_EAL_PkeyCtx *subjectKey, HITLS_X509_Cert *issuerCert,
                                    CRYPT_EAL_PkeyCtx *issuerKey, const char *cn, bool isCA, int32_t years,
                                    const HITLS_X509_SignAlgParam *algParam)
{
    HITLS_X509_Cert *c = HITLS_X509_CertNew();
    if (c == NULL) {
        return -1;
    }
    int32_t version = 2; // v3
    int32_t ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_VERSION, &version, sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    BSL_TIME notAfter = now;
    notAfter.year += years;
    ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_BEFORE_TIME, &now, sizeof(BSL_TIME));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_AFTER_TIME, &notAfter, sizeof(BSL_TIME));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    // serial
    uint8_t serial[4] = {0x11, 0x22, 0x33, 0x44};
    serial[0] |= 0x80; // ensure positive
    ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_SERIALNUM, serial, sizeof(serial));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    // DN list for subject and issuer
    HITLS_X509_DN dnName = {BSL_CID_AT_COMMONNAME, (uint8_t *)cn, (uint32_t)strlen(cn)};
    BslList *dnList = HITLS_X509_DnListNew();
    if (dnList == NULL) {
        ret = -1;
        goto ERR;
    }
    ret = HITLS_X509_AddDnName(dnList, &dnName, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(dnList);
        goto ERR;
    }

    ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(dnList);
        goto ERR;
    }

    if (issuerCert != NULL) {
        BslList *issuerDn = NULL;
        HITLS_X509_CertCtrl(issuerCert, HITLS_X509_GET_SUBJECT_DN, &issuerDn, sizeof(BslList *));
        ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_ISSUER_DN, issuerDn, sizeof(BslList));
    } else {
        ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList));
    }
    HITLS_X509_DnListFree(dnList);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    // pubkey
    ret = HITLS_X509_CertCtrl(c, HITLS_X509_SET_PUBKEY, subjectKey, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    // basic constraints
    HITLS_X509_ExtBCons bc = {0};
    bc.isCa = isCA;
    if (isCA) {
        bc.maxPathLen = 1;
    }
    ret = HITLS_X509_CertCtrl(c, HITLS_X509_EXT_SET_BCONS, &bc, sizeof(HITLS_X509_ExtBCons));
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    // sign (algParam == NULL means PKCS#1 v1.5 SHA-256; non-NULL allows e.g. RSA-PSS)
    ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, issuerKey, algParam, c);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }

    BSL_Buffer derBuff = {0};
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, c, &derBuff);
    if (ret != HITLS_PKI_SUCCESS) {
        goto ERR;
    }
    BSL_SAL_Free(derBuff.data);

    *cert = c;
    return 0;
ERR:
    HITLS_X509_CertFree(c);
    return -1;
}

static int32_t OcspTestCreateCert(HITLS_X509_Cert **cert, CRYPT_EAL_PkeyCtx *subjectKey, HITLS_X509_Cert *issuerCert,
                                  CRYPT_EAL_PkeyCtx *issuerKey, const char *cn, bool isCA)
{
    return OcspTestCreateCertEx(cert, subjectKey, issuerCert, issuerKey, cn, isCA, 10, NULL);
}

static int32_t OcspTestCreateCertChain(OcspTestCertChain *chain)
{
    if (OcspTestGenKey(&chain->rootKey) != 0) {
        return -1;
    }
    if (OcspTestGenKey(&chain->intermediateKey) != 0) {
        return -1;
    }
    if (OcspTestGenKey(&chain->eeKey) != 0) {
        return -1;
    }

    chain->root = NULL;
    chain->intermediate = NULL;
    chain->ee = NULL;

    if (OcspTestCreateCert(&chain->root, chain->rootKey, NULL, chain->rootKey, "OCSP Test Root CA", true) != 0) {
        return -1;
    }
    if (OcspTestCreateCert(&chain->intermediate, chain->intermediateKey, chain->root, chain->rootKey,
                           "OCSP Test Intermediate CA", true) != 0) {
        return -1;
    }
    if (OcspTestCreateCert(&chain->ee, chain->eeKey, chain->intermediate, chain->intermediateKey, "OCSP Test EE",
                           false) != 0) {
        return -1;
    }
    return 0;
}

static void OcspTestFreeCertChain(OcspTestCertChain *chain)
{
    HITLS_X509_CertFree(chain->root);
    HITLS_X509_CertFree(chain->intermediate);
    HITLS_X509_CertFree(chain->ee);
    CRYPT_EAL_PkeyFreeCtx(chain->rootKey);
    CRYPT_EAL_PkeyFreeCtx(chain->intermediateKey);
    CRYPT_EAL_PkeyFreeCtx(chain->eeKey);
}

/* Build a full cert chain whose certificates are all signed with RSA-PSS and valid
 * for 'years' years. Reuses the standard RSA keys from OcspTestGenKey. */
static int32_t OcspTestCreatePssCertChain(OcspTestCertChain *chain, int32_t years)
{
    if (OcspTestGenKey(&chain->rootKey) != 0) {
        return -1;
    }
    if (OcspTestGenKey(&chain->intermediateKey) != 0) {
        return -1;
    }
    if (OcspTestGenKey(&chain->eeKey) != 0) {
        return -1;
    }

    chain->root = NULL;
    chain->intermediate = NULL;
    chain->ee = NULL;

    HITLS_X509_SignAlgParam pssParam = {0};
    pssParam.algId = BSL_CID_RSASSAPSS;
    pssParam.rsaPss.saltLen = 32;
    pssParam.rsaPss.mdId = CRYPT_MD_SHA256;
    pssParam.rsaPss.mgfId = CRYPT_MD_SHA256;

    if (OcspTestCreateCertEx(&chain->root, chain->rootKey, NULL, chain->rootKey, "OCSP PSS Root CA", true, years,
                             &pssParam) != 0) {
        return -1;
    }
    if (OcspTestCreateCertEx(&chain->intermediate, chain->intermediateKey, chain->root, chain->rootKey,
                             "OCSP PSS Intermediate CA", true, years, &pssParam) != 0) {
        return -1;
    }
    if (OcspTestCreateCertEx(&chain->ee, chain->eeKey, chain->intermediate, chain->intermediateKey, "OCSP PSS EE",
                             false, years, &pssParam) != 0) {
        return -1;
    }
    return 0;
}

static HITLS_OCSP_SingleResp *OcspTestCreateSingleResp(CRYPT_EAL_MdCtx *mdCtx, HITLS_X509_Cert *targetCert,
                                                       HITLS_X509_Cert *issuerCert, HITLS_OCSP_CertStatus status)
{
    HITLS_OCSP_CertId *certId = HITLS_OCSP_CertIdNewFromCert(mdCtx, targetCert, issuerCert);
    if (certId == NULL) {
        return NULL;
    }
    BSL_TIME thisUpdate = {0};
    BSL_TIME nextUpdate = {0};
    BSL_SAL_SysTimeGet(&thisUpdate);
    nextUpdate = thisUpdate;
    nextUpdate.hour += 4;
    HITLS_OCSP_SingleResp *sr = HITLS_OCSP_SingleRespNew(certId, status, &thisUpdate);
    if (sr == NULL) {
        HITLS_OCSP_CertIdFree(certId);
        return NULL;
    }
    certId = NULL;
    HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE, &nextUpdate, sizeof(BSL_TIME));
    if (status == HITLS_OCSP_CERT_STATUS_REVOKED) {
        BSL_TIME revokeTime = thisUpdate;
        revokeTime.hour -= 1;
        int32_t reason = HITLS_X509_REVOKED_REASON_KEY_COMPROMISE;
        HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME, &revokeTime, sizeof(BSL_TIME));
        HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &reason, sizeof(int32_t));
    }
    return sr;
}

static HITLS_OCSP_BasicResp *OcspTestCreateBasicResp(HITLS_X509_Cert *responderCert, CRYPT_EAL_PkeyCtx *responderKey,
                                                     HITLS_X509_List *certs, HITLS_OCSP_SingleResp **singleResps,
                                                     uint32_t count, BSL_Buffer *nonce)
{
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    if (bs == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < count; i++) {
        int32_t ret = HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, (void *)singleResps[i],
                                               sizeof(HITLS_OCSP_SingleResp *));
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_BasicRespFree(bs);
            return NULL;
        }
        singleResps[i] = NULL; // ownership transferred
    }
    if (nonce != NULL && nonce->data != NULL) {
        int32_t ret = HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_SET_NONCE, nonce->data, nonce->dataLen);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_BasicRespFree(bs);
            return NULL;
        }
    }
    int32_t ret = HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, responderKey, NULL, responderCert, certs, bs, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_BasicRespFree(bs);
        return NULL;
    }
    return bs;
}

static OcspTestCertChain g_chain1 = {0};
static OcspTestCertChain g_chain2 = {0};
static CRYPT_EAL_MdCtx *g_mdCtx = NULL;
static bool g_ocspTestInited = false;

static HITLS_X509_StoreCtx *OcspTestNewStoreCtx(HITLS_X509_Cert *trustedRoot)
{
    HITLS_X509_StoreCtx *storeCtx = HITLS_X509_StoreCtxNew();
    if (storeCtx == NULL) {
        return NULL;
    }
    int32_t ret = HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, trustedRoot, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_StoreCtxFree(storeCtx);
        return NULL;
    }
    return storeCtx;
}

/* EC P-256 private key matching g_icaDer (the preset intermediate CA). */
static const uint8_t g_icaKeyDer[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x77, 0x15, 0x6e, 0xd8, 0x4d, 0x39, 0x1f, 0x7b, 0x00, 0x8d, 0x64, 0x7d,
    0xa3, 0x5a, 0xb5, 0x33, 0xac, 0x8f, 0xd1, 0xbb, 0x77, 0x9e, 0xbe, 0x03, 0x47, 0x86, 0xcd, 0x32, 0xbe, 0xa4, 0x41,
    0x83, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04,
    0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e,
    0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3,
    0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd,
    0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b,
};

/* Parse the preset intermediate CA private key (g_icaKeyDer). */
static CRYPT_EAL_PkeyCtx *OcspTestLoadIcaKey(void)
{
    BSL_Buffer keyBuf = {(uint8_t *)g_icaKeyDer, sizeof(g_icaKeyDer)};
    CRYPT_EAL_PkeyCtx *key = NULL;
    int32_t ret = CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_ECC, &keyBuf, NULL, 0, &key);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }
    return key;
}

static int32_t OcspTestGlobalSetup(void)
{
    if (g_ocspTestInited) {
        return 0;
    }
    TestMemInit();
    if (OcspTestInit() != 0) {
        return -1;
    }
    if (OcspTestCreateCertChain(&g_chain1) != 0) {
        return -1;
    }
    if (OcspTestCreateCertChain(&g_chain2) != 0) {
        return -1;
    }
    g_mdCtx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    if (g_mdCtx == NULL) {
        return -1;
    }
    g_ocspTestInited = true;
    return 0;
}
/* END_HEADER */

/* ASN.1 TLV jump: parse tag+length at pos, return value position and value length. */
static int32_t OcspTestSkipTlv(const uint8_t *der, uint32_t derLen, uint32_t pos, uint32_t *valuePos,
                               uint32_t *valueLen)
{
    if (der == NULL || pos >= derLen) {
        return -1;
    }
    uint32_t tagLen = 1;
    if ((der[pos] & 0x1f) == 0x1f) {
        tagLen++;
        while (pos + tagLen < derLen && (der[pos + tagLen - 1] & 0x80) != 0) {
            tagLen++;
        }
    }
    pos += tagLen;
    if (pos >= derLen) {
        return -1;
    }
    uint32_t valLen = 0;
    if ((der[pos] & 0x80) == 0) {
        valLen = der[pos];
        pos += 1;
    } else {
        uint32_t n = der[pos] & 0x7f;
        pos += 1;
        if (n == 0 || pos + n > derLen) {
            return -1;
        }
        for (uint32_t i = 0; i < n; i++) {
            valLen = (valLen << 8) | der[pos + i];
        }
        pos += n;
    }
    if (pos + valLen > derLen) {
        return -1;
    }
    *valuePos = pos;
    *valueLen = valLen;
    return 0;
}

/* Extract the ResponseData (tbsResponseData) TLV from a full OCSPResponse DER.
 * rdOut and rdLenOut cover tag+length+content of the ResponseData SEQUENCE. */
static int32_t OcspTestExtractResponseData(const uint8_t *der, uint32_t derLen, const uint8_t **rdOut,
                                           uint32_t *rdLenOut)
{
    uint32_t vp = 0;
    uint32_t vl = 0;
    uint32_t vp2 = 0;
    uint32_t vl2 = 0;
    /* OCSPResponse SEQUENCE (container): value starts at responseStatus */
    if (OcspTestSkipTlv(der, derLen, 0, &vp, &vl) != 0) {
        return -1;
    }
    /* responseStatus ENUMERATED (leaf): skip to next sibling */
    if (OcspTestSkipTlv(der, derLen, vp, &vp2, &vl2) != 0) {
        return -1;
    }
    uint32_t rbTag = vp2 + vl2;
    /* responseBytes [0] EXPLICIT (container): value starts at ResponseBytes SEQUENCE */
    if (OcspTestSkipTlv(der, derLen, rbTag, &vp, &vl) != 0) {
        return -1;
    }
    /* ResponseBytes SEQUENCE (container): value starts at responseType OID */
    if (OcspTestSkipTlv(der, derLen, vp, &vp, &vl) != 0) {
        return -1;
    }
    /* responseType OID (leaf): skip to next sibling (OCTET STRING) */
    if (OcspTestSkipTlv(der, derLen, vp, &vp2, &vl2) != 0) {
        return -1;
    }
    uint32_t octetTag = vp2 + vl2;
    /* response OCTET STRING (container): value = BasicOCSPResponse */
    if (OcspTestSkipTlv(der, derLen, octetTag, &vp, &vl) != 0) {
        return -1;
    }
    /* BasicOCSPResponse SEQUENCE (container): value starts at ResponseData */
    if (OcspTestSkipTlv(der, derLen, vp, &vp, &vl) != 0) {
        return -1;
    }
    /* ResponseData SEQUENCE */
    uint32_t rdTagStart = vp;
    if (OcspTestSkipTlv(der, derLen, vp, &vp2, &vl2) != 0) {
        return -1;
    }
    *rdOut = der + rdTagStart;
    *rdLenOut = (vp2 - rdTagStart) + vl2;
    return 0;
}

/* Compare two full OCSPResponse DERs field-by-field, ignoring the producedAt field
 * (which is auto-generated at sign time). Returns 0 when all other fields match. */
static int32_t OcspTestCompareRespNoProducedAt(const uint8_t *a, uint32_t aLen, const uint8_t *b, uint32_t bLen)
{
    const uint8_t *ra = NULL;
    const uint8_t *rb = NULL;
    uint32_t raLen = 0;
    uint32_t rbLen = 0;
    if (OcspTestExtractResponseData(a, aLen, &ra, &raLen) != 0 ||
        OcspTestExtractResponseData(b, bLen, &rb, &rbLen) != 0) {
        return -1;
    }
    /* ra points at the ResponseData SEQUENCE tag. Skip the SEQUENCE header to reach
     * the first child (responderID). */
    uint32_t va = 0, vla = 0;
    uint32_t vb = 0, vlb = 0;
    if (OcspTestSkipTlv(ra, raLen, 0, &va, &vla) != 0) {
        return -1;
    }
    if (OcspTestSkipTlv(rb, rbLen, 0, &vb, &vlb) != 0) {
        return -1;
    }
    /* va/vb = start of responderID TLV. Skip it to find producedAt. */
    uint32_t ridValA = 0, ridValB = 0;
    uint32_t ridVLenA = 0, ridVLenB = 0;
    if (OcspTestSkipTlv(ra, raLen, va, &ridValA, &ridVLenA) != 0) {
        return -1;
    }
    if (OcspTestSkipTlv(rb, rbLen, vb, &ridValB, &ridVLenB) != 0) {
        return -1;
    }
    uint32_t ridEndA = ridValA + ridVLenA;
    uint32_t ridEndB = ridValB + ridVLenB;
    /* Skip producedAt TLV */
    uint32_t paValA = 0, paValB = 0;
    uint32_t paVLenA = 0, paVLenB = 0;
    if (OcspTestSkipTlv(ra, raLen, ridEndA, &paValA, &paVLenA) != 0) {
        return -1;
    }
    if (OcspTestSkipTlv(rb, rbLen, ridEndB, &paValB, &paVLenB) != 0) {
        return -1;
    }
    uint32_t producedAtEndA = paValA + paVLenA;
    uint32_t producedAtEndB = paValB + paVLenB;
    /* responderID + (responses/extensions after producedAt) must match. */
    uint32_t ridLenA = ridEndA - va;
    uint32_t ridLenB = ridEndB - vb;
    if (ridLenA != ridLenB || memcmp(ra + va, rb + vb, ridLenA) != 0) {
        return -1;
    }
    uint32_t tailA = raLen - producedAtEndA;
    uint32_t tailB = rbLen - producedAtEndB;
    if (tailA != tailB || memcmp(ra + producedAtEndA, rb + producedAtEndB, tailA) != 0) {
        return -1;
    }
    return 0;
}

/* Extract the full TBSRequest TLV from an OCSPRequest DER.
 * OCSPRequest ::= SEQUENCE { TBSRequest, optionalSignature [0] OPTIONAL } */
static int32_t OcspTestExtractReqTbs(const uint8_t *der, uint32_t derLen, const uint8_t **tbsOut,
                                     uint32_t *tbsLenOut)
{
    uint32_t vp = 0;
    uint32_t vl = 0;
    uint32_t vp2 = 0;
    uint32_t vl2 = 0;
    /* OCSPRequest SEQUENCE: value starts at TBSRequest TLV */
    if (OcspTestSkipTlv(der, derLen, 0, &vp, &vl) != 0) {
        return -1;
    }
    /* TBSRequest SEQUENCE */
    if (OcspTestSkipTlv(der, derLen, vp, &vp2, &vl2) != 0) {
        return -1;
    }
    *tbsOut = der + vp;
    *tbsLenOut = (vp2 - vp) + vl2;
    return 0;
}

/* Build an OCSP request with 1 or 2 CertIDs and an optional nonce. */
/* Exercise the OCSP print APIs on an in-memory UIO (no terminal output).
 * Returns HITLS_PKI_SUCCESS on success, the print error code otherwise. */
static void Print2Terminal(BSL_UIO *uio)
{
    BSL_BufMem *bufMem = NULL;
    if (BSL_UIO_Ctrl(uio, BSL_UIO_MEM_GET_PTR, sizeof(BSL_BufMem *), &bufMem) != BSL_SUCCESS || bufMem == NULL ||
        bufMem->length == 0) {
        printf("  (empty output)\n");
    } else {
        printf("%.*s", (int)bufMem->length, bufMem->data);
        if (bufMem->data[bufMem->length - 1] != '\n') {
            printf("\n");
        }
    }
}

static int32_t OcspTestPrintReq(const HITLS_OCSP_Req *req)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    if (uio == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_REQ, (void *)req, sizeof(HITLS_OCSP_Req *), uio);

    if (1) {
        Print2Terminal(uio);
    }

    BSL_UIO_Free(uio);
    return ret;
}

static int32_t OcspTestPrintResp(const HITLS_OCSP_Resp *resp)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    if (uio == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_RESP, (void *)resp, sizeof(HITLS_OCSP_Resp *), uio);

    if (1) {
        Print2Terminal(uio);
    }

    BSL_UIO_Free(uio);
    return ret;
}

static HITLS_OCSP_Req *OcspTestBuildReq(CRYPT_MD_AlgId hashAlg, HITLS_X509_Cert *cert, HITLS_X509_Cert *issuer,
                                        HITLS_X509_Cert *cert2, HITLS_X509_Cert *issuer2, const uint8_t *nonce,
                                        uint32_t nonceLen)
{
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(hashAlg);
    if (mdCtx == NULL) {
        return NULL;
    }
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(mdCtx, cert, issuer);
    if (cid == NULL) {
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    HITLS_OCSP_SingleReq *sr = HITLS_OCSP_SingleReqNew(cid);
    if (sr == NULL) {
        HITLS_OCSP_CertIdFree(cid);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    HITLS_OCSP_Req *req = HITLS_OCSP_ReqNew();
    if (req == NULL) {
        HITLS_OCSP_SingleReqFree(sr);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    int32_t ret = HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr));
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_SingleReqFree(sr);
        HITLS_OCSP_ReqFree(req);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    if (cert2 != NULL) {
        HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(mdCtx, cert2, issuer2);
        if (cid2 == NULL) {
            HITLS_OCSP_ReqFree(req);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
        HITLS_OCSP_SingleReq *sr2 = HITLS_OCSP_SingleReqNew(cid2);
        if (sr2 == NULL) {
            HITLS_OCSP_CertIdFree(cid2);
            HITLS_OCSP_ReqFree(req);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
        ret = HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr2, sizeof(sr2));
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_SingleReqFree(sr2);
            HITLS_OCSP_ReqFree(req);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
    }
    if (nonce != NULL && nonceLen > 0) {
        ret = HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, (void *)nonce, nonceLen);
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_ReqFree(req);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
    }
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return req;
}

/* Rebuild an OCSP response from a parsed (Pre-generated) BasicResp, using
 * openHiTLS objects reconstructed with the same parameters. */
static HITLS_OCSP_Resp *OcspTestRebuildResp(const HITLS_OCSP_BasicResp *parsedBs, CRYPT_MD_AlgId certIdHashAlg,
                                            HITLS_X509_Cert *targetCert, HITLS_X509_Cert *issuerCert,
                                            HITLS_X509_Cert *responderCert, HITLS_OCSP_SignFlag ridFlags,
                                            CRYPT_EAL_PkeyCtx *signKey, HITLS_X509_List *certs, uint32_t signFlags)
{
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(certIdHashAlg);
    if (mdCtx == NULL) {
        return NULL;
    }
    int32_t ret = 0;
    BSL_Buffer nonce = {0};
    int32_t nonceRet = HITLS_OCSP_BasicRespCtrl((HITLS_OCSP_BasicResp *)parsedBs, HITLS_OCSP_BASICRESP_GET_NONCE,
                                                &nonce, sizeof(nonce));

    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    if (bs == NULL) {
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }

    uint32_t count = 0;
    ret = HITLS_OCSP_BasicRespGetRespCount(parsedBs, &count);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_BasicRespFree(bs);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    for (uint32_t i = 0; i < count; i++) {
        HITLS_OCSP_SingleResp *psr = NULL;
        ret = HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, i, &psr);
        if (ret != HITLS_PKI_SUCCESS || psr == NULL) {
            HITLS_OCSP_BasicRespFree(bs);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
        HITLS_OCSP_CertStatus status = (HITLS_OCSP_CertStatus)0xFF;
        HITLS_OCSP_SingleRespCtrl(psr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &status, sizeof(status));
        BSL_TIME thisUpdate = {0};
        HITLS_OCSP_SingleRespCtrl(psr, HITLS_OCSP_SINGLERESP_GET_THIS_UPDATE, &thisUpdate, sizeof(thisUpdate));
        HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(mdCtx, targetCert, issuerCert);
        if (cid == NULL) {
            HITLS_OCSP_BasicRespFree(bs);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
        HITLS_OCSP_SingleResp *sr = HITLS_OCSP_SingleRespNew(cid, status, &thisUpdate);
        if (sr == NULL) {
            HITLS_OCSP_CertIdFree(cid);
            HITLS_OCSP_BasicRespFree(bs);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
        BSL_TIME nextUpdate = {0};
        if (HITLS_OCSP_SingleRespCtrl(psr, HITLS_OCSP_SINGLERESP_GET_NEXT_UPDATE, &nextUpdate, sizeof(nextUpdate)) ==
            HITLS_PKI_SUCCESS) {
            HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE, &nextUpdate, sizeof(nextUpdate));
        }
        if (status == HITLS_OCSP_CERT_STATUS_REVOKED) {
            BSL_TIME revTime = {0};
            int32_t reason = 0;
            HITLS_OCSP_SingleRespCtrl(psr, HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME, &revTime, sizeof(revTime));
            HITLS_OCSP_SingleRespCtrl(psr, HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON, &reason, sizeof(reason));
            HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME, &revTime, sizeof(revTime));
            HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &reason, sizeof(reason));
        }
        ret = HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, (void *)sr, sizeof(sr));
        if (ret != HITLS_PKI_SUCCESS) {
            HITLS_OCSP_SingleRespFree(sr);
            HITLS_OCSP_BasicRespFree(bs);
            CRYPT_EAL_MdFreeCtx(mdCtx);
            return NULL;
        }
    }
    if (nonceRet == HITLS_PKI_SUCCESS && nonce.data != NULL) {
        HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_SET_NONCE, nonce.data, nonce.dataLen);
    }
    ret = HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, signKey, NULL, responderCert, certs, bs, signFlags | ridFlags);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_BasicRespFree(bs);
        CRYPT_EAL_MdFreeCtx(mdCtx);
        return NULL;
    }
    HITLS_OCSP_Resp *resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    CRYPT_EAL_MdFreeCtx(mdCtx);
    return resp;
}

static const uint8_t g_rootCaDer[] = {
    0x30, 0x82, 0x01, 0x84, 0x30, 0x82, 0x01, 0x29, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x40, 0x02, 0x0f, 0x9d,
    0x73, 0xb4, 0x7d, 0xed, 0x29, 0xc8, 0x9a, 0x25, 0xc3, 0xbc, 0xa1, 0xd4, 0xc0, 0x47, 0xb9, 0xa6, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39,
    0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0x3b, 0x74, 0x7e, 0xe9, 0xc5, 0x39, 0x2d, 0xf7, 0xb9, 0xf0, 0xe2, 0x73, 0xec, 0xce, 0xd9,
    0xe5, 0x0a, 0xd7, 0xf6, 0x4c, 0x5c, 0x6c, 0xb9, 0x29, 0x9e, 0x1d, 0x64, 0xce, 0x4b, 0x85, 0xb5, 0x00, 0x6a, 0xb6,
    0xd0, 0x0f, 0xd0, 0x47, 0xa8, 0xb0, 0x6b, 0xed, 0xf6, 0x6c, 0x25, 0x11, 0xe0, 0xf0, 0xb5, 0xda, 0x90, 0xdc, 0xf7,
    0x2c, 0xcc, 0x1b, 0x39, 0x56, 0x5f, 0xc5, 0x02, 0x2f, 0xb8, 0xd1, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f,
    0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39,
    0x27, 0xe4, 0xe4, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02,
    0x21, 0x00, 0xd3, 0xed, 0x96, 0x12, 0x33, 0x39, 0x27, 0xc3, 0x4f, 0x5f, 0x6a, 0x3c, 0x36, 0x87, 0x77, 0x1f, 0x58,
    0x42, 0x12, 0x7c, 0x53, 0xc9, 0xce, 0x89, 0x91, 0x03, 0xe3, 0x0b, 0x78, 0x39, 0xd0, 0xa8, 0x02, 0x21, 0x00, 0x94,
    0xf0, 0x57, 0x10, 0x03, 0x01, 0x96, 0x59, 0x7d, 0x8e, 0xf1, 0xbc, 0x3d, 0xdb, 0xc3, 0xaa, 0x94, 0xbc, 0xd3, 0x1b,
    0x47, 0x8e, 0xe4, 0xea, 0x6e, 0x3a, 0x77, 0x9f, 0x92, 0xfb, 0xe2, 0x4e,
};

static const uint8_t g_icaDer[] = {
    0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9,
    0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39,
    0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74,
    0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86,
    0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11,
    0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33,
    0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b,
    0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5,
    0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64,
    0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
    0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65,
    0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19,
    0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f,
     0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_reqMinSha256Der[] = {
    0x30, 0x71, 0x30, 0x6f, 0x30, 0x6d, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a,
    0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94,
    0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1,
    0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca,
    0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3,
    0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_reqMultiSha256Der[] = {
    0x30, 0x82, 0x01, 0x06, 0x30, 0x82, 0x01, 0x02, 0x30, 0x81, 0xda, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09,
    0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7,
    0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7,
    0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7,
    0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba,
    0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x73, 0x48, 0xc7, 0xec, 0x71, 0x5d, 0x08, 0xa9, 0x22, 0x3e, 0x77,
    0x06, 0xd5, 0x0f, 0x40, 0xc0, 0x86, 0x2b, 0x86, 0x80, 0xdd, 0x04, 0x2d, 0x1c, 0x92, 0x11, 0x72, 0x5c, 0xb2, 0xab,
    0xbc, 0x41, 0x04, 0x20, 0xea, 0xf1, 0xd6, 0xde, 0x6a, 0x59, 0xe4, 0x1f, 0x4b, 0x9c, 0xaf, 0xa7, 0xe5, 0x4f, 0xcd,
    0x7c, 0xfb, 0x58, 0x2f, 0x98, 0xdf, 0x2a, 0x11, 0x91, 0xe2, 0xf4, 0x8f, 0x74, 0x12, 0x22, 0x6e, 0x93, 0x02, 0x14,
    0x4b, 0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1,
    0x54, 0xa2, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
    0x12, 0x04, 0x10, 0xf1, 0x1b, 0xc3, 0x86, 0x18, 0xc9, 0xdb, 0xa9, 0xc8, 0x82, 0x27, 0x91, 0xed, 0x03, 0x38, 0xb4};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_reqMinSha1Der[] = {
    0x30, 0x55, 0x30, 0x53, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
    0x1a, 0x05, 0x00, 0x04, 0x14, 0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff, 0xe6, 0x16, 0x8b, 0x75, 0xa0, 0x61, 0x38,
    0xae, 0x4b, 0x93, 0x4c, 0x66, 0x3e, 0x82, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5,
    0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97,
    0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_respGoodByKeySha256Der[] = {
    0x30, 0x82, 0x02, 0xf0, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0xe9, 0x30, 0x82, 0x02, 0xe5, 0x06, 0x09, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0xd6, 0x30, 0x82, 0x02, 0xd2, 0x30, 0x81, 0xe5, 0xa2,
    0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf,
    0xe3, 0xcb, 0x5e, 0x29, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x32, 0x30, 0x33, 0x32, 0x34, 0x31,
    0x36, 0x5a, 0x30, 0x81, 0x94, 0x30, 0x81, 0x91, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed,
    0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b,
    0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc,
    0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14,
    0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0,
    0x7d, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
    0x12, 0x04, 0x10, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21,
    0x00, 0x96, 0xc0, 0x94, 0x82, 0x28, 0x04, 0xc5, 0xc4, 0xbd, 0xd3, 0x0d, 0x27, 0x29, 0xb7, 0x74, 0x6c, 0xc3, 0xfd,
    0x4c, 0x01, 0x98, 0xf3, 0xf0, 0x84, 0xc9, 0x6e, 0xf6, 0x44, 0x9e, 0xe0, 0x49, 0x00, 0x02, 0x20, 0x26, 0x0d, 0x22,
    0x8b, 0xdc, 0x92, 0x8c, 0x8d, 0x97, 0x25, 0x17, 0x3e, 0xa4, 0xe0, 0x5f, 0x18, 0xe7, 0x35, 0xc9, 0xc3, 0x0c, 0x06,
    0xe5, 0x4f, 0x08, 0x01, 0x80, 0xca, 0x12, 0x66, 0x8d, 0x2d, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30,
    0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e,
    0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31,
    0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
    0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45,
    0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d,
    0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad,
    0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3,
    0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b,
    0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9,
    0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
    0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4,
    0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02,
    0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac,
    0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_respMinByNameSha256Der[] = {
    0x30, 0x82, 0x01, 0x2d, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0x26, 0x30, 0x82, 0x01, 0x22, 0x06, 0x09, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0x13, 0x30, 0x82, 0x01, 0x0f, 0x30, 0x81,
    0xb7, 0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43,
    0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41,
    0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x32, 0x30, 0x33, 0x32, 0x34, 0x31, 0x36, 0x5a, 0x30,
    0x81, 0x80, 0x30, 0x7e, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84,
    0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8,
    0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc,
    0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02,
    0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6,
    0x47, 0xa0, 0x7d, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47,
    0x00, 0x30, 0x44, 0x02, 0x20, 0x13, 0x1c, 0x3e, 0x80, 0x52, 0x62, 0x23, 0xf4, 0xbd, 0xde, 0x5d, 0x1c, 0x91,
    0x2f, 0x8b, 0x2e, 0xad, 0x0a, 0x32, 0x0e, 0x19, 0x5f, 0x38, 0xaa, 0xc2, 0x51, 0x73, 0x55, 0x2f, 0xc1, 0xd1,
    0x18, 0x02, 0x20, 0x0c, 0x5f, 0xf8, 0x0d, 0x7a, 0xa2, 0xc3, 0x22, 0x3e, 0x51, 0xf8, 0x6e, 0xb7, 0xca, 0xba,
    0x36, 0xf6, 0x9f, 0xe9, 0xf8, 0xdd, 0x99, 0xd4, 0x1f, 0xc1, 0xee, 0x56, 0xe8, 0x6c, 0x3a, 0x9f, 0x9f};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_respGoodByNameSha1Der[] = {
    0x30, 0x82, 0x02, 0xdd, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0xd6, 0x30, 0x82, 0x02, 0xd2, 0x06, 0x09, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0xc3, 0x30, 0x82, 0x02, 0xbf, 0x30, 0x81, 0xd2, 0xa1,
    0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x18, 0x0f, 0x32, 0x30,
    0x32, 0x36, 0x30, 0x39, 0x32, 0x32, 0x30, 0x33, 0x32, 0x34, 0x31, 0x36, 0x5a, 0x30, 0x77, 0x30, 0x75, 0x30, 0x4d,
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff,
    0xe6, 0x16, 0x8b, 0x75, 0xa0, 0x61, 0x38, 0xae, 0x4b, 0x93, 0x4c, 0x66, 0x3e, 0x82, 0x04, 0x14, 0x53, 0xc7, 0xfe,
    0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14,
    0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0,
    0x7d, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
    0x12, 0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21,
    0x00, 0xf7, 0xeb, 0x97, 0x1d, 0x6b, 0xf3, 0x99, 0xe5, 0x7f, 0x60, 0xb7, 0x06, 0x79, 0x77, 0x7a, 0x5d, 0x84, 0xb0,
    0xed, 0x03, 0x80, 0xb7, 0xd0, 0xe0, 0xc0, 0xe0, 0xb7, 0x67, 0xcf, 0xaf, 0xe1, 0x23, 0x02, 0x20, 0x34, 0xd8, 0x91,
    0xaa, 0x9c, 0x55, 0x13, 0x12, 0xe7, 0x1e, 0xa1, 0xb0, 0xa6, 0x67, 0xfc, 0x5f, 0x39, 0xf2, 0x76, 0x58, 0xad, 0xde,
    0xd3, 0x63, 0x32, 0x5f, 0x16, 0xc1, 0x33, 0xaa, 0x63, 0xa1, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30,
    0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e,
    0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31,
    0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
    0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45,
    0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d,
    0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad,
    0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3,
    0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b,
    0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9,
    0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
    0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4,
    0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02,
    0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac,
    0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_respRevokedByNameSha256Der[] = {
    0x30, 0x82, 0x03, 0x12, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x03, 0x0b, 0x30, 0x82, 0x03, 0x07, 0x06, 0x09, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0xf8, 0x30, 0x82, 0x02, 0xf4, 0x30, 0x82, 0x01, 0x06,
    0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50,
    0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x18, 0x0f, 0x32,
    0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x32, 0x30, 0x33, 0x32, 0x34, 0x31, 0x36, 0x5a, 0x30, 0x81, 0xaa, 0x30, 0x81,
    0xa7, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
    0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4,
    0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48,
    0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e,
    0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3,
    0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30,
    0x32, 0x36, 0x30, 0x39, 0x31, 0x39, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0x18,
    0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x11, 0x18,
    0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x23, 0x30,
    0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x99,
    0x88, 0x77, 0x66, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xe2, 0x0a, 0x56,
    0x31, 0xfb, 0xd1, 0x61, 0x5b, 0x99, 0x6d, 0x01, 0xd6, 0x64, 0x49, 0x35, 0x1a, 0xe2, 0xc8, 0xcf, 0x6e, 0xd7, 0xcc,
    0xab, 0x14, 0x0a, 0x11, 0x6d, 0xb4, 0xe6, 0x31, 0x60, 0x1a, 0x02, 0x20, 0x10, 0x64, 0x23, 0x8c, 0xb7, 0xd3, 0xdb,
    0x40, 0xea, 0x49, 0xcb, 0xc9, 0x85, 0x1e, 0x73, 0x90, 0x46, 0x56, 0x3f, 0x77, 0xa1, 0x4a, 0x95, 0x5e, 0x40, 0xe1,
    0x0a, 0x22, 0xcd, 0xaa, 0xa5, 0x13, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30, 0x82, 0x01, 0x88, 0x30,
    0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75,
    0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43,
    0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32,
    0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32,
    0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43,
    0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03,
    0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5,
    0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53,
    0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30,
    0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3,
    0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4,
    0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
    0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0, 0xc4,
    0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8,
    0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9, 0x48,
    0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55};

/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_eeDer[] = {
    0x30, 0x82, 0x01, 0x30, 0x30, 0x81, 0xd7, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a,
    0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53,
    0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e,
    0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36,
    0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x45, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xee, 0xc9, 0x44, 0x5a, 0xd6, 0x6c, 0x39, 0x17, 0x45, 0x90, 0x13, 0x40, 0x8c,
    0x0f, 0x37, 0xee, 0x8b, 0x96, 0x26, 0xc6, 0x74, 0xc0, 0x98, 0x01, 0xad, 0x8b, 0xa1, 0x8f, 0x9c, 0x27, 0x4f, 0x9c,
    0x8b, 0x3d, 0x9e, 0x5f, 0x72, 0x79, 0x86, 0x1d, 0xc8, 0x49, 0x6c, 0x49, 0x98, 0x4c, 0xf1, 0x93, 0x9b, 0x79, 0xa7,
    0xff, 0xd0, 0x37, 0xbd, 0x95, 0x7e, 0x88, 0xb0, 0x58, 0xd1, 0x0c, 0x1a, 0xf8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xe7, 0xff, 0x49, 0x7e, 0x91,
    0x10, 0x18, 0x54, 0x30, 0x55, 0xf4, 0x1e, 0xb4, 0x9c, 0x9e, 0x92, 0xf3, 0xf9, 0x67, 0xf1, 0x25, 0xab, 0xec, 0x75,
    0x61, 0xdd, 0x99, 0x74, 0x61, 0x94, 0x20, 0x16, 0x02, 0x20, 0x43, 0xc7, 0x25, 0x20, 0xba, 0x32, 0x31, 0xd6, 0xa4,
     0x71, 0x1c, 0x80, 0xd3, 0xf3, 0xae, 0xc7, 0x60, 0x1a, 0xbc, 0xfb, 0xb6, 0x29, 0x72, 0x3e, 0xf6, 0xbe, 0x6f, 0x66,
     0x36, 0x0a, 0xfe, 0x58};

/* This preset OCSP data was generated by another cryptographic library. */
/* This preset OCSP data was generated by another cryptographic library. */
static const uint8_t g_reqSignedSha256Der[] = {
    0x30, 0x82, 0x02, 0x92, 0x30, 0x81, 0x9d, 0xa1, 0x23, 0xa4, 0x21, 0x30,
    0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14,
    0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
    0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x51, 0x30, 0x4f,
    0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14, 0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff, 0xe6, 0x16, 0x8b,
    0x75, 0xa0, 0x61, 0x38, 0xae, 0x4b, 0x93, 0x4c, 0x66, 0x3e, 0x82, 0x04,
    0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60,
    0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14, 0x18,
    0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b,
    0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa2, 0x23, 0x30, 0x21, 0x30,
    0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02,
    0x04, 0x12, 0x04, 0x10, 0xd7, 0x10, 0x45, 0xbf, 0xdd, 0xee, 0x63, 0xdd,
    0x6b, 0x30, 0xd1, 0x0a, 0xf7, 0xf2, 0x24, 0xfb, 0xa0, 0x82, 0x01, 0xee,
    0x30, 0x82, 0x01, 0xea, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00,
    0xbb, 0x67, 0x2a, 0x02, 0xd1, 0x04, 0xac, 0xa9, 0xc7, 0x74, 0x0b, 0x90,
    0x61, 0xe2, 0x20, 0xe0, 0xa8, 0x67, 0xd2, 0xa5, 0x95, 0x38, 0x17, 0x2a,
    0x16, 0x0a, 0x3c, 0xb4, 0xcb, 0xb5, 0x98, 0x45, 0x02, 0x20, 0x16, 0xfd,
    0xf9, 0x09, 0xb5, 0xad, 0xfd, 0x0e, 0x7f, 0xc3, 0xe9, 0xa9, 0xf3, 0x95,
    0xe0, 0xe0, 0x64, 0x87, 0xbc, 0xa3, 0x95, 0xc8, 0xba, 0x37, 0xa1, 0xab,
    0xd6, 0x1c, 0x44, 0x44, 0xfa, 0xc9, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82,
    0x01, 0x8c, 0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03,
    0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9,
    0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1,
    0x54, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20,
    0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30,
    0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30,
    0x39, 0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f,
    0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f,
    0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64,
    0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc,
    0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6,
    0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11,
    0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3,
    0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53,
    0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc,
    0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d,
    0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66,
    0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3,
    0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94,
    0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4,
    0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0,
    0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d,
    0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe,
    0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60,
    0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4,
    0x8e, 0x55,
};

/* Subject: CN = *.openhitls.net. */
static const uint8_t g_certWithOcspUrlDer[] = {
    0x30, 0x82, 0x06, 0xad, 0x30, 0x82, 0x05, 0x95, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x10, 0x0a, 0x3d, 0x6f, 0xdb, 0x62, 0xc2, 0x81, 0xa3, 0xf1,
    0xe6, 0x0b, 0x18, 0x69, 0x20, 0xe5, 0x28, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x60,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c,
    0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63,
    0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77,
    0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e,
    0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x16, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x54,
    0x4c, 0x53, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x20, 0x47, 0x31,
    0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x32, 0x34, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x30, 0x32, 0x30,
    0x37, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x1a, 0x31, 0x18,
    0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x2a, 0x2e, 0x6f,
    0x70, 0x65, 0x6e, 0x68, 0x69, 0x74, 0x6c, 0x73, 0x2e, 0x6e, 0x65, 0x74,
    0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00,
    0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81, 0x00, 0x91, 0x92, 0xf1,
    0xf4, 0xdf, 0x20, 0x10, 0x25, 0xce, 0x35, 0x5d, 0x60, 0x96, 0x1d, 0xed,
    0xd5, 0xb7, 0x29, 0x9c, 0x4a, 0x4d, 0xd9, 0xcd, 0x49, 0xa7, 0x2c, 0xd3,
    0x02, 0x71, 0x17, 0x43, 0x22, 0x80, 0x63, 0x94, 0x3d, 0x29, 0xf9, 0xe4,
    0xf7, 0xe1, 0xc4, 0xce, 0x5f, 0x16, 0xfb, 0xe2, 0x40, 0x27, 0x8f, 0xcb,
    0xe5, 0x26, 0xe2, 0x88, 0x8c, 0xb4, 0x76, 0x70, 0xec, 0xb4, 0x91, 0xd9,
    0x1c, 0x02, 0x2e, 0x17, 0x4e, 0xc2, 0xe8, 0xfe, 0x1c, 0xa7, 0x2c, 0x13,
    0x03, 0x03, 0xcf, 0x7e, 0x05, 0xe0, 0x51, 0xe8, 0x6a, 0xae, 0x72, 0x28,
    0x2e, 0x41, 0xd7, 0xf5, 0x1a, 0x3c, 0x97, 0xd8, 0x14, 0x91, 0xa7, 0x54,
    0xa6, 0x26, 0xd8, 0xbb, 0x8d, 0xfd, 0x51, 0x0d, 0xac, 0x6c, 0x00, 0x4d,
    0x83, 0xf0, 0xee, 0x4a, 0x8f, 0x37, 0xb2, 0x6a, 0xed, 0xaf, 0xb2, 0xcf,
    0x6f, 0x4b, 0xa1, 0xa3, 0xca, 0x19, 0x77, 0xcc, 0x6c, 0xdd, 0x04, 0xa5,
    0x80, 0x93, 0x5d, 0xc4, 0x80, 0x85, 0xfc, 0x94, 0x8b, 0x1c, 0x20, 0xaf,
    0x5c, 0xce, 0xeb, 0xb9, 0x32, 0xf0, 0xc2, 0x23, 0xb9, 0xd7, 0xdc, 0xa4,
    0x94, 0x84, 0x44, 0x4b, 0xdd, 0xe8, 0xf5, 0xc5, 0x85, 0x1c, 0x2d, 0xe7,
    0xf8, 0x63, 0xde, 0x46, 0xc9, 0xd3, 0x81, 0x39, 0xe7, 0x18, 0x33, 0x54,
    0x37, 0xed, 0x7c, 0x15, 0xea, 0x85, 0x16, 0xf7, 0x7a, 0x24, 0x38, 0x13,
    0x8f, 0xc7, 0x02, 0x81, 0xfc, 0x9a, 0x93, 0x62, 0x9b, 0xd0, 0x8a, 0x2a,
    0xbf, 0xb9, 0x71, 0x4e, 0x58, 0x9e, 0x94, 0xa1, 0xf7, 0x7c, 0xf9, 0x1e,
    0x48, 0x36, 0xaa, 0x30, 0xec, 0x40, 0x09, 0x5d, 0x49, 0x8d, 0x6e, 0x85,
    0x3f, 0xfa, 0xb2, 0x11, 0x3e, 0x86, 0x8a, 0x0b, 0x02, 0x8b, 0xfe, 0xec,
    0x5a, 0x73, 0xe4, 0xf4, 0xab, 0xb5, 0x2d, 0x93, 0xca, 0x24, 0x1f, 0x14,
    0x8e, 0x1f, 0x86, 0x81, 0x6f, 0xa0, 0x8c, 0x33, 0xee, 0x0d, 0xdd, 0x21,
    0x41, 0xdc, 0x82, 0x69, 0x59, 0x0b, 0x8f, 0xb6, 0x0f, 0x04, 0x04, 0xdc,
    0x98, 0xf3, 0xce, 0x5c, 0x5d, 0x68, 0xcb, 0x7d, 0x2c, 0x59, 0x2b, 0x08,
    0x2d, 0x19, 0x32, 0x64, 0x1e, 0xb0, 0x71, 0xeb, 0x5f, 0x64, 0xd2, 0xcc,
    0x86, 0xb7, 0xbe, 0x6f, 0xc6, 0x98, 0x25, 0x16, 0xef, 0x2a, 0x91, 0xfd,
    0x0c, 0xa8, 0x0d, 0xc5, 0xcf, 0x98, 0x06, 0x5b, 0x44, 0x7e, 0xbf, 0xa1,
    0xbf, 0xae, 0xd6, 0xa0, 0xf4, 0x65, 0xcb, 0x88, 0xcc, 0x71, 0x33, 0xe2,
    0xbe, 0xd0, 0x89, 0x07, 0x6e, 0xcd, 0x49, 0xf6, 0xbf, 0x7c, 0xab, 0x77,
    0xcb, 0x16, 0x59, 0x99, 0x9c, 0x04, 0x86, 0x4f, 0x00, 0x52, 0xb0, 0x79,
    0xb1, 0x7d, 0xa8, 0xb7, 0xa1, 0x82, 0x1a, 0xa7, 0xd5, 0x08, 0x60, 0x83,
    0x87, 0xe4, 0x09, 0x72, 0xab, 0x3f, 0xb2, 0x8c, 0x5b, 0x02, 0x03, 0x01,
    0x00, 0x01, 0xa3, 0x82, 0x03, 0x27, 0x30, 0x82, 0x03, 0x23, 0x30, 0x1f,
    0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x94,
    0x4f, 0xd4, 0x5d, 0x8b, 0xe4, 0xa4, 0xe2, 0xa6, 0x80, 0xfe, 0xfd, 0xd8,
    0xf9, 0x00, 0xef, 0xa3, 0xbe, 0x02, 0x57, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xcc, 0x3e, 0x89, 0x90, 0xdb, 0x75,
    0xbf, 0x53, 0x28, 0x84, 0x3d, 0x56, 0xf4, 0x6c, 0xb4, 0x32, 0x9e, 0x44,
    0xb1, 0x6e, 0x30, 0x29, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x22, 0x30,
    0x20, 0x82, 0x0f, 0x2a, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x68, 0x69, 0x74,
    0x6c, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x82, 0x0d, 0x6f, 0x70, 0x65, 0x6e,
    0x68, 0x69, 0x74, 0x6c, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x3e, 0x06,
    0x03, 0x55, 0x1d, 0x20, 0x04, 0x37, 0x30, 0x35, 0x30, 0x33, 0x06, 0x06,
    0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30, 0x29, 0x30, 0x27, 0x06, 0x08,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1b, 0x68, 0x74,
    0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67,
    0x69, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x50,
    0x53, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
    0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25,
    0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    0x30, 0x3f, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x38, 0x30, 0x36, 0x30,
    0x34, 0xa0, 0x32, 0xa0, 0x30, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a,
    0x2f, 0x2f, 0x63, 0x64, 0x70, 0x2e, 0x67, 0x65, 0x6f, 0x74, 0x72, 0x75,
    0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x65, 0x6f, 0x54, 0x72,
    0x75, 0x73, 0x74, 0x54, 0x4c, 0x53, 0x52, 0x53, 0x41, 0x43, 0x41, 0x47,
    0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x76, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x6a, 0x30, 0x68, 0x30, 0x26, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x1a, 0x68,
    0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
    0x2e, 0x67, 0x65, 0x6f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x3e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x02, 0x86, 0x32, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x61,
    0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x67, 0x65, 0x6f, 0x74, 0x72, 0x75,
    0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x65, 0x6f, 0x54, 0x72,
    0x75, 0x73, 0x74, 0x54, 0x4c, 0x53, 0x52, 0x53, 0x41, 0x43, 0x41, 0x47,
    0x31, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13,
    0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x82, 0x01, 0x7e, 0x06,
    0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02, 0x04,
    0x82, 0x01, 0x6e, 0x04, 0x82, 0x01, 0x6a, 0x01, 0x68, 0x00, 0x77, 0x00,
    0x4c, 0x63, 0xdc, 0x98, 0xe5, 0x9c, 0x1d, 0xab, 0x88, 0xf6, 0x1e, 0x8a,
    0x3d, 0xde, 0xae, 0x8f, 0xab, 0x44, 0xa3, 0x37, 0x7b, 0x5f, 0x9b, 0x94,
    0xc3, 0xfb, 0xa1, 0x9c, 0xfc, 0xc1, 0xbe, 0x26, 0x00, 0x00, 0x01, 0x9f,
    0x91, 0xe4, 0x84, 0x53, 0x00, 0x00, 0x04, 0x03, 0x00, 0x48, 0x30, 0x46,
    0x02, 0x21, 0x00, 0xbc, 0x34, 0x71, 0xf2, 0x65, 0x02, 0xf6, 0x66, 0xe2,
    0x8c, 0x4a, 0x53, 0x4f, 0x32, 0x27, 0x78, 0x30, 0x37, 0xca, 0x5a, 0xc7,
    0xb9, 0xab, 0xde, 0x5e, 0x98, 0xd3, 0x34, 0x03, 0x65, 0xb1, 0xc1, 0x02,
    0x21, 0x00, 0xb6, 0x8f, 0x09, 0x14, 0x94, 0xfc, 0x38, 0x1f, 0x2b, 0xf9,
    0xad, 0xa1, 0x5a, 0x18, 0xa8, 0x9e, 0x4d, 0x15, 0x35, 0x65, 0xe5, 0xe6,
    0x05, 0xd9, 0xad, 0x0b, 0xf2, 0xae, 0x49, 0xac, 0xab, 0x51, 0x00, 0x75,
    0x00, 0xd6, 0xd5, 0x8d, 0xa9, 0xd0, 0x17, 0x53, 0xf3, 0x6a, 0x4a, 0xa0,
    0xc7, 0x57, 0x49, 0x02, 0xaf, 0xeb, 0xc7, 0xdc, 0x2c, 0xd3, 0x8c, 0xd9,
    0xf7, 0x64, 0xc8, 0x0c, 0x89, 0x19, 0x1e, 0x9f, 0x02, 0x00, 0x00, 0x01,
    0x9f, 0x91, 0xe4, 0x84, 0x6f, 0x00, 0x00, 0x04, 0x03, 0x00, 0x46, 0x30,
    0x44, 0x02, 0x20, 0x1b, 0x5d, 0x4b, 0x58, 0x07, 0x15, 0x8c, 0x5e, 0x15,
    0xc8, 0x34, 0xb7, 0xbd, 0x61, 0xf8, 0x4a, 0xce, 0xac, 0x89, 0x6b, 0xba,
    0xfd, 0x6e, 0x66, 0x0c, 0x21, 0x8e, 0x6e, 0x68, 0x98, 0xdc, 0x98, 0x02,
    0x20, 0x75, 0x5d, 0x17, 0xb4, 0x2e, 0x5d, 0x4b, 0x7d, 0x40, 0x3e, 0xf4,
    0x5d, 0xe9, 0x60, 0xd1, 0x28, 0x03, 0xc2, 0xd2, 0x7c, 0x50, 0xbf, 0x6c,
    0x68, 0xdc, 0xc9, 0xb2, 0xdb, 0x9e, 0xf1, 0x79, 0xfd, 0x00, 0x76, 0x00,
    0x44, 0xc2, 0xbd, 0x0c, 0xe9, 0x14, 0x0e, 0x64, 0xa5, 0xc9, 0x4a, 0x01,
    0x93, 0x0a, 0x5a, 0xa1, 0xbb, 0x35, 0x97, 0x0e, 0x00, 0xee, 0x11, 0x16,
    0x89, 0x68, 0x2a, 0x1c, 0x44, 0xd7, 0xb5, 0x66, 0x00, 0x00, 0x01, 0x9f,
    0x91, 0xe4, 0x84, 0x8c, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45,
    0x02, 0x20, 0x49, 0x15, 0x11, 0x89, 0xea, 0xa7, 0x14, 0xf9, 0x0c, 0x46,
    0x37, 0x42, 0xee, 0x6e, 0xcb, 0xb0, 0x1a, 0x8f, 0xe4, 0x11, 0x0e, 0x53,
    0x50, 0x6c, 0xaa, 0x7c, 0x0c, 0xd2, 0x14, 0x85, 0x4e, 0xd8, 0x02, 0x21,
    0x00, 0x9a, 0xb5, 0x1a, 0x04, 0x8b, 0xa3, 0x69, 0x4c, 0xdb, 0x10, 0xcd,
    0xcf, 0xc0, 0x07, 0x84, 0xa3, 0x72, 0x90, 0x69, 0x1c, 0xbe, 0x03, 0xa3,
    0x3d, 0xfa, 0x7b, 0xbe, 0x51, 0xe2, 0x9d, 0x59, 0x44, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x86, 0xc8, 0xf6, 0xb0, 0x3d, 0xf1, 0xbe,
    0x61, 0xc3, 0xf1, 0x1a, 0x6c, 0xee, 0x16, 0xa2, 0x07, 0x2f, 0x1d, 0x2a,
    0x8e, 0xb7, 0x0b, 0x1d, 0x7e, 0x61, 0xad, 0x3d, 0xca, 0xd0, 0x84, 0x6c,
    0xc3, 0xbf, 0x86, 0xc6, 0x36, 0x7d, 0xa9, 0xc0, 0x17, 0x1b, 0x8f, 0xf8,
    0xbb, 0xda, 0x6c, 0xe9, 0x63, 0x6f, 0x24, 0xdd, 0x88, 0x2e, 0x49, 0x2f,
    0x72, 0x9b, 0x51, 0xf9, 0xff, 0x08, 0x4b, 0xb0, 0x4c, 0x2e, 0x3f, 0x1e,
    0xad, 0xee, 0x90, 0x99, 0x9f, 0x73, 0x92, 0x9b, 0xaa, 0x96, 0xc2, 0xff,
    0xb2, 0x11, 0xfd, 0x3c, 0xf5, 0xd8, 0x65, 0x96, 0x77, 0x5f, 0x25, 0x3c,
    0x54, 0x9c, 0x21, 0x85, 0xc1, 0xd4, 0x9a, 0xd3, 0x0d, 0x2c, 0x84, 0x34,
    0x4f, 0x34, 0x57, 0x0c, 0x69, 0x45, 0x03, 0xc5, 0xfb, 0x15, 0x97, 0xab,
    0x13, 0xe8, 0x4d, 0xe4, 0x31, 0x6a, 0x20, 0x4c, 0x95, 0xbc, 0x20, 0xeb,
    0xfd, 0xd7, 0x81, 0x85, 0xa8, 0x5c, 0x67, 0xc1, 0xc4, 0xf1, 0x64, 0xec,
    0x07, 0x41, 0xbb, 0x47, 0x2a, 0x31, 0xe1, 0xf9, 0x8f, 0xb7, 0x59, 0x31,
    0xe7, 0xe1, 0xd8, 0x41, 0x84, 0x88, 0xfe, 0xe3, 0x00, 0xd9, 0x4c, 0x3b,
    0x2f, 0x0d, 0x7c, 0xd6, 0xc9, 0xa9, 0x0b, 0x97, 0x7e, 0xf5, 0xeb, 0x1b,
    0xdc, 0x3d, 0xc4, 0xa8, 0x59, 0xbf, 0x68, 0x62, 0x41, 0xa3, 0x14, 0x49,
    0x66, 0xa4, 0x1a, 0x56, 0xd0, 0xd9, 0x66, 0xea, 0x7e, 0x23, 0x27, 0x28,
    0x22, 0x71, 0x10, 0xea, 0xf5, 0x28, 0xd6, 0xa8, 0x7b, 0x77, 0x07, 0xc0,
    0x3a, 0x29, 0xd8, 0x77, 0xf5, 0x7e, 0xe4, 0x1c, 0xe3, 0x63, 0x12, 0x6a,
    0x11, 0x20, 0x89, 0xdd, 0x71, 0x14, 0x9f, 0x3d, 0x99, 0xfb, 0xbd, 0xa9,
    0xc5, 0xec, 0x69, 0x11, 0x34, 0xa8, 0x1a, 0x8c, 0xf5, 0x7d, 0x1c, 0xc7,
    0x26, 0x67, 0x8d, 0x57, 0x36, 0xaa, 0xbd, 0x1d, 0x88,
};

/* ============================================================================
 * End-to-End Test Case 1: Single cert request -> response
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_E2E_SINGLE_TC001(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reDer = {0};
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *singleResp = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_SingleReq *singleReq = NULL;
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Step 1: Create OCSP request with 1 cert */
    certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    singleReq = HITLS_OCSP_SingleReqNew(certId);
    ASSERT_TRUE(singleReq != NULL);
    certId = NULL; // ownership transferred
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)singleReq, sizeof(singleReq)),
              HITLS_PKI_SUCCESS);
    singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, NULL, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);

    /* Step 2: Parse request, get cert info */
    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedReq != NULL);

    uint32_t reqCount = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(parsedReq, &reqCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reqCount, 1);

    HITLS_OCSP_SingleReq *parsedSingleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(parsedReq, 0, &parsedSingleReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedSingleReq != NULL);

    HITLS_OCSP_CertId *parsedCertId = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(parsedSingleReq, &parsedCertId), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedCertId != NULL);

    /* Step 3: Create OCSP response based on request cert info, echo request nonce */
    BSL_Buffer reqNonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(parsedReq, HITLS_OCSP_REQ_GET_NONCE, &reqNonce, sizeof(reqNonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqNonce.data != NULL);
    ASSERT_TRUE(reqNonce.dataLen > 0);

    singleResp = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[1] = {singleResp};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, &reqNonce);
    ASSERT_TRUE(bs != NULL);
    singleResp = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);

    /* Step 4: Parse OCSP response, get cert status */
    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedResp != NULL);

    int32_t respStatus = 0;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_STATUS, &respStatus, sizeof(respStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(respStatus, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedBs != NULL);

    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(parsedBs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);

    HITLS_OCSP_SingleResp *parsedSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedSr != NULL);

    HITLS_OCSP_CertStatus certStatus = 0;
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_GOOD);

    // Verify response echoes the request nonce
    BSL_Buffer respNonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(parsedBs, HITLS_OCSP_BASICRESP_GET_NONCE, &respNonce, sizeof(respNonce)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(respNonce.dataLen, reqNonce.dataLen);
    ASSERT_EQ(memcmp(respNonce.data, reqNonce.data, reqNonce.dataLen), 0);

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, 0), HITLS_PKI_SUCCESS);

    // Check nonce consistency between request and response
    HITLS_OCSP_NonceStatus nonceStatus = 0;
    ASSERT_EQ(HITLS_OCSP_CheckNonce(req, parsedBs, &nonceStatus), HITLS_PKI_SUCCESS);
    ASSERT_EQ(nonceStatus, HITLS_OCSP_NONCE_EQUAL);

    // Check validity of the SingleResponse (allow 300s drift, 1 hour maxage)
    ASSERT_EQ(HITLS_OCSP_CheckValidity(parsedSr, 300, 3600), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on request and response objects (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);

    // Round-trip verify
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, parsedResp, &reDer), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reDer.dataLen, respDer.dataLen);
    ASSERT_EQ(memcmp(reDer.data, respDer.data, respDer.dataLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_SingleRespFree(singleResp);
    BSL_SAL_Free(reDer.data);
    HITLS_OCSP_SingleReqFree(singleReq);
    BSL_SAL_Free(respDer.data);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_CertIdFree(certId);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * End-to-End Test Case 2: Multi cert request -> response
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_E2E_MULTI_TC002(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *resp2 = NULL;
    HITLS_OCSP_SingleResp *resp1 = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_SingleReq *sr2 = NULL;
    HITLS_OCSP_CertId *certId2 = NULL;
    HITLS_OCSP_SingleReq *sr1 = NULL;
    HITLS_OCSP_CertId *certId1 = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Step 1: Create OCSP request with 2 certs */
    certId1 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId1 != NULL);
    sr1 = HITLS_OCSP_SingleReqNew(certId1);
    ASSERT_TRUE(sr1 != NULL);
    certId1 = NULL;

    certId2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain2.ee, g_chain2.intermediate);
    ASSERT_TRUE(certId2 != NULL);
    sr2 = HITLS_OCSP_SingleReqNew(certId2);
    ASSERT_TRUE(sr2 != NULL);
    certId2 = NULL;

    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr1, sizeof(sr1)), HITLS_PKI_SUCCESS);
    sr1 = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr2, sizeof(sr2)), HITLS_PKI_SUCCESS);
    sr2 = NULL;

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);

    /* Step 2: Parse request */
    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq), HITLS_PKI_SUCCESS);
    BSL_SAL_Free(reqDer.data);
    reqDer.data = NULL;

    uint32_t reqCount = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(parsedReq, &reqCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reqCount, 2);

    /* Step 3: Create response with 2 SingleResponses */
    resp1 = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(resp1 != NULL);
    resp2 = OcspTestCreateSingleResp(g_mdCtx, g_chain2.ee, g_chain2.intermediate, HITLS_OCSP_CERT_STATUS_REVOKED);
    ASSERT_TRUE(resp2 != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[2] = {resp1, resp2};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 2, NULL);
    ASSERT_TRUE(bs != NULL);
    resp1 = NULL;
    resp2 = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    /* Step 4: Parse response, verify both cert statuses */
    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    BSL_SAL_Free(respDer.data);
    respDer.data = NULL;

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);

    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(parsedBs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 2);

    // First: GOOD
    HITLS_OCSP_SingleResp *parsedSr0 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr0), HITLS_PKI_SUCCESS);
    HITLS_OCSP_CertStatus status0 = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr0, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &status0, sizeof(status0)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(status0, HITLS_OCSP_CERT_STATUS_GOOD);

    // Second: REVOKED
    HITLS_OCSP_SingleResp *parsedSr1 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 1, &parsedSr1), HITLS_PKI_SUCCESS);
    HITLS_OCSP_CertStatus status1 = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr1, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &status1, sizeof(status1)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(status1, HITLS_OCSP_CERT_STATUS_REVOKED);

    // Check revoked info
    BSL_TIME revokeTime = {0};
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr1, HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME, &revokeTime,
                                        sizeof(revokeTime)),
              HITLS_PKI_SUCCESS);
    int32_t revokeReason = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr1, HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON, &revokeReason,
                                        sizeof(revokeReason)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(revokeReason, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(respDer.data);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_SingleRespFree(resp1);
    HITLS_OCSP_SingleRespFree(resp2);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_SingleReqFree(sr1);
    HITLS_OCSP_CertIdFree(certId1);
    HITLS_OCSP_SingleReqFree(sr2);
    HITLS_OCSP_CertIdFree(certId2);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * Single encode/decode tests
 * ============================================================================ */

/* BEGIN_CASE */
void SDV_OCSP_RESP_REVOKED_TC003(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_REVOKED);
    ASSERT_TRUE(sr != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    // Parse and verify revoked status
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);

    HITLS_OCSP_SingleResp *parsedSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);

    HITLS_OCSP_CertStatus status = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &status, sizeof(status)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_CERT_STATUS_REVOKED);

    BSL_TIME revokeTime = {0};
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_REVOCATION_TIME, &revokeTime, sizeof(revokeTime)),
        HITLS_PKI_SUCCESS);

    int32_t reason = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON, &reason, sizeof(reason)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(reason, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleRespFree(sr);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RESP_UNKNOWN_TC004(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_UNKNOWN);
    ASSERT_TRUE(sr != NULL);

    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);

    HITLS_OCSP_SingleResp *parsedSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);

    HITLS_OCSP_CertStatus status = 0;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &status, sizeof(status)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_CERT_STATUS_UNKNOWN);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleRespFree(sr);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RESP_NOCERTS_TC005(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reDer = {0};
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    HITLS_OCSP_SingleResp *sr =
        OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    // Sign with NOCERTS flag
    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    HITLS_OCSP_BasicResp *bs =
        OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    // Parse and verify round-trip
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, parsedResp, &reDer), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reDer.dataLen, respDer.dataLen);
    ASSERT_EQ(memcmp(reDer.data, respDer.data, respDer.dataLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reDer.data);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */
/* BEGIN_CASE */
void SDV_OCSP_RESP_WITHCERTS_TC006(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reDer = {0};
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    // Include certs in response
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);
    BSL_LIST_AddElement(certs, g_chain1.root, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    // Parse and verify round-trip
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, parsedResp, &reDer), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reDer.dataLen, respDer.dataLen);
    ASSERT_EQ(memcmp(reDer.data, respDer.data, respDer.dataLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reDer.data);
    HITLS_OCSP_SingleRespFree(sr);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * Abnormal / boundary API tests
 * ============================================================================ */

/* BEGIN_CASE */
void SDV_OCSP_NULL_PARAM_TC007(void)
{
#ifdef HITLS_PKI_OCSP
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Null pointer checks
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, NULL, NULL), HITLS_OCSP_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, NULL, NULL), HITLS_OCSP_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, NULL, NULL), HITLS_OCSP_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, NULL, NULL), HITLS_OCSP_ERR_NULL_POINTER);
    HITLS_OCSP_BasicResp *freshBs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(freshBs != NULL);
    HITLS_OCSP_BasicRespFree(freshBs);
    ASSERT_TRUE(HITLS_OCSP_SingleRespNew(NULL, HITLS_OCSP_CERT_STATUS_GOOD, &(BSL_TIME){0}) == NULL);
    ASSERT_TRUE(HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, NULL) == NULL);
    ASSERT_TRUE(HITLS_OCSP_RespNew(99, NULL) == NULL);

EXIT:;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_INVALID_STATUS_TC008(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Invalid resp status
    ASSERT_TRUE(HITLS_OCSP_RespNew(-1, NULL) == NULL);
    ASSERT_TRUE(HITLS_OCSP_RespNew(7, NULL) == NULL);

    // Non-successful with basicResp should fail
    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    // Non-successful status with basicResp
    ASSERT_TRUE(HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST, bs) == NULL);

    // Create non-successful response (no basicResp)
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR, NULL);
    ASSERT_TRUE(resp != NULL);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    // Parse non-successful response
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    int32_t status = 0;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR);

    // GET_BASIC should fail for non-successful
    HITLS_OCSP_BasicResp *getBs = NULL;
    ASSERT_NE(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &getBs, sizeof(&getBs)), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleRespFree(sr);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_REQ_EMPTY_TC009(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Empty request (no SingleReq added)
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);

    BSL_Buffer reqDer = {0};
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_OCSP_ERR_EMPTY_REQUEST);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
    ;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC014: CheckNonce boundary cases
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_CHECK_NONCE_TC014(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_BasicResp *bsWithNonce = NULL;
    HITLS_OCSP_Req *reqWithNonce = NULL;
    HITLS_OCSP_SingleReq *sr2 = NULL;
    HITLS_OCSP_CertId *certId2 = NULL;
    HITLS_OCSP_BasicResp *bsNoNonce = NULL;
    HITLS_OCSP_Req *reqNoNonce = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Case 1: Both absent
    certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    sr = HITLS_OCSP_SingleReqNew(certId);
    certId = NULL;
    ASSERT_TRUE(sr != NULL);
    reqNoNonce = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(reqNoNonce != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(reqNoNonce, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;

    HITLS_OCSP_SingleResp *singleResp =
        OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp != NULL);
    HITLS_OCSP_SingleResp *srArr[1] = {singleResp};
    bsNoNonce = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bsNoNonce != NULL);
    singleResp = NULL;

    HITLS_OCSP_NonceStatus status = 0;
    ASSERT_EQ(HITLS_OCSP_CheckNonce(reqNoNonce, bsNoNonce, &status), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_NONCE_BOTH_ABSENT);

    // Case 2: Request only
    certId2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId2 != NULL);
    sr2 = HITLS_OCSP_SingleReqNew(certId2);
    certId2 = NULL;
    ASSERT_TRUE(sr2 != NULL);
    reqWithNonce = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(reqWithNonce != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(reqWithNonce, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr2, sizeof(sr2)),
              HITLS_PKI_SUCCESS);
    sr2 = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(reqWithNonce, HITLS_OCSP_REQ_SET_NONCE, NULL, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_CheckNonce(reqWithNonce, bsNoNonce, &status), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_NONCE_REQ_ONLY);

    // Case 3: Response only (abnormal)
    uint8_t respNonceData[] = {0x01, 0x02, 0x03, 0x04};
    BSL_Buffer respNonceBuf = {respNonceData, sizeof(respNonceData)};
    HITLS_OCSP_SingleResp *singleResp3 =
        OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp3 != NULL);
    HITLS_OCSP_SingleResp *srArr3[1] = {singleResp3};
    bsWithNonce = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr3, 1, &respNonceBuf);
    ASSERT_TRUE(bsWithNonce != NULL);
    singleResp3 = NULL;

    ASSERT_EQ(HITLS_OCSP_CheckNonce(reqNoNonce, bsWithNonce, &status), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_NONCE_RESP_ONLY);

    // Case 4: Mismatched nonces
    uint8_t reqNonceData[] = {0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(reqWithNonce, HITLS_OCSP_REQ_SET_NONCE, reqNonceData, sizeof(reqNonceData)),
              HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_CheckNonce(reqWithNonce, bsWithNonce, &status), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_NONCE_NOT_EQUAL);

    // Case 5: NULL status output
    ASSERT_EQ(HITLS_OCSP_CheckNonce(reqWithNonce, bsWithNonce, NULL), HITLS_OCSP_ERR_NULL_POINTER);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(reqNoNonce), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(reqWithNonce), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_BasicRespFree(bsWithNonce);
    HITLS_OCSP_SingleReqFree(sr);
    HITLS_OCSP_BasicRespFree(bsNoNonce);
    HITLS_OCSP_SingleReqFree(sr2);
    HITLS_OCSP_ReqFree(reqWithNonce);
    HITLS_OCSP_ReqFree(reqNoNonce);
    HITLS_OCSP_CertIdFree(certId);
    HITLS_OCSP_CertIdFree(certId2);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC015: CheckValidity boundary cases
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_CHECK_VALIDITY_TC015(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    // Valid: current time, generous limits
    ASSERT_EQ(HITLS_OCSP_CheckValidity(sr, 300, 3600), HITLS_PKI_SUCCESS);

    // maxage = 0 disables the maxage check (drift = 0 also passes for thisUpdate == now)
    ASSERT_EQ(HITLS_OCSP_CheckValidity(sr, 0, 0), HITLS_PKI_SUCCESS);

    // Stale response: thisUpdate well in the past. With maxage = 0 the maxage check is
    // disabled, so it passes; with a positive maxage it must be rejected.
    HITLS_OCSP_CertId *oldCid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(oldCid != NULL);
    BSL_TIME oldTime = {0};
    BSL_SAL_SysTimeGet(&oldTime);
    oldTime.year -= 1;
    HITLS_OCSP_SingleResp *staleSr = HITLS_OCSP_SingleRespNew(oldCid, HITLS_OCSP_CERT_STATUS_GOOD, &oldTime);
    ASSERT_TRUE(staleSr != NULL);
    ASSERT_EQ(HITLS_OCSP_CheckValidity(staleSr, 0, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_OCSP_CheckValidity(staleSr, 300, 3600), HITLS_PKI_SUCCESS);
    HITLS_OCSP_SingleRespFree(staleSr);

    // Too far in future: drift = -1 (thisUpdate > now - 1)
    ASSERT_NE(HITLS_OCSP_CheckValidity(sr, -1, -1), HITLS_PKI_SUCCESS);

    // NULL single response
    ASSERT_EQ(HITLS_OCSP_CheckValidity(NULL, 300, 3600), HITLS_OCSP_ERR_NULL_POINTER);

EXIT:
    HITLS_OCSP_SingleRespFree(sr);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC016: BasicRespVerify abnormal cases
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_VERIFY_ABNORMAL_TC016(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_BasicResp *unsignedBs = NULL;
    HITLS_OCSP_BasicResp *bs2 = NULL;
    HITLS_OCSP_SingleResp *sr2 = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedBs != NULL);

    // Case 1: NULL bs
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(NULL, certs, NULL, 0), HITLS_OCSP_ERR_NULL_POINTER);

    // Case 2: storeCtx NULL, flags=0 (should fail — chain verification needed but no store)
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, NULL, 0), HITLS_OCSP_ERR_NULL_POINTER);

    // Case 3: Invalid flags (unsupported bits)
    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, 0xFF), HITLS_OCSP_ERR_INVALID_PARAM);

    // Case 4: Wrong certs (empty list) — signer not found
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, HITLS_OCSP_VFY_NOINTERN),
              HITLS_OCSP_ERR_SIGNER_NOT_FOUND);

    // Case 5: Verify unsigned response
    sr2 = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr2 != NULL);
    HITLS_OCSP_SingleResp *srArr2[1] = {sr2};
    bs2 = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr2, 1, NULL);
    ASSERT_TRUE(bs2 != NULL);
    sr2 = NULL;
    // Manually mark as unsigned (HITLS_OCSP_BasicRespSign was called, so it is signed)
    // We test the not-signed path via a fresh BasicResp that hasn't been signed
    unsignedBs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(unsignedBs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(unsignedBs, certs, storeCtx, 0), HITLS_OCSP_ERR_NOT_SIGNED);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_SingleRespFree(sr);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleRespFree(sr2);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(unsignedBs);
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_BasicRespFree(bs2);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC017: Pre-built OCSP request/response DER — full fields
 *         Request: 1 certID + nonce
 *         Response: successful, 1 SingleResponse(good) + nonce + certs
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_FULL_TC017(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *singleResp = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Build request with nonce, encode to DER
    certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    sr = HITLS_OCSP_SingleReqNew(certId);
    certId = NULL;
    ASSERT_TRUE(sr != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;
    uint8_t nonceData[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, nonceData, sizeof(nonceData)), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);

    // Parse the DER back and verify fields
    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq), HITLS_PKI_SUCCESS);

    uint32_t reqCount = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(parsedReq, &reqCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reqCount, 1);

    BSL_Buffer parsedReqNonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(parsedReq, HITLS_OCSP_REQ_GET_NONCE, &parsedReqNonce, sizeof(parsedReqNonce)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedReqNonce.dataLen, sizeof(nonceData));
    ASSERT_EQ(memcmp(parsedReqNonce.data, nonceData, sizeof(nonceData)), 0);

    // Build response with nonce + certs
    singleResp = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);
    BSL_LIST_AddElement(certs, g_chain1.root, BSL_LIST_POS_END);

    BSL_Buffer reqNonce = {nonceData, sizeof(nonceData)};
    HITLS_OCSP_SingleResp *srArr[1] = {singleResp};
    HITLS_OCSP_BasicResp *bs =
        OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, &reqNonce);
    ASSERT_TRUE(bs != NULL);
    singleResp = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);

    // Parse response DER and verify all fields
    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    int32_t respStatus = 0;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_STATUS, &respStatus, sizeof(respStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(respStatus, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);

    // Verify nonce
    BSL_Buffer respNonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(parsedBs, HITLS_OCSP_BASICRESP_GET_NONCE, &respNonce, sizeof(respNonce)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(respNonce.dataLen, sizeof(nonceData));
    ASSERT_EQ(memcmp(respNonce.data, nonceData, sizeof(nonceData)), 0);

    // Verify cert status
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(parsedBs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);

    HITLS_OCSP_SingleResp *parsedSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);
    HITLS_OCSP_CertStatus certStatus = 0;
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_GOOD);

    // Verify signature + chain
    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Check nonce consistency
    HITLS_OCSP_NonceStatus nonceStatus = 0;
    ASSERT_EQ(HITLS_OCSP_CheckNonce(parsedReq, parsedBs, &nonceStatus), HITLS_PKI_SUCCESS);
    ASSERT_EQ(nonceStatus, HITLS_OCSP_NONCE_EQUAL);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_SingleRespFree(singleResp);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleReqFree(sr);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_CertIdFree(certId);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC018: Pre-built OCSP request/response DER — minimal fields
 *         Request: 1 certID, no nonce
 *         Response: successful, 1 SingleResponse(good), no certs, no nonce
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_MINIMAL_TC018(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reDer = {0};
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_SingleResp *singleResp = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Build minimal request (no nonce)
    certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    sr = HITLS_OCSP_SingleReqNew(certId);
    certId = NULL;
    ASSERT_TRUE(sr != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);

    // Parse back and verify no nonce
    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq), HITLS_PKI_SUCCESS);

    BSL_Buffer reqNonce = {0};
    int32_t nonceRet = HITLS_OCSP_ReqCtrl(parsedReq, HITLS_OCSP_REQ_GET_NONCE, &reqNonce, sizeof(reqNonce));
    ASSERT_TRUE(nonceRet != HITLS_PKI_SUCCESS || reqNonce.data == NULL);

    // Build minimal response (no certs, no nonce, good status)
    singleResp = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp != NULL);
    HITLS_OCSP_SingleResp *srArr[1] = {singleResp};
    HITLS_OCSP_BasicResp *bs =
        OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    singleResp = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    // Parse back and verify
    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);

    // No nonce in response
    BSL_Buffer respNonce = {0};
    nonceRet = HITLS_OCSP_BasicRespCtrl(parsedBs, HITLS_OCSP_BASICRESP_GET_NONCE, &respNonce, sizeof(respNonce));
    ASSERT_TRUE(nonceRet != HITLS_PKI_SUCCESS || respNonce.data == NULL);

    // Verify cert status
    HITLS_OCSP_SingleResp *parsedSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);
    HITLS_OCSP_CertStatus certStatus = 0;
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_GOOD);

    // Verify signature (with external certs, no storeCtx needed for TRUSTOTHER)
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, NULL, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // CheckNonce: both absent
    HITLS_OCSP_NonceStatus nonceStatus = 99;
    ASSERT_EQ(HITLS_OCSP_CheckNonce(parsedReq, parsedBs, &nonceStatus), HITLS_PKI_SUCCESS);
    ASSERT_EQ(nonceStatus, HITLS_OCSP_NONCE_BOTH_ABSENT);

    // Round-trip verify
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, parsedResp, &reDer), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reDer.dataLen, respDer.dataLen);
    ASSERT_EQ(memcmp(reDer.data, respDer.data, respDer.dataLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reDer.data);
    HITLS_OCSP_SingleRespFree(singleResp);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleReqFree(sr);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_CertIdFree(certId);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_INVALID_REVOCATION_REASON_TC010(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    HITLS_OCSP_CertId *certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    sr = HITLS_OCSP_SingleRespNew(certId, HITLS_OCSP_CERT_STATUS_REVOKED, &(BSL_TIME){0});
    certId = NULL;
    ASSERT_TRUE(sr != NULL);

    // Invalid reason values
    int32_t invalidReason = -1;
    ASSERT_NE(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &invalidReason,
                                        sizeof(invalidReason)),
              HITLS_PKI_SUCCESS);

    invalidReason = 7; // unused in RFC 5280
    ASSERT_NE(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &invalidReason,
                                        sizeof(invalidReason)),
              HITLS_PKI_SUCCESS);

    invalidReason = 11; // out of range
    ASSERT_NE(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &invalidReason,
                                        sizeof(invalidReason)),
              HITLS_PKI_SUCCESS);

    // Valid reason
    int32_t validReason = HITLS_X509_REVOKED_REASON_CA_COMPROMISE;
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &validReason, sizeof(validReason)),
        HITLS_PKI_SUCCESS);

EXIT:
    HITLS_OCSP_SingleRespFree(sr);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RESP_SIGN_VERIFY_TC011(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    HITLS_X509_Cert *signer = NULL;
    HITLS_X509_Cert *signer2 = NULL;
    HITLS_X509_Cert *signerDup = NULL;
    HITLS_X509_List *signerCerts = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END);

    HITLS_OCSP_SingleResp *srArr[1] = {sr};
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, certs, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    sr = NULL;

    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(&parsedBs)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedBs != NULL);

    // Verify signature with correct certs and storeCtx
    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, 0), HITLS_PKI_SUCCESS);

    // Verify with NOINTERN (should still succeed since signer is in external certs)
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, HITLS_OCSP_VFY_NOINTERN), HITLS_PKI_SUCCESS);

    // Verify with TRUSTOTHER (signer is external, skip chain verification)
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Get signer: the returned cert is reference-counted and owned by the caller.
    // signerCerts holds a duplicate that the list owns, so once the list is released the only
    // thing keeping the returned certificate alive is the reference taken by GetSigner.
    ASSERT_EQ(HITLS_OCSP_BasicRespGetSigner(parsedBs, certs, &signer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(signer != NULL);
    signerCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(signerCerts != NULL);
    signerDup = HITLS_X509_CertDup(g_chain1.intermediate);
    ASSERT_TRUE(signerDup != NULL);
    BSL_LIST_AddElement(signerCerts, signerDup, BSL_LIST_POS_END);
    signerDup = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetSigner(parsedBs, signerCerts, &signer2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(signer2 != NULL);
    // signer is the element of the external list, now holding a reference of its own.
    ASSERT_TRUE(signer == g_chain1.intermediate);
    // signer2 is the duplicate owned by signerCerts.
    ASSERT_TRUE(signer2 != signer);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);

    // Release every other reference: the caller-held references must keep the certs alive.
    BSL_LIST_FREE(signerCerts, FreeCertListData);
    signerCerts = NULL;
    BSL_LIST_FREE(certs, FreeListData);
    certs = NULL;
    HITLS_OCSP_RespFree(parsedResp);
    parsedResp = NULL;
    BSL_SAL_Free(respDer.data);
    respDer.data = NULL;

    // Both certs are still usable after the response and the cert lists are gone, and they
    // are equivalent certificates.
    uint8_t signerMd[32] = {0};
    uint8_t signer2Md[32] = {0};
    uint32_t mdLen = sizeof(signerMd);
    ASSERT_EQ(HITLS_X509_CertDigest(signer, CRYPT_MD_SHA256, signerMd, &mdLen), HITLS_PKI_SUCCESS);
    ASSERT_EQ(mdLen, sizeof(signerMd));
    mdLen = sizeof(signer2Md);
    ASSERT_EQ(HITLS_X509_CertDigest(signer2, CRYPT_MD_SHA256, signer2Md, &mdLen), HITLS_PKI_SUCCESS);
    ASSERT_EQ(mdLen, sizeof(signer2Md));
    ASSERT_TRUE(memcmp(signerMd, signer2Md, sizeof(signerMd)) == 0);
EXIT:
    HITLS_X509_CertFree(signer);
    HITLS_X509_CertFree(signer2);
    HITLS_X509_CertFree(signerDup);
    BSL_LIST_FREE(signerCerts, FreeCertListData);
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_SingleRespFree(sr);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_BasicRespFree(bs);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_NONCE_TC012(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reDer = {0};
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Create request with nonce
    HITLS_OCSP_CertId *certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    sr = HITLS_OCSP_SingleReqNew(certId);
    certId = NULL;
    ASSERT_TRUE(sr != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;

    // Set nonce
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, NULL, 0), HITLS_PKI_SUCCESS);

    // Get nonce
    BSL_Buffer reqNonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &reqNonce, sizeof(reqNonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqNonce.data != NULL);
    ASSERT_TRUE(reqNonce.dataLen > 0);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);

    // Parse and verify nonce round-trip
    BSL_Buffer parseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedReq), HITLS_PKI_SUCCESS);

    BSL_Buffer parsedNonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(parsedReq, HITLS_OCSP_REQ_GET_NONCE, &parsedNonce, sizeof(parsedNonce)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedNonce.dataLen, reqNonce.dataLen);
    ASSERT_EQ(memcmp(parsedNonce.data, reqNonce.data, reqNonce.dataLen), 0);

    // Round-trip
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, parsedReq, &reDer), HITLS_PKI_SUCCESS);
    ASSERT_EQ(reDer.dataLen, reqDer.dataLen);
    ASSERT_EQ(memcmp(reDer.data, reqDer.data, reqDer.dataLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reDer.data);
    HITLS_OCSP_SingleReqFree(sr);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RESP_NON_SUCCESSFUL_TC013(void)
{
#ifdef HITLS_PKI_OCSP
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    // Test all non-successful statuses
    int32_t statuses[] = {HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST, HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR,
                          HITLS_OCSP_RESP_STATUS_TRY_LATER, HITLS_OCSP_RESP_STATUS_SIG_REQUIRED,
                          HITLS_OCSP_RESP_STATUS_UNAUTHORIZED};

    for (uint32_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
        HITLS_OCSP_Resp *resp = HITLS_OCSP_RespNew(statuses[i], NULL);
        ASSERT_TRUE(resp != NULL);

        BSL_Buffer respDer = {0};
        ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

        HITLS_OCSP_Resp *parsedResp = NULL;
        BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
        ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);

        int32_t parsedStatus = 0;
        ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_STATUS, &parsedStatus, sizeof(parsedStatus)),
                  HITLS_PKI_SUCCESS);
        ASSERT_EQ(parsedStatus, statuses[i]);

        // Exercise the print APIs on the created response (no terminal output).
        ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
        ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);

        BSL_SAL_Free(respDer.data);
        HITLS_OCSP_RespFree(parsedResp);
        HITLS_OCSP_RespFree(resp);
    }

    /* RFC 6960 reserves status value 4; RespNew must reject it. */
    ASSERT_EQ(HITLS_OCSP_RespNew(4, NULL), NULL);
EXIT:;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC019: Pre-generated OCSP request DER (full fields + nonce)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_REQ_FULL_TC019(void)
{
#ifdef HITLS_PKI_OCSP
    static const uint8_t reqFullDer[] = {
        0x30, 0x7a, 0x30, 0x78, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
        0x1a, 0x05, 0x00, 0x04, 0x14, 0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff, 0xe6, 0x16, 0x8b, 0x75, 0xa0, 0x61, 0x38,
        0xae, 0x4b, 0x93, 0x4c, 0x66, 0x3e, 0x82, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5,
        0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97,
        0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa2, 0x23, 0x30,
        0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10,
        0xa4, 0xcd, 0xa8, 0x13, 0x35, 0x74, 0x23, 0x89, 0x2a, 0xcf, 0xfe, 0x8f, 0xb1, 0x0c, 0xfc, 0xb8};
    BSL_Buffer buf = {(uint8_t *)reqFullDer, sizeof(reqFullDer)};
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &buf, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    uint32_t count = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(req, &count), HITLS_PKI_SUCCESS);
    ASSERT_EQ(count, 1);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    static const uint8_t expectedNonce[] = {0xa4, 0xcd, 0xa8, 0x13, 0x35, 0x74, 0x23, 0x89,
                                            0x2a, 0xcf, 0xfe, 0x8f, 0xb1, 0x0c, 0xfc, 0xb8};
    ASSERT_EQ(nonce.dataLen, sizeof(expectedNonce));
    ASSERT_EQ(memcmp(nonce.data, expectedNonce, sizeof(expectedNonce)), 0);
    HITLS_OCSP_SingleReq *singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &singleReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq != NULL);
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq, &certId), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId != NULL);
    CRYPT_MD_AlgId hashAlg = 0;
    BSL_Buffer issuerNameHash = {0};
    BSL_Buffer issuerKeyHash = {0};
    BSL_Buffer serialNumber = {0};
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId, &hashAlg, &issuerNameHash, &issuerKeyHash, &serialNumber),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg, CRYPT_MD_SHA1);
    ASSERT_TRUE(issuerNameHash.dataLen == 20);
    ASSERT_TRUE(issuerKeyHash.dataLen == 20);
    ASSERT_TRUE(serialNumber.dataLen > 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC020: Pre-generated OCSP request DER (minimal, no nonce)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_REQ_MINIMAL_TC020(void)
{
#ifdef HITLS_PKI_OCSP
    static const uint8_t reqMinDer[] = {
        0x30, 0x55, 0x30, 0x53, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
        0x1a, 0x05, 0x00, 0x04, 0x14, 0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff, 0xe6, 0x16, 0x8b, 0x75, 0xa0, 0x61, 0x38,
        0xae, 0x4b, 0x93, 0x4c, 0x66, 0x3e, 0x82, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5,
        0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97,
        0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d};
    BSL_Buffer buf = {(uint8_t *)reqMinDer, sizeof(reqMinDer)};
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &buf, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    uint32_t count = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(req, &count), HITLS_PKI_SUCCESS);
    ASSERT_EQ(count, 1);
    BSL_Buffer nonce = {0};
    int32_t ret = HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce));
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS || nonce.data == NULL);
    HITLS_OCSP_SingleReq *singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &singleReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq != NULL);
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq, &certId), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId != NULL);
    CRYPT_MD_AlgId hashAlg = 0;
    BSL_Buffer issuerNameHash = {0};
    BSL_Buffer issuerKeyHash = {0};
    BSL_Buffer serialNumber = {0};
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId, &hashAlg, &issuerNameHash, &issuerKeyHash, &serialNumber),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg, CRYPT_MD_SHA1);
    ASSERT_TRUE(issuerNameHash.dataLen == 20);
    ASSERT_TRUE(issuerKeyHash.dataLen == 20);
    ASSERT_TRUE(serialNumber.dataLen > 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC021: Pre-generated OCSP response DER (full: nonce + certs)
 *        Parse, verify status, nonce, cert status, signature+chain
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_RESP_FULL_TC021(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_List *certs = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    static const uint8_t respFullDer[] = {
        0x30, 0x82, 0x02, 0xca, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0xc3, 0x30, 0x82, 0x02, 0xbf, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0xb0, 0x30, 0x82, 0x02, 0xac, 0x30, 0x81,
        0xbf, 0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43,
        0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41,
        0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x37, 0x31, 0x36, 0x5a, 0x30,
        0x64, 0x30, 0x62, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        0x7a, 0x95, 0x3c, 0x0a, 0x52, 0xff, 0xe6, 0x16, 0x8b, 0x75, 0xa0, 0x61, 0x38, 0xae, 0x4b, 0x93, 0x4c, 0x66,
        0x3e, 0x82, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3,
        0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a,
        0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
        0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x37, 0x31, 0x36, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x4a, 0x27, 0xfb, 0x6a,
        0x4f, 0x53, 0xc7, 0x71, 0x7e, 0x49, 0xf2, 0x00, 0x0b, 0xa3, 0x93, 0x8e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x9c, 0x77, 0x9a, 0xc2,
        0xb9, 0xfb, 0x6c, 0x84, 0xd8, 0x5f, 0xde, 0xd8, 0x0d, 0x4c, 0x28, 0x53, 0xb8, 0x91, 0xed, 0x9a, 0xf9, 0x7c,
        0x00, 0xa1, 0xe4, 0x65, 0xf8, 0x41, 0x39, 0xaf, 0x35, 0xcb, 0x02, 0x20, 0x7b, 0x1a, 0xb0, 0x66, 0x83, 0x40,
        0x62, 0xa9, 0xb9, 0x34, 0x94, 0xb3, 0xc8, 0x7c, 0xa4, 0xfc, 0xa1, 0xd0, 0x16, 0x61, 0x7f, 0x8f, 0x1e, 0xc9,
        0xe6, 0x31, 0x4b, 0x02, 0x20, 0x64, 0x68, 0x73, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30, 0x82,
        0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e,
        0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e,
        0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33,
        0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d,
        0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc,
        0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d,
        0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57,
        0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
        0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27,
        0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
        0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27,
        0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8,
        0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02,
        0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f,
        0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
    };

    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respFullDer, sizeof(respFullDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    static const uint8_t expectedNonce[] = {0x4a, 0x27, 0xfb, 0x6a, 0x4f, 0x53, 0xc7, 0x71,
                                            0x7e, 0x49, 0xf2, 0x00, 0x0b, 0xa3, 0x93, 0x8e};
    ASSERT_EQ(nonce.dataLen, sizeof(expectedNonce));
    ASSERT_EQ(memcmp(nonce.data, expectedNonce, sizeof(expectedNonce)), 0);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_UNKNOWN);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    // ica = NULL;
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC022: Pre-generated OCSP response DER (minimal: no nonce, with certs)
 *        Parse, verify status, no nonce, cert status, signature+chain
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_RESP_MINIMAL_TC022(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_List *certs = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respMinDer[] = {
        0x30, 0x82, 0x01, 0x2f, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0x28, 0x30, 0x82, 0x01, 0x24, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0x15, 0x30, 0x82, 0x01, 0x11, 0x30, 0x81,
        0xb7, 0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43,
        0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41,
        0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x32, 0x33, 0x38, 0x34, 0x37, 0x5a, 0x30,
        0x81, 0x80, 0x30, 0x7e, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84,
        0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8,
        0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc,
        0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02,
        0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6,
        0x47, 0xa0, 0x7d, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
        0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xf9, 0xc7, 0xd3, 0x81, 0x70, 0x58, 0xb5, 0x94, 0xa2, 0x53, 0xfd, 0x5f,
        0x4c, 0xe5, 0x53, 0x86, 0x5f, 0xfa, 0x7f, 0xcf, 0xb9, 0xea, 0xbc, 0x3c, 0x0e, 0x5b, 0x7a, 0x71, 0xab, 0x9f,
        0xa2, 0xda, 0x02, 0x21, 0x00, 0xff, 0x53, 0x62, 0xc5, 0x69, 0x7c, 0xf0, 0xab, 0x29, 0xdf, 0xb1, 0x74, 0xad,
        0x82, 0x53, 0xeb, 0xeb, 0x98, 0xd4, 0x15, 0x59, 0x96, 0xb0, 0x1a, 0xc9, 0x19, 0xa1, 0xe7, 0xa5, 0x05, 0xd4,
        0xd2,
    };

    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respMinDer, sizeof(respMinDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    int32_t nonceRet = HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce));
    ASSERT_TRUE(nonceRet != HITLS_PKI_SUCCESS || nonce.data == NULL);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_UNKNOWN);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC023: Pre-generated API OCSP request (signed+nonce+requestorName+singleExt)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_REQ_SIGNED_TC023(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_Cert *ica = NULL;
    HITLS_OCSP_Req *req = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t reqSignedDer[] = {
        0x30, 0x82, 0x02, 0xd4, 0x30, 0x81, 0xdf, 0xa1, 0x23, 0xa4, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
        0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x30, 0x69, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c,
        0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3,
        0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb,
        0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6,
        0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3,
        0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa0, 0x22, 0x30, 0x20, 0x30,
        0x1e, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06, 0x04, 0x11, 0x18, 0x0f, 0x32, 0x30,
        0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa2, 0x23, 0x30, 0x21, 0x30,
        0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xde, 0xad,
        0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0xa0, 0x82, 0x01, 0xee,
        0x30, 0x82, 0x01, 0xea, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
        0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xfb, 0x45, 0x5a, 0x39, 0x41, 0x60, 0x97, 0x18, 0xb6, 0xaa, 0x64, 0x51,
        0xaa, 0x2f, 0xa4, 0xd3, 0x1d, 0x61, 0x31, 0xc1, 0x03, 0x74, 0x6d, 0x60, 0x59, 0x50, 0xc3, 0xf0, 0x86, 0x89,
        0xe5, 0x99, 0x02, 0x20, 0x53, 0xbe, 0x1a, 0xa5, 0x67, 0x21, 0x1f, 0xfe, 0x18, 0x5b, 0x62, 0x11, 0xa2, 0x02,
        0x77, 0xc3, 0x5a, 0x87, 0x97, 0x50, 0xea, 0xf5, 0xd2, 0x2d, 0x9e, 0xe7, 0x2e, 0x91, 0x2d, 0x36, 0x0d, 0x89,
        0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53,
        0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50,
        0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30,
        0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32,
        0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f,
        0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43,
        0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45,
        0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11,
        0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5,
        0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc,
        0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66,
        0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94,
        0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4,
        0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d,
        0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe,
        0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13,
        0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
    };
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer reqBuf = {(uint8_t *)reqSignedDer, sizeof(reqSignedDer)};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqBuf, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    bool isSigned = false;
    ASSERT_EQ(HITLS_OCSP_ReqIsSigned(req, &isSigned), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(isSigned);
    uint32_t count = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(req, &count), HITLS_PKI_SUCCESS);
    ASSERT_EQ(count, 1);
    HITLS_OCSP_SingleReq *singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &singleReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq != NULL);
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq, &certId), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId != NULL);
    int32_t hashAlg = -1;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId, (CRYPT_MD_AlgId *)&hashAlg, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg, CRYPT_MD_SHA256);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    static const uint8_t expectedNonce[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78,
                                            0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44};
    ASSERT_EQ(nonce.dataLen, sizeof(expectedNonce));
    ASSERT_EQ(memcmp(nonce.data, expectedNonce, sizeof(expectedNonce)), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC024: Pre-generated API OCSP request (2 CertIDs + nonce, unsigned)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_REQ_MULTI_TC024(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *req = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t reqMultiDer[] = {
        0x30, 0x82, 0x01, 0x06, 0x30, 0x82, 0x01, 0x02, 0x30, 0x81, 0xda, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d, 0x06,
        0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37,
        0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a,
        0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b,
        0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca,
        0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38,
        0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x73, 0x48, 0xc7,
        0xec, 0x71, 0x5d, 0x08, 0xa9, 0x22, 0x3e, 0x77, 0x06, 0xd5, 0x0f, 0x40, 0xc0, 0x86, 0x2b, 0x86, 0x80, 0xdd,
        0x04, 0x2d, 0x1c, 0x92, 0x11, 0x72, 0x5c, 0xb2, 0xab, 0xbc, 0x41, 0x04, 0x20, 0xea, 0xf1, 0xd6, 0xde, 0x6a,
        0x59, 0xe4, 0x1f, 0x4b, 0x9c, 0xaf, 0xa7, 0xe5, 0x4f, 0xcd, 0x7c, 0xfb, 0x58, 0x2f, 0x98, 0xdf, 0x2a, 0x11,
        0x91, 0xe2, 0xf4, 0x8f, 0x74, 0x12, 0x22, 0x6e, 0x93, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9,
        0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0xa2, 0x23, 0x30, 0x21, 0x30,
        0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x8b, 0x59,
        0x52, 0xca, 0xed, 0xfd, 0x6c, 0x14, 0x97, 0xb3, 0xc3, 0x6d, 0x09, 0xa9, 0x1b, 0xf3,
    };
    BSL_Buffer reqBuf = {(uint8_t *)reqMultiDer, sizeof(reqMultiDer)};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqBuf, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    uint32_t count = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(req, &count), HITLS_PKI_SUCCESS);
    ASSERT_EQ(count, 2);
    HITLS_OCSP_SingleReq *singleReq0 = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &singleReq0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq0 != NULL);
    HITLS_OCSP_CertId *certId0 = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq0, &certId0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId0 != NULL);
    HITLS_OCSP_SingleReq *singleReq1 = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 1, &singleReq1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq1 != NULL);
    HITLS_OCSP_CertId *certId1 = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq1, &certId1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId1 != NULL);
    int32_t hashAlg0 = -1;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId0, (CRYPT_MD_AlgId *)&hashAlg0, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg0, CRYPT_MD_SHA256);
    int32_t hashAlg1 = -1;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId1, (CRYPT_MD_AlgId *)&hashAlg1, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg1, CRYPT_MD_SHA256);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    ASSERT_EQ(nonce.dataLen, (uint32_t)16);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC025: Pre-generated API OCSP response (GOOD+nextUpdate+byKey+nonce)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_RESP_GOOD_TC025(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_List *certs = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respGoodDer[] = {
        0x30, 0x82, 0x02, 0xf0, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0xe9, 0x30, 0x82, 0x02, 0xe5, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0xd6, 0x30, 0x82, 0x02, 0xd2, 0x30, 0x81,
        0xe5, 0xa2, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82,
        0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30,
        0x32, 0x33, 0x38, 0x34, 0x37, 0x5a, 0x30, 0x81, 0x94, 0x30, 0x81, 0x91, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39,
        0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d,
        0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1,
        0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c,
        0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13,
        0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32,
        0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30,
        0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30,
        0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xaa, 0xbb,
        0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x2a, 0x35, 0x45,
        0x32, 0x50, 0x3f, 0x35, 0x0d, 0x44, 0xee, 0x69, 0x01, 0x4d, 0xda, 0xcf, 0x71, 0x88, 0x46, 0xc2, 0x46, 0xcd,
        0x11, 0x92, 0xb1, 0xfb, 0xb5, 0xec, 0x62, 0x16, 0x35, 0x1b, 0xe4, 0x02, 0x21, 0x00, 0xae, 0x75, 0xd6, 0xa4,
        0x2c, 0xb7, 0xde, 0xa5, 0x3c, 0x5f, 0x0a, 0x98, 0xeb, 0x90, 0x7d, 0xa1, 0xa6, 0x5e, 0x6c, 0x2e, 0x79, 0x99,
        0x4d, 0x76, 0xb6, 0xe7, 0xf3, 0x84, 0x4b, 0xa0, 0x5d, 0xd7, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c,
        0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e,
        0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41,
        0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17,
        0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d,
        0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65,
        0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
        0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba,
        0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65,
        0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92,
        0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82,
        0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f,
        0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
        0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65,
        0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22,
        0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22,
        0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
    };
    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respGoodDer, sizeof(respGoodDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    static const uint8_t expectedNonce[] = {0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
                                            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    ASSERT_EQ(nonce.dataLen, sizeof(expectedNonce));
    ASSERT_EQ(memcmp(nonce.data, expectedNonce, sizeof(expectedNonce)), 0);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_GOOD);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC026: Pre-generated API OCSP response (REVOKED+reason+nextUpdate+nonce+singleExt)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_RESP_REVOKED_TC026(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_List *certs = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respRevokedDer[] = {
        0x30, 0x82, 0x03, 0x36, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x03, 0x2f, 0x30, 0x82, 0x03, 0x2b, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x03, 0x1c, 0x30, 0x82, 0x03, 0x18, 0x30, 0x82,
        0x01, 0x2a, 0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f,
        0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43,
        0x41, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x32, 0x33, 0x38, 0x34, 0x37, 0x5a,
        0x30, 0x81, 0xce, 0x30, 0x81, 0xcb, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed,
        0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9,
        0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b,
        0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a,
        0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5,
        0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x31, 0x39, 0x31,
        0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30,
        0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
        0x30, 0x39, 0x32, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x22, 0x30, 0x20, 0x30, 0x1e, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06, 0x04, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x30,
        0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xa3, 0xc1, 0x8a, 0x56,
        0x60, 0x44, 0x49, 0xec, 0x5d, 0x8b, 0x5d, 0xce, 0xc6, 0xd1, 0x79, 0x0e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x28, 0x6b, 0x01, 0x00, 0x26,
        0x69, 0x0f, 0xf2, 0x07, 0x3f, 0xd2, 0x07, 0x7e, 0x12, 0xe6, 0x06, 0x0a, 0xbe, 0x69, 0x60, 0x42, 0xb7, 0xae,
        0x4a, 0x77, 0xdf, 0xdd, 0xc9, 0xdd, 0x3d, 0x0b, 0x0d, 0x02, 0x21, 0x00, 0xfd, 0x38, 0x5e, 0x2f, 0x46, 0x52,
        0xf0, 0x4a, 0xee, 0x03, 0x8c, 0xf0, 0x84, 0x23, 0x25, 0x46, 0x53, 0x96, 0x05, 0x3a, 0xc0, 0x20, 0x00, 0xb7,
        0x1e, 0xd3, 0x04, 0x98, 0x12, 0xfa, 0x1f, 0xa8, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30, 0x82,
        0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9, 0x2e,
        0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e,
        0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33,
        0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d,
        0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc,
        0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d,
        0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57,
        0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
        0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27,
        0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
        0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27,
        0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30,
        0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8,
        0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02,
        0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f,
        0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
    };
    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respRevokedDer, sizeof(respRevokedDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_REVOKED);
    int32_t reason = -1;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON, &reason, sizeof(reason)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(reason, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC027: Pre-generated API OCSP response (minimal: UNKNOWN, no nonce, no certs)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_RESP_MINIMAL_TC027(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_Cert *ica = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respMinDer[] = {
        0x30, 0x82, 0x01, 0x2f, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0x28, 0x30, 0x82, 0x01, 0x24, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0x15, 0x30, 0x82, 0x01, 0x11, 0x30, 0x81,
        0xb7, 0xa1, 0x21, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43,
        0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41,
        0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x32, 0x33, 0x38, 0x34, 0x37, 0x5a, 0x30,
        0x81, 0x80, 0x30, 0x7e, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84,
        0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8,
        0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc,
        0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02,
        0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6,
        0x47, 0xa0, 0x7d, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49,
        0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xf9, 0xc7, 0xd3, 0x81, 0x70, 0x58, 0xb5, 0x94, 0xa2, 0x53, 0xfd, 0x5f,
        0x4c, 0xe5, 0x53, 0x86, 0x5f, 0xfa, 0x7f, 0xcf, 0xb9, 0xea, 0xbc, 0x3c, 0x0e, 0x5b, 0x7a, 0x71, 0xab, 0x9f,
        0xa2, 0xda, 0x02, 0x21, 0x00, 0xff, 0x53, 0x62, 0xc5, 0x69, 0x7c, 0xf0, 0xab, 0x29, 0xdf, 0xb1, 0x74, 0xad,
        0x82, 0x53, 0xeb, 0xeb, 0x98, 0xd4, 0x15, 0x59, 0x96, 0xb0, 0x1a, 0xc9, 0x19, 0xa1, 0xe7, 0xa5, 0x05, 0xd4,
        0xd2,
    };
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respMinDer, sizeof(respMinDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    int32_t nonceRet = HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce));
    ASSERT_TRUE(nonceRet != HITLS_PKI_SUCCESS || nonce.data == NULL);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus, sizeof(certStatus)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_UNKNOWN);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * TC028: Pre-generated API minimal OCSP request (SHA-256 hash, no nonce, no signature)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_REQ_MINIMAL_TC028(void)
{
#ifdef HITLS_PKI_OCSP
    static const uint8_t reqMinDer[] = {
        0x30, 0x71, 0x30, 0x6f, 0x30, 0x6d, 0x30, 0x6b, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a,
        0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94,
        0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1,
        0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca,
        0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3,
        0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d};
    BSL_Buffer buf = {(uint8_t *)reqMinDer, sizeof(reqMinDer)};
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &buf, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    uint32_t count = 0;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqCount(req, &count), HITLS_PKI_SUCCESS);
    ASSERT_EQ(count, 1);
    BSL_Buffer nonce = {0};
    int32_t ret = HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce));
    ASSERT_TRUE(ret != HITLS_PKI_SUCCESS || nonce.data == NULL);
    HITLS_OCSP_SingleReq *singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqGetSingleReqByIndex(req, 0, &singleReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(singleReq != NULL);
    HITLS_OCSP_CertId *certId = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleReqGetCertId(singleReq, &certId), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(certId != NULL);
    CRYPT_MD_AlgId hashAlg = 0;
    BSL_Buffer issuerNameHash = {0};
    BSL_Buffer issuerKeyHash = {0};
    BSL_Buffer serialNumber = {0};
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(certId, &hashAlg, &issuerNameHash, &issuerKeyHash, &serialNumber),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(hashAlg, CRYPT_MD_SHA256);
    ASSERT_TRUE(issuerNameHash.dataLen == 32);
    ASSERT_TRUE(issuerKeyHash.dataLen == 32);
    ASSERT_TRUE(serialNumber.dataLen > 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */


/* ============================================================================
 * TC030: Pre-generated API comprehensive OCSP response
 *        (byKey ResponderID, 3 SingleResponses: GOOD+REVOKED+UNKNOWN,
 *         nextUpdate, revocationReason, singleExtensions, nonce, embedded cert)
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_RESP_COMPREHENSIVE_TC029(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_List *certs = NULL;
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respCompDer[] = {
        0x30, 0x82, 0x04, 0x65, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x04, 0x5e, 0x30, 0x82, 0x04, 0x5a, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x04, 0x4b, 0x30, 0x82,
        0x04, 0x47, 0x30, 0x82, 0x02, 0x58, 0xa2, 0x16, 0x04, 0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89,
        0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x18, 0x0f,
        0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x31, 0x31, 0x30, 0x33, 0x35, 0x35, 0x5a, 0x30,
        0x82, 0x02, 0x06, 0x30, 0x81, 0xb5, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a,
        0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d,
        0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb,
        0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53,
        0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e,
        0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0,
        0x7d, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x22, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06, 0x04, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x30,
        0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x81, 0xcb, 0x30, 0x69,
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
        0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16,
        0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8,
        0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b,
        0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7,
        0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6,
        0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0xa1, 0x16, 0x18, 0x0f, 0x32, 0x30, 0x32,
        0x36, 0x30, 0x39, 0x31, 0x39, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x03, 0x0a, 0x01,
        0x01, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x22, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2b, 0x06, 0x01,
        0x05, 0x05, 0x07, 0x30, 0x01, 0x06, 0x04, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31,
        0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x7e, 0x30, 0x69, 0x30, 0x0d, 0x06,
        0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87,
        0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd, 0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4,
        0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7, 0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20,
        0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1, 0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e,
        0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6, 0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94,
        0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97, 0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba,
        0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39,
        0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xbb, 0xcc,
        0xdd, 0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02,
        0x21, 0x00, 0xca, 0x98, 0x40, 0x14, 0x2d, 0x9d, 0x1c, 0xb6, 0xb8, 0xc6, 0x9f, 0x5f, 0x1b, 0x6a,
        0x1f, 0xab, 0x6a, 0x53, 0x7d, 0x25, 0x9c, 0xd9, 0x5f, 0x9a, 0x34, 0xd8, 0x65, 0xa7, 0x65, 0xcf,
        0xbb, 0x57, 0x02, 0x21, 0x00, 0x94, 0xc4, 0x71, 0x4b, 0xc4, 0x98, 0xdc, 0x29, 0x5d, 0x62, 0x56,
        0x58, 0xfd, 0x0a, 0xe9, 0x04, 0xb6, 0x0f, 0x3e, 0x82, 0x4b, 0xcc, 0xf1, 0x60, 0x04, 0x2b, 0xdb,
        0x81, 0x28, 0x24, 0x0c, 0xf1, 0xa0, 0x82, 0x01, 0x90, 0x30, 0x82, 0x01, 0x8c, 0x30, 0x82, 0x01,
        0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b, 0x0e, 0xb9,
        0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32, 0xc1, 0x54,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15,
        0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f,
        0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30,
        0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x37, 0x30, 0x31,
        0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69,
        0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59, 0xe6, 0xd0,
        0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9, 0xe5, 0xf5,
        0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33, 0xad, 0x86,
        0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58, 0xdc, 0x24,
        0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x53, 0xc7,
        0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf, 0xe3, 0xcb,
        0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xda,
        0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39,
        0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3, 0xeb, 0x20,
        0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d, 0x38, 0x79,
        0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a, 0xfe, 0x85,
        0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9, 0x48, 0x48, 0xe4,
        0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55

    };
    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respCompDer, sizeof(respCompDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    BSL_Buffer nonce = {0};
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL);
    static const uint8_t expectedNonce[] = {0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04,
                                            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
    ASSERT_EQ(nonce.dataLen, sizeof(expectedNonce));
    ASSERT_EQ(memcmp(nonce.data, expectedNonce, sizeof(expectedNonce)), 0);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 3);
    HITLS_OCSP_SingleResp *sr0 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr0), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr0 != NULL);
    HITLS_OCSP_CertStatus certStatus0 = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr0, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus0, sizeof(certStatus0)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus0, HITLS_OCSP_CERT_STATUS_GOOD);
    BSL_TIME nextUpdate0 = {0};
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr0, HITLS_OCSP_SINGLERESP_GET_NEXT_UPDATE, &nextUpdate0, sizeof(nextUpdate0)),
              HITLS_PKI_SUCCESS);
    HITLS_OCSP_SingleResp *sr1 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 1, &sr1), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr1 != NULL);
    HITLS_OCSP_CertStatus certStatus1 = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr1, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus1, sizeof(certStatus1)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus1, HITLS_OCSP_CERT_STATUS_REVOKED);
    int32_t reason = -1;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr1, HITLS_OCSP_SINGLERESP_GET_REVOCATION_REASON, &reason, sizeof(reason)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(reason, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE);
    HITLS_OCSP_SingleResp *sr2 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 2, &sr2), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr2 != NULL);
    HITLS_OCSP_CertStatus certStatus2 = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr2, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus2, sizeof(certStatus2)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus2, HITLS_OCSP_CERT_STATUS_UNKNOWN);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */
/* ============================================================================
 * TC029: OCSP response signed by delegated responder (with id-kp-OCSPSigning EKU)
 *        Covers RFC 6960 §4.2.2.2 condition 2: signer has OCSPSigning EKU and
 *        is issued by the CA that issued the target cert.
 * ============================================================================ */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_PREDATA_API_RESP_DELEGATED_TC030(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_StoreCtx *storeCtx2 = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *rootCa = NULL;
    HITLS_X509_Cert *responder = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_List *certs = NULL;
    static const uint8_t rootCaDer[] = {
        0x30, 0x82, 0x01, 0x84, 0x30, 0x82, 0x01, 0x29, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x40,
        0x02, 0x0f, 0x9d, 0x73, 0xb4, 0x7d, 0xed, 0x29, 0xc8, 0x9a, 0x25, 0xc3, 0xbc, 0xa1, 0xd4, 0xc0,
        0x47, 0xb9, 0xa6, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50,
        0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39,
        0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31,
        0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43,
        0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x3b, 0x74, 0x7e, 0xe9,
        0xc5, 0x39, 0x2d, 0xf7, 0xb9, 0xf0, 0xe2, 0x73, 0xec, 0xce, 0xd9, 0xe5, 0x0a, 0xd7, 0xf6, 0x4c,
        0x5c, 0x6c, 0xb9, 0x29, 0x9e, 0x1d, 0x64, 0xce, 0x4b, 0x85, 0xb5, 0x00, 0x6a, 0xb6, 0xd0, 0x0f,
        0xd0, 0x47, 0xa8, 0xb0, 0x6b, 0xed, 0xf6, 0x6c, 0x25, 0x11, 0xe0, 0xf0, 0xb5, 0xda, 0x90, 0xdc,
        0xf7, 0x2c, 0xcc, 0x1b, 0x39, 0x56, 0x5f, 0xc5, 0x02, 0x2f, 0xb8, 0xd1, 0xa3, 0x53, 0x30, 0x51,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4,
        0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30,
        0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8,
        0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
        0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00,
        0x30, 0x46, 0x02, 0x21, 0x00, 0xd3, 0xed, 0x96, 0x12, 0x33, 0x39, 0x27, 0xc3, 0x4f, 0x5f, 0x6a,
        0x3c, 0x36, 0x87, 0x77, 0x1f, 0x58, 0x42, 0x12, 0x7c, 0x53, 0xc9, 0xce, 0x89, 0x91, 0x03, 0xe3,
        0x0b, 0x78, 0x39, 0xd0, 0xa8, 0x02, 0x21, 0x00, 0x94, 0xf0, 0x57, 0x10, 0x03, 0x01, 0x96, 0x59,
        0x7d, 0x8e, 0xf1, 0xbc, 0x3d, 0xdb, 0xc3, 0xaa, 0x94, 0xbc, 0xd3, 0x1b, 0x47, 0x8e, 0xe4, 0xea,
        0x6e, 0x3a, 0x77, 0x9f, 0x92, 0xfb, 0xe2, 0x4e,
    };
    static const uint8_t icaDer[] = {
        0x30, 0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b,
        0x5b, 0x0e, 0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93,
        0x32, 0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50,
        0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39,
        0x32, 0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31,
        0x37, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d,
        0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03,
        0x59, 0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7,
        0xd9, 0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5,
        0x33, 0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68,
        0x58, 0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
        0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27,
        0xbf, 0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64,
        0xf9, 0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90,
        0xb3, 0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d,
        0x3d, 0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe,
        0x4a, 0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9,
        0x48, 0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55,
    };
    static const uint8_t responderDer[] = {
        0x30, 0x82, 0x01, 0x50, 0x30, 0x81, 0xf7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x70, 0x5b,
        0xf2, 0xb8, 0x81, 0x2a, 0xd1, 0x06, 0x6e, 0x2d, 0xb4, 0xdd, 0x5c, 0xaa, 0x0b, 0x4d, 0x1f, 0xec,
        0xee, 0xe9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x1f,
        0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20,
        0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30,
        0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x31, 0x30, 0x39, 0x32, 0x30, 0x33, 0x32, 0x5a,
        0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x38, 0x30, 0x39, 0x32, 0x30, 0x33, 0x32, 0x5a, 0x30,
        0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x4f, 0x43, 0x53, 0x50,
        0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00, 0x04, 0xed, 0x5c, 0x6b, 0x82, 0x1e, 0xb8, 0xe3, 0xdd, 0xb5, 0xd9, 0x55,
        0x5b, 0xaf, 0x9e, 0xca, 0x9b, 0x74, 0x55, 0x92, 0x7c, 0x32, 0x2a, 0xf3, 0x1e, 0x08, 0xac, 0xbf,
        0x07, 0xec, 0x01, 0x6e, 0xc4, 0x58, 0x18, 0x26, 0x97, 0xf3, 0x27, 0x1c, 0x23, 0xff, 0xf4, 0x85,
        0xf4, 0x6c, 0x07, 0xfa, 0xd4, 0x0b, 0xe7, 0x23, 0xdc, 0xb7, 0xf0, 0xaf, 0x9f, 0xfd, 0x49, 0xf0,
        0xb4, 0x6c, 0xe6, 0x57, 0xd7, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25,
        0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
        0x20, 0x0d, 0x19, 0x64, 0x80, 0x5a, 0x93, 0x20, 0x96, 0x47, 0x65, 0x03, 0x19, 0x48, 0x2d, 0x1a,
        0x0b, 0x89, 0x03, 0xf2, 0x00, 0x63, 0xfb, 0xd6, 0x23, 0xdb, 0xb0, 0xef, 0x44, 0x36, 0xc9, 0x59,
        0xb9, 0x02, 0x21, 0x00, 0xec, 0x7e, 0x91, 0x4c, 0x81, 0x4c, 0xf5, 0xf8, 0x14, 0x88, 0x4d, 0xbe,
        0x42, 0x67, 0x1e, 0xbe, 0xb5, 0xc8, 0xfb, 0xb6, 0x56, 0x33, 0x9e, 0x8a, 0x80, 0xd5, 0xb9, 0x6d,
        0x41, 0x0b, 0x79, 0xdc
    };
/* This preset OCSP data was generated by another cryptographic library. */
    static const uint8_t respDelegatedDer[] = {
        0x30, 0x82, 0x05, 0x97, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x05, 0x90, 0x30, 0x82, 0x05, 0x8c, 0x06,
        0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x05, 0x7d, 0x30, 0x82,
        0x05, 0x79, 0x30, 0x81, 0xe5, 0xa2, 0x16, 0x04, 0x14, 0x25, 0x78, 0x6a, 0xf1, 0xbb, 0x7e, 0xa7,
        0xd5, 0x70, 0x2c, 0xe5, 0x79, 0x6c, 0x28, 0x89, 0xc3, 0xe7, 0x7a, 0x76, 0x5f, 0x18, 0x0f, 0x32,
        0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x31, 0x30, 0x39, 0x32, 0x32, 0x33, 0x31, 0x5a, 0x30, 0x81,
        0x94, 0x30, 0x81, 0x91, 0x30, 0x69, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0xbc, 0x87, 0x8c, 0x37, 0x39, 0x09, 0x9a, 0xb1, 0xfd,
        0x10, 0xed, 0x26, 0x84, 0x2b, 0x16, 0x71, 0xf2, 0xf4, 0x51, 0x14, 0xe3, 0x3a, 0x1d, 0x94, 0xa7,
        0x18, 0xe8, 0x6a, 0xb9, 0x1b, 0xc8, 0x9f, 0x04, 0x20, 0x61, 0x5f, 0x48, 0x99, 0xfb, 0x5b, 0xe1,
        0xa7, 0x84, 0xc7, 0x86, 0x7f, 0x8b, 0x84, 0xfc, 0x6e, 0xe6, 0xfa, 0x77, 0xef, 0x53, 0x7e, 0xf6,
        0xca, 0x1c, 0xda, 0x9f, 0x87, 0xf7, 0x23, 0x7a, 0x94, 0x02, 0x14, 0x18, 0x60, 0x6e, 0x36, 0x97,
        0xd1, 0xc3, 0x38, 0x13, 0x7a, 0xd6, 0x29, 0x9b, 0xba, 0xe5, 0xb4, 0xe6, 0x47, 0xa0, 0x7d, 0x80,
        0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x39, 0x32, 0x37, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01,
        0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x41, 0x7e, 0x9e,
        0x93, 0xfc, 0x76, 0xf1, 0x97, 0x67, 0x85, 0xb6, 0x3d, 0x00, 0x88, 0xd6, 0xfe, 0x07, 0x4f, 0x83,
        0xa4, 0x31, 0x48, 0x44, 0xc3, 0xa1, 0xcf, 0x12, 0xdb, 0x42, 0x9f, 0x2f, 0xaa, 0x02, 0x20, 0x6d,
        0x48, 0x1c, 0x5a, 0x68, 0x59, 0x20, 0x4b, 0xe3, 0xf4, 0x25, 0x60, 0x96, 0x47, 0xe2, 0x2a, 0x9a,
        0xb8, 0x5a, 0x7f, 0x40, 0x6a, 0x3a, 0xcf, 0x1d, 0x59, 0xe6, 0xa7, 0xa1, 0x35, 0x29, 0x93, 0xa0,
        0x82, 0x04, 0x38, 0x30, 0x82, 0x04, 0x34, 0x30, 0x82, 0x01, 0x50, 0x30, 0x81, 0xf7, 0xa0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x14, 0x70, 0x5b, 0xf2, 0xb8, 0x81, 0x2a, 0xd1, 0x06, 0x6e, 0x2d, 0xb4,
        0xdd, 0x5c, 0xaa, 0x0b, 0x4d, 0x1f, 0xec, 0xee, 0xe9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69,
        0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x31,
        0x30, 0x39, 0x32, 0x30, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x38, 0x30,
        0x39, 0x32, 0x30, 0x33, 0x32, 0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x0e, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65,
        0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xed, 0x5c, 0x6b, 0x82,
        0x1e, 0xb8, 0xe3, 0xdd, 0xb5, 0xd9, 0x55, 0x5b, 0xaf, 0x9e, 0xca, 0x9b, 0x74, 0x55, 0x92, 0x7c,
        0x32, 0x2a, 0xf3, 0x1e, 0x08, 0xac, 0xbf, 0x07, 0xec, 0x01, 0x6e, 0xc4, 0x58, 0x18, 0x26, 0x97,
        0xf3, 0x27, 0x1c, 0x23, 0xff, 0xf4, 0x85, 0xf4, 0x6c, 0x07, 0xfa, 0xd4, 0x0b, 0xe7, 0x23, 0xdc,
        0xb7, 0xf0, 0xaf, 0x9f, 0xfd, 0x49, 0xf0, 0xb4, 0x6c, 0xe6, 0x57, 0xd7, 0xa3, 0x17, 0x30, 0x15,
        0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01,
        0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x0d, 0x19, 0x64, 0x80, 0x5a, 0x93, 0x20, 0x96,
        0x47, 0x65, 0x03, 0x19, 0x48, 0x2d, 0x1a, 0x0b, 0x89, 0x03, 0xf2, 0x00, 0x63, 0xfb, 0xd6, 0x23,
        0xdb, 0xb0, 0xef, 0x44, 0x36, 0xc9, 0x59, 0xb9, 0x02, 0x21, 0x00, 0xec, 0x7e, 0x91, 0x4c, 0x81,
        0x4c, 0xf5, 0xf8, 0x14, 0x88, 0x4d, 0xbe, 0x42, 0x67, 0x1e, 0xbe, 0xb5, 0xc8, 0xfb, 0xb6, 0x56,
        0x33, 0x9e, 0x8a, 0x80, 0xd5, 0xb9, 0x6d, 0x41, 0x0b, 0x79, 0xdc, 0x30, 0x82, 0x01, 0x50, 0x30,
        0x81, 0xf7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x70, 0x5b, 0xf2, 0xb8, 0x81, 0x2a, 0xd1,
        0x06, 0x6e, 0x2d, 0xb4, 0xdd, 0x5c, 0xaa, 0x0b, 0x4d, 0x1f, 0xec, 0xee, 0xe9, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72,
        0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36,
        0x30, 0x39, 0x32, 0x31, 0x30, 0x39, 0x32, 0x30, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30,
        0x39, 0x31, 0x38, 0x30, 0x39, 0x32, 0x30, 0x33, 0x32, 0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x52, 0x65, 0x73, 0x70,
        0x6f, 0x6e, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0xed, 0x5c, 0x6b, 0x82, 0x1e, 0xb8, 0xe3, 0xdd, 0xb5, 0xd9, 0x55, 0x5b, 0xaf, 0x9e, 0xca, 0x9b,
        0x74, 0x55, 0x92, 0x7c, 0x32, 0x2a, 0xf3, 0x1e, 0x08, 0xac, 0xbf, 0x07, 0xec, 0x01, 0x6e, 0xc4,
        0x58, 0x18, 0x26, 0x97, 0xf3, 0x27, 0x1c, 0x23, 0xff, 0xf4, 0x85, 0xf4, 0x6c, 0x07, 0xfa, 0xd4,
        0x0b, 0xe7, 0x23, 0xdc, 0xb7, 0xf0, 0xaf, 0x9f, 0xfd, 0x49, 0xf0, 0xb4, 0x6c, 0xe6, 0x57, 0xd7,
        0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
        0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x0d, 0x19, 0x64, 0x80,
        0x5a, 0x93, 0x20, 0x96, 0x47, 0x65, 0x03, 0x19, 0x48, 0x2d, 0x1a, 0x0b, 0x89, 0x03, 0xf2, 0x00,
        0x63, 0xfb, 0xd6, 0x23, 0xdb, 0xb0, 0xef, 0x44, 0x36, 0xc9, 0x59, 0xb9, 0x02, 0x21, 0x00, 0xec,
        0x7e, 0x91, 0x4c, 0x81, 0x4c, 0xf5, 0xf8, 0x14, 0x88, 0x4d, 0xbe, 0x42, 0x67, 0x1e, 0xbe, 0xb5,
        0xc8, 0xfb, 0xb6, 0x56, 0x33, 0x9e, 0x8a, 0x80, 0xd5, 0xb9, 0x6d, 0x41, 0x0b, 0x79, 0xdc, 0x30,
        0x82, 0x01, 0x88, 0x30, 0x82, 0x01, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4b, 0x5b,
        0x0e, 0xb9, 0x2e, 0xa4, 0xc9, 0xac, 0x75, 0x58, 0x29, 0x2f, 0x53, 0xe2, 0x37, 0xff, 0x93, 0x32,
        0xc1, 0x54, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x17,
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x20,
        0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32,
        0x30, 0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x39, 0x31, 0x37,
        0x30, 0x31, 0x32, 0x35, 0x33, 0x32, 0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x14, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
        0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0x3c, 0xcc, 0xd0, 0x1f, 0x91, 0x16, 0x86, 0x45, 0x77, 0x00, 0x38, 0x03, 0x59,
        0xe6, 0xd0, 0xba, 0x12, 0xfc, 0x3e, 0xf8, 0xe5, 0x06, 0xdd, 0x9f, 0x00, 0x11, 0x4d, 0xc7, 0xd9,
        0xe5, 0xf5, 0x40, 0x84, 0x65, 0xa3, 0x6d, 0xab, 0xe3, 0x47, 0x6f, 0xcf, 0x7e, 0x1f, 0xa5, 0x33,
        0xad, 0x86, 0x01, 0xd7, 0x53, 0x8d, 0x92, 0xaf, 0x57, 0xa8, 0xf2, 0xcd, 0x0d, 0x47, 0x68, 0x58,
        0xdc, 0x24, 0x9b, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05,
        0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
        0x53, 0xc7, 0xfe, 0x40, 0x66, 0x89, 0x99, 0xbe, 0xd5, 0x4b, 0x60, 0xdb, 0x82, 0xa3, 0x27, 0xbf,
        0xe3, 0xcb, 0x5e, 0x29, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80,
        0x14, 0xda, 0x3a, 0xf1, 0xf8, 0xe4, 0xd6, 0xa0, 0x94, 0x67, 0xe5, 0x79, 0x2f, 0x23, 0x64, 0xf9,
        0x6f, 0x39, 0x27, 0xe4, 0xe4, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x74, 0xeb, 0x89, 0x84, 0xa4, 0x5a, 0x90, 0xb3,
        0xeb, 0x20, 0xe0, 0xa0, 0x65, 0xc4, 0xd8, 0x9d, 0xa0, 0xc4, 0x19, 0xab, 0x36, 0xed, 0x4d, 0x3d,
        0x38, 0x79, 0x86, 0x56, 0x6d, 0x54, 0x22, 0x19, 0x02, 0x21, 0x00, 0xf3, 0xb8, 0x25, 0xfe, 0x4a,
        0xfe, 0x85, 0xcc, 0xa7, 0x0b, 0x30, 0x87, 0xd7, 0x22, 0x62, 0x3f, 0xac, 0x60, 0x35, 0xa9, 0x48,
        0x48, 0xe4, 0x13, 0xe7, 0xfb, 0x71, 0xde, 0x52, 0xd4, 0x8e, 0x55
    };
    BSL_Buffer rootBuf = {(uint8_t *)rootCaDer, sizeof(rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCa), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)icaDer, sizeof(icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer responderBuf = {(uint8_t *)responderDer, sizeof(responderDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &responderBuf, &responder), HITLS_PKI_SUCCESS);
    BSL_Buffer respBuf = {(uint8_t *)respDelegatedDer, sizeof(respDelegatedDer)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respBuf, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespCount(bs, &respCount), HITLS_PKI_SUCCESS);
    ASSERT_EQ(respCount, 1);
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &sr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_CertStatus certStatus = (HITLS_OCSP_CertStatus)0xFF;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS,
                                         &certStatus, sizeof(certStatus)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(certStatus, HITLS_OCSP_CERT_STATUS_GOOD);
    /* Provide responder cert and ICA cert as external certs.
     * Root CA is the trust anchor in storeCtx.
     * Chain: responder -> ICA -> Root CA (trusted) */
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, responder, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(rootCa);
    ASSERT_TRUE(storeCtx != NULL);
    /* This must succeed: responder has OCSPSigning EKU and is issued by ICA
     * (the CA that issued the target cert). Condition 2 of RFC 6960 §4.2.2.2. */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx, 0), HITLS_PKI_SUCCESS);

    storeCtx2 = HITLS_X509_StoreCtxNew();
    /* Empty trust store: the chain tail (ICA) is not trusted locally, so the
     * verify fails with the local-issuer-not-found error (main distinguishes
     * it from ISSUE_CERT_NOT_FOUND which means a trusted tail without issuer). */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(bs, certs, storeCtx2, 0), HITLS_X509_ERR_VFY_ISSUE_CERT_NOT_FOUND_LOCALLY);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_StoreCtxFree(storeCtx2);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_CertFree(rootCa);
    HITLS_X509_CertFree(responder);
    BSL_LIST_FREE(certs, FreeListData);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * Compare tests: rebuild with openHiTLS API using the same parameters as the
 * Pre-generated preset DER, then compare byte-for-byte.
 *   - Requests:  full DER must match (deterministic, unsigned)
 *   - Responses: tbsResponseData (ResponseData TLV) must match; signature differs
 * ============================================================================ */

/* TC031: Request minimal, SHA-256 CertID, no nonce */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_REQ_MIN_SHA256_TC031(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    req = OcspTestBuildReq(CRYPT_MD_SHA256, ee, ica, NULL, NULL, NULL, 0);
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);
    ASSERT_EQ(reqDer.dataLen, sizeof(g_reqMinSha256Der));
    ASSERT_EQ(memcmp(reqDer.data, g_reqMinSha256Der, sizeof(g_reqMinSha256Der)), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC032: Request minimal, SHA-1 CertID, no nonce */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_REQ_MIN_SHA1_TC032(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    req = OcspTestBuildReq(CRYPT_MD_SHA1, ee, ica, NULL, NULL, NULL, 0);
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);
    ASSERT_EQ(reqDer.dataLen, sizeof(g_reqMinSha1Der));
    ASSERT_EQ(memcmp(reqDer.data, g_reqMinSha1Der, sizeof(g_reqMinSha1Der)), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC033: Request multi (2 CertIDs) SHA-256 + nonce */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_REQ_MULTI_SHA256_TC033(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    BSL_Buffer nonce = {0};
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &root), HITLS_PKI_SUCCESS);
    /* Read the nonce from the preset DER */
    BSL_Buffer presetBuf = {(uint8_t *)g_reqMultiSha256Der, sizeof(g_reqMultiSha256Der)};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &presetBuf, &parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedReq != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(parsedReq, HITLS_OCSP_REQ_GET_NONCE, &nonce, sizeof(nonce)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(nonce.data != NULL && nonce.dataLen > 0);
    req = OcspTestBuildReq(CRYPT_MD_SHA256, ee, ica, ica, root, nonce.data, nonce.dataLen);
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);
    ASSERT_EQ(reqDer.dataLen, sizeof(g_reqMultiSha256Der));
    ASSERT_EQ(memcmp(reqDer.data, g_reqMultiSha256Der, sizeof(g_reqMultiSha256Der)), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
    HITLS_X509_CertFree(root);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC034: Response GOOD, byKey responderID, SHA-256 CertID, nonce, embedded certs */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_RESP_GOOD_BYKEY_SHA256_TC034(void)
{
#ifdef HITLS_PKI_OCSP
    CRYPT_EAL_PkeyCtx *icaKey = NULL;
    HITLS_X509_List *certs = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Resp *pResp = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_BasicResp *pBs = NULL;
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer presetBuf = {(uint8_t *)g_respGoodByKeySha256Der, sizeof(g_respGoodByKeySha256Der)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &presetBuf, &pResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pResp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(pResp, HITLS_OCSP_RESP_GET_BASIC, &pBs, sizeof(pBs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pBs != NULL);
    HITLS_OCSP_SingleResp *pSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(pBs, 0, &pSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pSr != NULL);
    HITLS_OCSP_CertId *pCid = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(pSr, HITLS_OCSP_SINGLERESP_GET_CERTID, &pCid, sizeof(pCid)), HITLS_PKI_SUCCESS);
    CRYPT_MD_AlgId hashAlg = 0;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(pCid, &hashAlg, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    int32_t ridType = HITLS_OCSP_SIGN_RESPID_BYKEY;
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    icaKey = OcspTestLoadIcaKey();
    ASSERT_TRUE(icaKey != NULL);
    resp = OcspTestRebuildResp(pBs, hashAlg, ee, ica, ica, ridType, icaKey, certs, 0);
    ASSERT_TRUE(resp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);
    ASSERT_EQ(OcspTestCompareRespNoProducedAt(respDer.data, respDer.dataLen, g_respGoodByKeySha256Der,
                                              sizeof(g_respGoodByKeySha256Der)),
              0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(pResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(icaKey);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_RespFree(pResp);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC035: Response minimal UNKNOWN, byName responderID, SHA-256, no nonce, no certs */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_RESP_MIN_BYNAME_SHA256_TC035(void)
{
#ifdef HITLS_PKI_OCSP
    CRYPT_EAL_PkeyCtx *icaKey = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Resp *pResp = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_BasicResp *pBs = NULL;
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer presetBuf = {(uint8_t *)g_respMinByNameSha256Der, sizeof(g_respMinByNameSha256Der)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &presetBuf, &pResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pResp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(pResp, HITLS_OCSP_RESP_GET_BASIC, &pBs, sizeof(pBs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pBs != NULL);
    HITLS_OCSP_SingleResp *pSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(pBs, 0, &pSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pSr != NULL);
    HITLS_OCSP_CertId *pCid = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(pSr, HITLS_OCSP_SINGLERESP_GET_CERTID, &pCid, sizeof(pCid)), HITLS_PKI_SUCCESS);
    CRYPT_MD_AlgId hashAlg = 0;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(pCid, &hashAlg, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    icaKey = OcspTestLoadIcaKey();
    ASSERT_TRUE(icaKey != NULL);
    resp = OcspTestRebuildResp(pBs, hashAlg, ee, ica, ica, 0, icaKey, NULL, HITLS_OCSP_SIGN_NOCERTS);
    ASSERT_TRUE(resp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);
    ASSERT_EQ(OcspTestCompareRespNoProducedAt(respDer.data, respDer.dataLen, g_respMinByNameSha256Der,
                                              sizeof(g_respMinByNameSha256Der)),
              0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(pResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(icaKey);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_RespFree(pResp);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC036: Response GOOD, byName responderID, SHA-1 CertID, nonce, embedded certs */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_RESP_GOOD_BYNAME_SHA1_TC036(void)
{
#ifdef HITLS_PKI_OCSP
    CRYPT_EAL_PkeyCtx *icaKey = NULL;
    HITLS_X509_List *certs = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Resp *pResp = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_BasicResp *pBs = NULL;
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer presetBuf = {(uint8_t *)g_respGoodByNameSha1Der, sizeof(g_respGoodByNameSha1Der)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &presetBuf, &pResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pResp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(pResp, HITLS_OCSP_RESP_GET_BASIC, &pBs, sizeof(pBs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pBs != NULL);
    HITLS_OCSP_SingleResp *pSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(pBs, 0, &pSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pSr != NULL);
    HITLS_OCSP_CertId *pCid = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(pSr, HITLS_OCSP_SINGLERESP_GET_CERTID, &pCid, sizeof(pCid)), HITLS_PKI_SUCCESS);
    CRYPT_MD_AlgId hashAlg = 0;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(pCid, &hashAlg, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    icaKey = OcspTestLoadIcaKey();
    ASSERT_TRUE(icaKey != NULL);
    resp = OcspTestRebuildResp(pBs, hashAlg, ee, ica, ica, 0, icaKey, certs, 0);
    ASSERT_TRUE(resp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);
    ASSERT_EQ(OcspTestCompareRespNoProducedAt(respDer.data, respDer.dataLen, g_respGoodByNameSha1Der,
                                              sizeof(g_respGoodByNameSha1Der)),
              0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(pResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(icaKey);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_RespFree(pResp);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC037: Response REVOKED + reason, byName responderID, SHA-256, nonce, embedded certs */
/* BEGIN_CASE */
void SDV_OCSP_PRESET_COMPARE_RESP_REVOKED_BYNAME_SHA256_TC037(void)
{
#ifdef HITLS_PKI_OCSP
    CRYPT_EAL_PkeyCtx *icaKey = NULL;
    HITLS_X509_List *certs = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Resp *pResp = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_BasicResp *pBs = NULL;
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);
    BSL_Buffer presetBuf = {(uint8_t *)g_respRevokedByNameSha256Der, sizeof(g_respRevokedByNameSha256Der)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &presetBuf, &pResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pResp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(pResp, HITLS_OCSP_RESP_GET_BASIC, &pBs, sizeof(pBs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pBs != NULL);
    HITLS_OCSP_SingleResp *pSr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(pBs, 0, &pSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(pSr != NULL);
    HITLS_OCSP_CertId *pCid = NULL;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(pSr, HITLS_OCSP_SINGLERESP_GET_CERTID, &pCid, sizeof(pCid)), HITLS_PKI_SUCCESS);
    CRYPT_MD_AlgId hashAlg = 0;
    ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(pCid, &hashAlg, NULL, NULL, NULL), HITLS_PKI_SUCCESS);
    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, ica, BSL_LIST_POS_END), BSL_SUCCESS);
    icaKey = OcspTestLoadIcaKey();
    ASSERT_TRUE(icaKey != NULL);
    resp = OcspTestRebuildResp(pBs, hashAlg, ee, ica, ica, 0, icaKey, certs, 0);
    ASSERT_TRUE(resp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);
    ASSERT_EQ(OcspTestCompareRespNoProducedAt(respDer.data, respDer.dataLen, g_respRevokedByNameSha256Der,
                                              sizeof(g_respRevokedByNameSha256Der)),
              0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(pResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(icaKey);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_RespFree(pResp);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC038: Find SingleResponse by CertID in BasicOCSPResponse */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_BASICRESP_FIND_RESP_TC038(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_CertId *missingCid = NULL;
    HITLS_X509_Cert *extraCert = NULL;
    CRYPT_EAL_PkeyCtx *extraKey = NULL;
    HITLS_OCSP_CertId *searchCid = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_CertId *cid1 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid1 != NULL);
    HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain2.ee, g_chain2.intermediate);
    ASSERT_TRUE(cid2 != NULL);

    BSL_TIME t = {0};
    t.year = 2024;
    t.month = 1;
    t.day = 1;
    HITLS_OCSP_SingleResp *sr1 = HITLS_OCSP_SingleRespNew(cid1, HITLS_OCSP_CERT_STATUS_GOOD, &t);
    ASSERT_TRUE(sr1 != NULL);
    HITLS_OCSP_SingleResp *sr2 = HITLS_OCSP_SingleRespNew(cid2, HITLS_OCSP_CERT_STATUS_REVOKED, &t);
    ASSERT_TRUE(sr2 != NULL);
    BSL_TIME revTime = t;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr2, HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME, &revTime, sizeof(BSL_TIME)),
              HITLS_PKI_SUCCESS);

    bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr1, sizeof(sr1)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr2, sizeof(sr2)), HITLS_PKI_SUCCESS);

    searchCid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(searchCid != NULL);
    HITLS_OCSP_SingleResp *found = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespFindResp(bs, searchCid, &found), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(found == sr1);

    /* A CertID built from a fresh cert with a different serial must NOT be found. */
    ASSERT_EQ(OcspTestGenKey(&extraKey), 0);
    ASSERT_EQ(OcspTestCreateCert(&extraCert, extraKey, g_chain1.intermediate, g_chain1.intermediateKey,
                                 "Not In Response", false),
              0);
    ASSERT_TRUE(extraCert != NULL);
    uint8_t otherSerial[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_EQ(HITLS_X509_CertCtrl(extraCert, HITLS_X509_SET_SERIALNUM, otherSerial, sizeof(otherSerial)),
              HITLS_PKI_SUCCESS);
    missingCid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, extraCert, g_chain1.intermediate);
    ASSERT_TRUE(missingCid != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespFindResp(bs, missingCid, &found), HITLS_OCSP_ERR_CERTID_NOT_FOUND);

    ASSERT_EQ(HITLS_OCSP_BasicRespFindResp(bs, NULL, &found), HITLS_OCSP_ERR_NULL_POINTER);
    ASSERT_EQ(HITLS_OCSP_BasicRespFindResp(bs, searchCid, NULL), HITLS_OCSP_ERR_NULL_POINTER);

EXIT:
    HITLS_OCSP_CertIdFree(searchCid);
    HITLS_OCSP_CertIdFree(missingCid);
    HITLS_X509_CertFree(extraCert);
    CRYPT_EAL_PkeyFreeCtx(extraKey);
    HITLS_OCSP_BasicRespFree(bs);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC039: Enum to string - revocation reasons */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_STR_REV_REASON_TC039(void)
{
#ifdef HITLS_PKI_OCSP
    const char *s = NULL;
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_UNSPECIFIED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "unspecified"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_KEY_COMPROMISE);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "keyCompromise"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_CA_COMPROMISE);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "cACompromise"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_AFFILIATION_CHANGED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "affiliationChanged"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_SUPERSEDED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "superseded"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_CESSATION_OF_OPERATION);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "cessationOfOperation"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_CERTIFICATE_HOLD);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "certificateHold"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(7);
    ASSERT_TRUE(s == NULL); /* RFC 5280: value 7 is unused/reserved, not a valid reason */
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_REMOVE_FROM_CRL);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "removeFromCRL"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_PRIVILEGE_WITHDRAWN);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "privilegeWithdrawn"), 0);
    s = HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_AA_COMPROMISE);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "aACompromise"), 0);
    ASSERT_EQ(HITLS_OCSP_RevocationReasonToStr(-1), NULL);
    ASSERT_EQ(HITLS_OCSP_RevocationReasonToStr(100), NULL);
EXIT:
    ;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC040: Enum to string - cert status */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_STR_CERT_STATUS_TC040(void)
{
#ifdef HITLS_PKI_OCSP
    const char *s = NULL;
    s = HITLS_OCSP_CertStatusToStr(HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "good"), 0);
    s = HITLS_OCSP_CertStatusToStr(HITLS_OCSP_CERT_STATUS_REVOKED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "revoked"), 0);
    s = HITLS_OCSP_CertStatusToStr(HITLS_OCSP_CERT_STATUS_UNKNOWN);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "unknown"), 0);
    ASSERT_EQ(HITLS_OCSP_CertStatusToStr((HITLS_OCSP_CertStatus)99), NULL);
EXIT:
    ;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC041: Enum to string - resp status */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_STR_RESP_STATUS_TC041(void)
{
#ifdef HITLS_PKI_OCSP
    const char *s = NULL;
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_SUCCESSFUL);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "successful"), 0);
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_MALFORMED_REQUEST);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "malformedRequest"), 0);
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "internalError"), 0);
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_TRY_LATER);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "tryLater"), 0);
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_SIG_REQUIRED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "sigRequired"), 0);
    s = HITLS_OCSP_RespStatusToStr(HITLS_OCSP_RESP_STATUS_UNAUTHORIZED);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ(strcmp(s, "unauthorized"), 0);
    ASSERT_EQ(HITLS_OCSP_RespStatusToStr((HITLS_OCSP_RespStatus)4), NULL);
    ASSERT_EQ(HITLS_OCSP_RespStatusToStr((HITLS_OCSP_RespStatus)99), NULL);
EXIT:
    ;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC042: Print OCSP request and response via HITLS_PKI_PrintCtrl */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_PRINT_TC042(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    BSL_UIO *respUio = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    BSL_UIO *reqUio = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    /* Request */
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    HITLS_OCSP_SingleReq *singleReq = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(singleReq != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, singleReq, sizeof(singleReq)),
              HITLS_PKI_SUCCESS);
    reqUio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_TRUE(reqUio != NULL);
    ASSERT_EQ(HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_REQ, (void *)req, sizeof(HITLS_OCSP_Req *), reqUio),
              HITLS_PKI_SUCCESS);

    /* Response */
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid2 != NULL);
    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    HITLS_OCSP_SingleResp *sr = HITLS_OCSP_SingleRespNew(cid2, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(sr != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate,
                                       NULL, bs, 0),
              HITLS_PKI_SUCCESS);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    respUio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_TRUE(respUio != NULL);
    ASSERT_EQ(HITLS_PKI_PrintCtrl(HITLS_PKI_PRINT_OCSP_RESP, (void *)resp, sizeof(HITLS_OCSP_Resp *), respUio),
              HITLS_PKI_SUCCESS);

    /* Exercise the print helpers too. */
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);

    /* Invalid command must be rejected */
    ASSERT_EQ(HITLS_PKI_PrintCtrl(0x7ffff, (void *)req, sizeof(HITLS_OCSP_Req *), reqUio),
              HITLS_X509_ERR_INVALID_PARAM);
EXIT:
    BSL_UIO_Free(reqUio);
    BSL_UIO_Free(respUio);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC043: ReqSign -> ReqGenBuff -> ReqParseBuff -> ReqVerify */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_REQ_SIGN_VERIFY_TC043(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *badKeyReq = NULL;
    HITLS_OCSP_Req *unsignedReq = NULL;
    BSL_Buffer reParsedDer = {0};
    HITLS_OCSP_Req *parsed = NULL;
    BSL_Buffer der = {0};
    HITLS_X509_List *certs = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    HITLS_OCSP_SingleReq *singleReq = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(singleReq != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, singleReq, sizeof(singleReq)), HITLS_PKI_SUCCESS);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, g_chain1.intermediate, BSL_LIST_POS_END), BSL_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate,
                                 certs, req, 0),
              HITLS_PKI_SUCCESS);
    bool isSigned = false;
    ASSERT_EQ(HITLS_OCSP_ReqIsSigned(req, &isSigned), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(isSigned);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &der), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(der.data != NULL);

    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &der, &parsed), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
    bool parsedSigned = false;
    ASSERT_EQ(HITLS_OCSP_ReqIsSigned(parsed, &parsedSigned), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedSigned);

    /* A parsed signed request can now be re-encoded (rawData saved at parse time). */
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, parsed, &reParsedDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reParsedDer.data != NULL);
    ASSERT_EQ(reParsedDer.dataLen, der.dataLen);
    ASSERT_EQ(memcmp(reParsedDer.data, der.data, der.dataLen), 0);

    /* Mutating a signed request must be rejected. */
    HITLS_OCSP_CertId *extraCid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(extraCid != NULL);
    HITLS_OCSP_SingleReq *extraSr = HITLS_OCSP_SingleReqNew(extraCid);
    ASSERT_TRUE(extraSr != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, extraSr, sizeof(extraSr)),
              HITLS_OCSP_ERR_ALREADY_SIGNED);
    HITLS_OCSP_SingleReqFree(extraSr);

    /* Signature-only verify is not enough when the signer is not trusted via TRUSTOTHER:
     * a storeCtx is required for chain validation, so passing NULL must fail. */
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsed, certs, NULL, 0), HITLS_OCSP_ERR_NULL_POINTER);

    /* With a storeCtx trusting the request's root CA, the signer chain (intermediate -> root)
     * verifies, so ReqVerify passes the chain validation step. */
    HITLS_X509_StoreCtx *storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsed, certs, storeCtx, 0), HITLS_PKI_SUCCESS);
    HITLS_X509_StoreCtxFree(storeCtx);

    /* The signer cert (requestorCert) is embedded automatically, so the request is
     * self-contained: with no external certs the signer is still located in the embedded
     * certs. */
    HITLS_X509_StoreCtx *selfStoreCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(selfStoreCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsed, NULL, selfStoreCtx, 0), HITLS_PKI_SUCCESS);
    HITLS_X509_StoreCtxFree(selfStoreCtx);

    /* A storeCtx trusting an unrelated CA must fail chain validation. */
    HITLS_X509_StoreCtx *wrongStoreCtx = OcspTestNewStoreCtx(g_chain2.root);
    ASSERT_TRUE(wrongStoreCtx != NULL);
    ASSERT_NE(HITLS_OCSP_ReqVerify(parsed, certs, wrongStoreCtx, 0), HITLS_PKI_SUCCESS);
    HITLS_X509_StoreCtxFree(wrongStoreCtx);

    /* With HITLS_OCSP_VFY_TRUSTOTHER the signer is taken from the external certs list and
     * trusted as-is, so chain validation is skipped even against an unrelated storeCtx. */
    HITLS_X509_StoreCtx *trustOtherCtx = OcspTestNewStoreCtx(g_chain2.root);
    ASSERT_TRUE(trustOtherCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsed, certs, trustOtherCtx, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);
    HITLS_X509_StoreCtxFree(trustOtherCtx);

    unsignedReq = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(unsignedReq != NULL);
    HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid2 != NULL);
    HITLS_OCSP_SingleReq *sr2 = HITLS_OCSP_SingleReqNew(cid2);
    ASSERT_TRUE(sr2 != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(unsignedReq, HITLS_OCSP_REQ_ADD_SINGLEREQ, sr2, sizeof(sr2)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(unsignedReq, certs, NULL, 0), HITLS_OCSP_ERR_NOT_SIGNED);

    /* Signing with a private key that does not match the requestor certificate must fail. */
    badKeyReq = OcspTestBuildReq(CRYPT_MD_SHA256, g_chain2.ee, g_chain2.intermediate, NULL, NULL, NULL, 0);
    ASSERT_TRUE(badKeyReq != NULL);
    ASSERT_NE(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain2.intermediate, NULL,
                                 badKeyReq, HITLS_OCSP_SIGN_NOCERTS),
              HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(badKeyReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(parsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(unsignedReq), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(reParsedDer.data);
    BSL_SAL_Free(der.data);
    HITLS_OCSP_ReqFree(parsed);
    HITLS_OCSP_ReqFree(unsignedReq);
    HITLS_OCSP_ReqFree(badKeyReq);
    HITLS_OCSP_ReqFree(req);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC044: ReqVerify with tampered requestList must fail */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_REQ_VERIFY_TAMPER_TC044(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *parsed = NULL;
    BSL_Buffer der = {0};
    HITLS_X509_List *certList = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    HITLS_OCSP_SingleReq *singleReq = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(singleReq != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, singleReq, sizeof(singleReq)), HITLS_PKI_SUCCESS);
    /* Embed the signer cert so ReqVerify can locate it without external certs. */
    certList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certList != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certList, g_chain1.intermediate, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate,
                                 certList, req, 0),
              HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &der), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(der.data != NULL);

    /* Walk into OCSPRequest -> TBSRequest -> requestorName -> requestList -> Request ->
     * CertID -> AlgId -> OID -> params -> issuerNameHash, then flip a content byte of the
     * hash so the signature no longer matches while the DER structure stays valid. */
    uint32_t vp = 0, vl = 0;
    uint32_t pos = 0;
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* OCSPRequest */
    pos = vp;                                                                     /* TBSRequest TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* TBSRequest */
    pos = vp;                                                                     /* requestorName [1] TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* requestorName [1] */
    pos = vp + vl;                                                               /* requestList TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* requestList */
    pos = vp;                                                                     /* Request TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* Request */
    pos = vp;                                                                     /* CertID TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* CertID */
    pos = vp;                                                                     /* AlgId TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* AlgId */
    pos = vp;                                                                     /* OID TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* OID */
    pos = vp + vl;                                                               /* params (NULL) TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* params */
    pos = vp + vl;                                                               /* issuerNameHash TLV start */
    ASSERT_EQ(OcspTestSkipTlv(der.data, der.dataLen, pos, &vp, &vl), 0);         /* issuerNameHash OCTET */
    uint32_t hashPos = vp;                                                       /* first content byte of issuerNameHash */
    ASSERT_TRUE(hashPos < der.dataLen);
    der.data[hashPos] ^= 0xFF;

    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &der, &parsed), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsed, NULL, NULL, 0), HITLS_OCSP_ERR_SIGN_VERIFY);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(parsed), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(der.data);
    HITLS_OCSP_ReqFree(parsed);
    HITLS_OCSP_ReqFree(req);
    BSL_LIST_FREE(certList, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

static void BslBufferFree(void *value)
{
    if (value != NULL) {
        BSL_Buffer *buff = (BSL_Buffer *)value;
        BSL_SAL_Free(buff->data);
        BSL_SAL_Free(buff);
    }
}

/* TC045: Get OCSP URLs from certificate AIA */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_GET_OCSP_URLS_TC045(void)
{
#ifdef HITLS_PKI_OCSP
    CRYPT_EAL_PkeyCtx *key = NULL;
    HITLS_X509_Cert *noAiaCert = NULL;
    BslList *urls = NULL;
    HITLS_X509_Cert *cert = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    const char *expectUrl = "http://status.geotrust.com";

    /* Parse a preset certificate that carries an AIA extension with an OCSP URI */
    BSL_Buffer certBuf = {(uint8_t *)g_certWithOcspUrlDer, sizeof(g_certWithOcspUrlDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &certBuf, &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);

    ASSERT_EQ(HITLS_OCSP_GetCertOcspUrls(cert, &urls), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(urls != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(urls), 1);
    BSL_Buffer *got = (BSL_Buffer *)BSL_LIST_GetIndexNode(0, urls);
    ASSERT_TRUE(got != NULL);
    ASSERT_EQ(got->dataLen, strlen(expectUrl));
    ASSERT_EQ(memcmp(got->data, expectUrl, got->dataLen), 0);

    BSL_LIST_FREE(urls, (BSL_LIST_PFUNC_FREE)BslBufferFree);
    urls = NULL;

    /* Certificate without AIA: must return HITLS_OCSP_ERR_NO_OCSP_URL */
    ASSERT_EQ(OcspTestGenKey(&key), 0);
    ASSERT_EQ(OcspTestCreateCert(&noAiaCert, key, g_chain1.intermediate, g_chain1.intermediateKey, "No AIA", false),
              0);
    ASSERT_TRUE(noAiaCert != NULL);
    ASSERT_EQ(HITLS_OCSP_GetCertOcspUrls(noAiaCert, &urls), HITLS_OCSP_ERR_NO_OCSP_URL);

EXIT:
    BSL_LIST_FREE(urls, (BSL_LIST_PFUNC_FREE)BslBufferFree);
    HITLS_X509_CertFree(noAiaCert);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(key);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC046: Parse and verify a preset signed request */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_REQ_PARSE_PREDATA_SIGNED_TC046(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    BSL_Buffer encode = {(uint8_t *)g_reqSignedSha256Der, sizeof(g_reqSignedSha256Der)};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &encode, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);
    bool signedReq = false;
    ASSERT_EQ(HITLS_OCSP_ReqIsSigned(req, &signedReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(signedReq);

    /* Signer is the embedded OCSP Intermediate CA; its chain (intermediate -> root) validates
     * against a storeCtx trusting the preset OCSP Root CA. */
    BSL_Buffer rootBuf = {(uint8_t *)g_rootCaDer, sizeof(g_rootCaDer)};
    HITLS_X509_Cert *rootCert = NULL;
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &rootBuf, &rootCert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(rootCert != NULL);
    HITLS_X509_StoreCtx *storeCtx = OcspTestNewStoreCtx(rootCert);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(req, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(rootCert);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC047: Re-sign the preset signed request with openHiTLS and compare the
 * TBSRequest (all data except the signature value). */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_REQ_SIGN_COMPARE_PREDATA_TC047(void)
{
#ifdef HITLS_PKI_OCSP
    BSL_Buffer newDer = {0};
    HITLS_X509_List *certs = NULL;
    HITLS_X509_Cert *reqCert = NULL;
    CRYPT_EAL_PkeyCtx *reqKey = NULL;
    HITLS_OCSP_Req *req = NULL;
    HITLS_X509_Cert *ica = NULL;
    HITLS_X509_Cert *ee = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    BSL_Buffer eeBuf = {(uint8_t *)g_eeDer, sizeof(g_eeDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &eeBuf, &ee), HITLS_PKI_SUCCESS);
    BSL_Buffer icaBuf = {(uint8_t *)g_icaDer, sizeof(g_icaDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &icaBuf, &ica), HITLS_PKI_SUCCESS);

    /* Same inputs as the Pre-generated request: SHA-1 CertID (ee/ica), nonce,
     * requestorName = "OCSP Intermediate CA" subject DN. The signing key must match the
     * requestor certificate, so generate a cert with the same CN and sign with its key. */
    static const uint8_t presetNonce[16] = {0xD7, 0x10, 0x45, 0xBF, 0xDD, 0xEE, 0x63, 0xDD,
                                            0x6B, 0x30, 0xD1, 0x0A, 0xF7, 0xF2, 0x24, 0xFB};
    req = OcspTestBuildReq(CRYPT_MD_SHA1, ee, ica, NULL, NULL, presetNonce, sizeof(presetNonce));
    ASSERT_TRUE(req != NULL);

    ASSERT_EQ(OcspTestGenKey(&reqKey), 0);
    ASSERT_EQ(OcspTestCreateCert(&reqCert, reqKey, NULL, reqKey, "OCSP Intermediate CA", false), 0);
    ASSERT_TRUE(reqCert != NULL);

    certs = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(certs != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(certs, reqCert, BSL_LIST_POS_END), BSL_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, reqKey, NULL, reqCert, certs, req, 0), HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &newDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(newDer.data != NULL);

    const uint8_t *tbsNew = NULL;
    const uint8_t *tbsPreset = NULL;
    uint32_t tbsNewLen = 0;
    uint32_t tbsPresetLen = 0;
    ASSERT_EQ(OcspTestExtractReqTbs(newDer.data, newDer.dataLen, &tbsNew, &tbsNewLen), 0);
    ASSERT_EQ(OcspTestExtractReqTbs(g_reqSignedSha256Der, sizeof(g_reqSignedSha256Der), &tbsPreset, &tbsPresetLen),
              0);
    ASSERT_EQ(tbsNewLen, tbsPresetLen);
    ASSERT_EQ(memcmp(tbsNew, tbsPreset, tbsPresetLen), 0);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(newDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_X509_CertFree(reqCert);
    CRYPT_EAL_PkeyFreeCtx(reqKey);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(ica);
    BSL_LIST_FREE(certs, FreeListData);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC048: BasicRespSign with signer cert — key-match check, internal responderId,
 *        producedAt auto-generation/config, and signer cert embedding. */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_BASICRESP_SIGN_SIGNER_TC048(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_BasicResp *bs4 = NULL;
    HITLS_OCSP_SingleResp *sr3 = NULL;
    HITLS_OCSP_BasicResp *bs3 = NULL;
    CRYPT_EAL_PkeyCtx *wrongKey = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a signed BasicResp using the chain1 intermediate as signer (key matches). */
    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);

    bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;

    /* 1. Signing with a mismatched private key must be rejected. */
    ASSERT_EQ(OcspTestGenKey(&wrongKey), 0);
    ASSERT_NE(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, wrongKey, NULL, g_chain1.intermediate, NULL, bs, 0),
              HITLS_PKI_SUCCESS);

    /* 2. Sign with the matching key (default byName responderId, producedAt auto-generated). */
     ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                        bs, 0),
               HITLS_PKI_SUCCESS);
     BSL_TIME producedAt = {0};
     ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_GET_PRODUCED_AT, &producedAt, sizeof(producedAt)),
               HITLS_PKI_SUCCESS);
     ASSERT_TRUE(producedAt.year > 2000);

     /* 3. byKey responderId flag produces a valid signed response. */
    bs3 = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs3 != NULL);
    sr3 = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr3 != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs3, HITLS_OCSP_BASICRESP_ADD_RESP, sr3, sizeof(sr3)), HITLS_PKI_SUCCESS);
    sr3 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                       bs3, HITLS_OCSP_SIGN_RESPID_BYKEY),
              HITLS_PKI_SUCCESS);

    /* 5. Unknown flag must be rejected. */
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                       bs3, HITLS_OCSP_SIGN_RESPID_BYKEY | 0x80000000),
              HITLS_OCSP_ERR_INVALID_PARAM);

    /* 6. NULL signerCert must be rejected. */
    bs4 = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs4 != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, NULL, NULL, bs4, 0),
              HITLS_OCSP_ERR_NULL_POINTER);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(wrongKey);
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_BasicRespFree(bs3);
    HITLS_OCSP_BasicRespFree(bs4);
    HITLS_OCSP_SingleRespFree(sr3);
    HITLS_OCSP_SingleRespFree(sr);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC049: TRUSTOTHER treats an external signer certificate as a locally configured OCSP
 * signing authority (RFC 6960 §4.2.2.2 condition 1): chain validation and the
 * issuer/delegation authorization check are skipped. */
/* BEGIN_CASE */
void SDV_OCSP_NEWAPI_BASICRESP_VERIFY_TRUSTOTHER_AUTH_TC049(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_X509_List *extCerts = NULL;
    HITLS_OCSP_Resp *parsedResp2 = NULL;
    BSL_Buffer resp2Der = {0};
    HITLS_OCSP_Resp *resp2 = NULL;
    HITLS_X509_List *badCerts = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *unrelatedCert = NULL;
    HITLS_X509_List *goodCerts = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_SingleResp *sr = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a signed BasicResp using chain1's intermediate as the signer (direct issuer). */
    sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                       bs, HITLS_OCSP_SIGN_NOCERTS),
              HITLS_PKI_SUCCESS);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
              HITLS_PKI_SUCCESS);

    /* Positive control: the real issuer cert passed as external with TRUSTOTHER verifies. */
    goodCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(goodCerts != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(goodCerts, g_chain1.intermediate, BSL_LIST_POS_END), BSL_SUCCESS);
    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, goodCerts, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER),
              HITLS_PKI_SUCCESS);

    /* A signer certificate that does not match the ResponderID cannot be located at all:
     * build a cert from chain2 unrelated to the target (chain1.ee), whose key does not
     * hash to the response's ResponderID. Even with TRUSTOTHER the signer must first be
     * found, so this fails with SIGNER_NOT_FOUND. */
    ASSERT_EQ(OcspTestCreateCert(&unrelatedCert, g_chain2.intermediateKey, g_chain2.root, g_chain2.rootKey,
                                 "Unrelated Responder", false),
              0);
    ASSERT_TRUE(unrelatedCert != NULL);
    badCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(badCerts != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(badCerts, unrelatedCert, BSL_LIST_POS_END), BSL_SUCCESS);
    /* The unrelated cert's key does not match the ResponderID (which hashes the real
     * signer key), so the signer is not located at all. */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, badCerts, storeCtx, HITLS_OCSP_VFY_TRUSTOTHER),
              HITLS_OCSP_ERR_SIGNER_NOT_FOUND);

    /* TRUSTOTHER treats an external signer as a locally configured signing authority
     * (RFC 6960 condition 1): even a signer that is NOT the CertID issuer is accepted
     * when it is found in the external certs. Without TRUSTOTHER the same response must
     * be rejected (chain verification / authorization). Build a response whose CertID
     * issuer is chain2 while the signer is chain1's intermediate. */
    HITLS_OCSP_SingleResp *sr2 =
        OcspTestCreateSingleResp(g_mdCtx, g_chain2.ee, g_chain2.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(sr2 != NULL);
    HITLS_OCSP_BasicResp *bs2 = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs2 != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs2, HITLS_OCSP_BASICRESP_ADD_RESP, sr2, sizeof(sr2)), HITLS_PKI_SUCCESS);
    sr2 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                       bs2, HITLS_OCSP_SIGN_NOCERTS),
              HITLS_PKI_SUCCESS);
    resp2 = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs2);
    ASSERT_TRUE(resp2 != NULL);
    bs2 = NULL;
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp2, &resp2Der), HITLS_PKI_SUCCESS);
    BSL_Buffer parse2Buf = {resp2Der.data, resp2Der.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parse2Buf, &parsedResp2), HITLS_PKI_SUCCESS);
    HITLS_OCSP_BasicResp *parsedBs2 = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp2, HITLS_OCSP_RESP_GET_BASIC, &parsedBs2, sizeof(parsedBs2)),
              HITLS_PKI_SUCCESS);

    extCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_TRUE(extCerts != NULL);
    ASSERT_EQ(BSL_LIST_AddElement(extCerts, g_chain1.intermediate, BSL_LIST_POS_END), BSL_SUCCESS);
    /* With TRUSTOTHER: external signer found -> accepted as locally configured authority. */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs2, extCerts, NULL, HITLS_OCSP_VFY_TRUSTOTHER), HITLS_PKI_SUCCESS);
    /* Without TRUSTOTHER: signer is not the CertID issuer -> rejected. */
    ASSERT_NE(HITLS_OCSP_BasicRespVerify(parsedBs2, extCerts, NULL, 0), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(resp2Der.data);
    HITLS_OCSP_SingleRespFree(sr);
    HITLS_OCSP_RespFree(parsedResp2);
    HITLS_OCSP_RespFree(resp2);
    BSL_LIST_FREE(extCerts, FreeListData);
    HITLS_X509_CertFree(unrelatedCert);
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(goodCerts, FreeListData);
    BSL_LIST_FREE(badCerts, FreeListData);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_CERTID_CMP_TC050(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_CertId *cid3 = NULL;
    HITLS_OCSP_CertId *cid2 = NULL;
    HITLS_OCSP_CertId *cid1 = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    cid1 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid1 != NULL);
    cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid2 != NULL);
    cid3 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain2.ee, g_chain2.intermediate);
    ASSERT_TRUE(cid3 != NULL);

    /* Identical CertIDs match. */
    ASSERT_EQ(HITLS_OCSP_CertIdCmp(cid1, cid2), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_CertIdCmp(cid2, cid1), HITLS_PKI_SUCCESS);

    /* Different issuer (different cert chain) does not match. */
    ASSERT_NE(HITLS_OCSP_CertIdCmp(cid1, cid3), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_OCSP_CertIdCmp(cid3, cid1), HITLS_PKI_SUCCESS);

    /* NULL inputs are not equal. */
    ASSERT_NE(HITLS_OCSP_CertIdCmp(NULL, cid1), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_OCSP_CertIdCmp(cid1, NULL), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_OCSP_CertIdCmp(NULL, NULL), HITLS_PKI_SUCCESS);

    /* Exercise the print APIs on the created request/response to catch crashes. */
    HITLS_OCSP_SingleReq *sr = HITLS_OCSP_SingleReqNew(cid1);
    ASSERT_TRUE(sr != NULL);
    cid1 = NULL; /* ownership transferred to sr */
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL; /* ownership transferred to req */
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_CertIdFree(cid1);
    HITLS_OCSP_CertIdFree(cid2);
    HITLS_OCSP_CertIdFree(cid3);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RSA_PSS_TC051(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    OcspTestCertChain pssChain = {0};
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* RSA-PSS certificate chain, valid for 30 years. */
    ASSERT_EQ(OcspTestCreatePssCertChain(&pssChain, 30), 0);

    storeCtx = OcspTestNewStoreCtx(pssChain.root);
    ASSERT_TRUE(storeCtx != NULL);

    /* The PSS chain certificates must be valid for 30 years. */
    BSL_TIME notBefore = {0};
    BSL_TIME notAfter = {0};
    ASSERT_EQ(HITLS_X509_CertCtrl(pssChain.ee, HITLS_X509_GET_BEFORE_TIME, &notBefore, sizeof(BSL_TIME)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(pssChain.ee, HITLS_X509_GET_AFTER_TIME, &notAfter, sizeof(BSL_TIME)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(notAfter.year - notBefore.year, 30);

    HITLS_X509_SignAlgParam pssParam = {0};
    pssParam.algId = BSL_CID_RSASSAPSS;
    pssParam.rsaPss.saltLen = 32;
    pssParam.rsaPss.mdId = CRYPT_MD_SHA256;
    pssParam.rsaPss.mgfId = CRYPT_MD_SHA256;

    /* --- Request signed with RSA-PSS --- */
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, pssChain.ee, pssChain.intermediate);
    ASSERT_TRUE(cid != NULL);
    HITLS_OCSP_SingleReq *singleReq = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(singleReq != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, singleReq, sizeof(singleReq)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(
        HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, pssChain.intermediateKey, &pssParam, pssChain.intermediate, NULL, req, 0),
        HITLS_PKI_SUCCESS);
    bool isSigned = false;
    ASSERT_EQ(HITLS_OCSP_ReqIsSigned(req, &isSigned), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(isSigned);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(reqDer.data != NULL);

    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedReq != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsedReq, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);

    /* --- Response signed with RSA-PSS --- */
    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, pssChain.ee, pssChain.intermediate);
    ASSERT_TRUE(cid2 != NULL);
    HITLS_OCSP_SingleResp *sr = HITLS_OCSP_SingleRespNew(cid2, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, pssChain.intermediateKey, &pssParam, pssChain.intermediate,
                                       NULL, bs, 0),
              HITLS_PKI_SUCCESS);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);

    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedResp != NULL);
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
              HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedBs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_Free(reqDer.data);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_X509_StoreCtxFree(storeCtx);
    OcspTestFreeCertChain(&pssChain);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_SM2_KEY_REJECT_TC053(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP) && defined(HITLS_CRYPTO_SM2)
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_Req *req = NULL;
    CRYPT_EAL_PkeyCtx *sm2Key = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);

    /* Generate an SM2 key pair (random source registered via TestRandInit). */
    ASSERT_EQ(TestRandInit(), 0);
    sm2Key = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(sm2Key != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(sm2Key), CRYPT_SUCCESS);

    /* Build a request to sign. */
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    HITLS_OCSP_SingleReq *sr = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(sr != NULL);
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, sr, sizeof(sr)), HITLS_PKI_SUCCESS);

    /* SM2 signing keys are rejected: OCSP no longer supports SM2. */
    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SM3, sm2Key, NULL, g_chain1.ee, NULL, req, 0), HITLS_X509_ERR_ALG_UNSUPPORT);

    /* Same for response signing. */
    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    HITLS_OCSP_CertId *cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid2 != NULL);
    HITLS_OCSP_SingleResp *singleResp = HITLS_OCSP_SingleRespNew(cid2, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(singleResp != NULL);
    bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, singleResp, sizeof(singleResp)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SM3, sm2Key, NULL, g_chain1.ee, NULL, bs, 0),
              HITLS_X509_ERR_ALG_UNSUPPORT);

    /* Exercise the print API (no terminal output). */
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_ReqFree(req);
    CRYPT_EAL_PkeyFreeCtx(sm2Key);
    HITLS_X509_StoreCtxFree(storeCtx);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* Run the full OCSP request/response create+parse flow. Intended for memory-fault
 * injection tests: does NOT use ASSERT, returns non-zero on any failure and releases
 * all resources. */
static int32_t OcspTestMallocFlow(void)
{
    int32_t ret = -1;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_CertId *cid = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    HITLS_OCSP_Req *req = NULL;
    HITLS_X509_List *reqCerts = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *parsedReq = NULL;
    HITLS_OCSP_CertId *cid2 = NULL;
    HITLS_OCSP_SingleResp *singleResp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_X509_List *respCerts = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *parsedResp = NULL;

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    if (storeCtx == NULL) {
        goto EXIT;
    }

    /* --- Create request --- */
    cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    if (cid == NULL) {
        goto EXIT;
    }
    sr = HITLS_OCSP_SingleReqNew(cid);
    if (sr == NULL) {
        goto EXIT;
    }
    cid = NULL; /* ownership transferred */
    req = HITLS_OCSP_ReqNew();
    if (req == NULL) {
        goto EXIT;
    }
    if (HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, sr, sizeof(sr)) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    sr = NULL; /* ownership transferred */
    if (HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_SET_NONCE, NULL, 0) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    reqCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (reqCerts == NULL) {
        goto EXIT;
    }
    if (BSL_LIST_AddElement(reqCerts, g_chain1.intermediate, BSL_LIST_POS_END) != BSL_SUCCESS) {
        goto EXIT;
    }
    if (HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, reqCerts, req, 0) !=
        HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    /* --- Parse request --- */
    if (HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_Buffer reqParseBuf = {reqDer.data, reqDer.dataLen};
    if (HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &reqParseBuf, &parsedReq) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    bool isSigned = false;
    if (HITLS_OCSP_ReqIsSigned(parsedReq, &isSigned) != HITLS_PKI_SUCCESS || !isSigned) {
        goto EXIT;
    }
    uint32_t reqCount = 0;
    if (HITLS_OCSP_ReqGetSingleReqCount(parsedReq, &reqCount) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_SingleReq *parsedSr = NULL;
    if (HITLS_OCSP_ReqGetSingleReqByIndex(parsedReq, 0, &parsedSr) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_CertId *parsedCid = NULL;
    if (HITLS_OCSP_SingleReqGetCertId(parsedSr, &parsedCid) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    if (HITLS_OCSP_ReqVerify(parsedReq, NULL, storeCtx, 0) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }

    /* --- Create response --- */
    cid2 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    if (cid2 == NULL) {
        goto EXIT;
    }
    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    singleResp = HITLS_OCSP_SingleRespNew(cid2, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    if (singleResp == NULL) {
        goto EXIT;
    }
    if (HITLS_OCSP_CheckValidity(singleResp, 300, 3600) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    cid2 = NULL; /* ownership transferred */
    bs = HITLS_OCSP_BasicRespNew();
    if (bs == NULL) {
        goto EXIT;
    }
    if (HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, singleResp, sizeof(singleResp)) !=
        HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    singleResp = NULL; /* ownership transferred */
    respCerts = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (respCerts == NULL) {
        goto EXIT;
    }
    if (BSL_LIST_AddElement(respCerts, g_chain1.intermediate, BSL_LIST_POS_END) != BSL_SUCCESS) {
        goto EXIT;
    }
    if (HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, respCerts, bs,
                                 0) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_NonceStatus nonceStatus = HITLS_OCSP_NONCE_BOTH_ABSENT;
    if (HITLS_OCSP_CheckNonce(req, bs, &nonceStatus) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    if (resp == NULL) {
        goto EXIT;
    }
    bs = NULL; /* ownership transferred */

    /* --- Parse response --- */
    if (HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    BSL_Buffer respParseBuf = {respDer.data, respDer.dataLen};
    if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &respParseBuf, &parsedResp) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    int32_t respStatus = 0;
    if (HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_STATUS, &respStatus, sizeof(respStatus)) !=
        HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    if (HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    uint32_t respCount = 0;
    if (HITLS_OCSP_BasicRespGetRespCount(parsedBs, &respCount) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_SingleResp *parsedSingleResp = NULL;
    if (HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSingleResp) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_CertStatus certStatus = 0;
    if (HITLS_OCSP_SingleRespCtrl(parsedSingleResp, HITLS_OCSP_SINGLERESP_GET_CERT_STATUS, &certStatus,
                                  sizeof(certStatus)) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    if (HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0) != HITLS_PKI_SUCCESS) {
        goto EXIT;
    }
    HITLS_OCSP_BasicRespFindResp(parsedBs, parsedCid, &parsedSingleResp);
    HITLS_OCSP_CertIdGetInfo(parsedCid, NULL, NULL, NULL, NULL);
    HITLS_OCSP_CertIdCmp(parsedCid, parsedCid);
    HITLS_OCSP_CertStatusToStr(certStatus);
    HITLS_OCSP_RespStatusToStr((HITLS_OCSP_RespStatus)respStatus);
    HITLS_OCSP_RevocationReasonToStr(HITLS_X509_REVOKED_REASON_UNSPECIFIED);
    HITLS_OCSP_GetCertOcspUrls(g_chain1.ee, NULL);

    ret = 0;

EXIT:
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_SingleReqFree(sr);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_SingleRespFree(singleResp);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_CertIdFree(cid);
    HITLS_OCSP_CertIdFree(cid2);
    BSL_LIST_FREE(reqCerts, FreeListData);
    BSL_LIST_FREE(respCerts, FreeListData);
    HITLS_X509_StoreCtxFree(storeCtx);
    return ret;
}

/* BEGIN_CASE */
void SDV_OCSP_MALLOC_COUNT_TC054(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Pre-run to count the number of malloc calls across the full flow. */
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(OcspTestMallocFlow(), 0);
    uint32_t mallocCount = STUB_GetMallocCallCount();
    ASSERT_TRUE(mallocCount > 0);
    Print("OCSP full-flow malloc count: %u\n", mallocCount);

    /* Iteratively fail the i-th malloc; the flow must fail (or complete) without
     * crashing and must release all resources. Sampling every OCSP_MALLOC_FAIL_STEP
     * failure point keeps the runtime bounded while still covering the failure paths
     * (adjacent failure points behave nearly identically). The first and last failure
     * points are covered explicitly since the step loop may not hit them. */
#define OCSP_MALLOC_FAIL_STEP 5
    STUB_EnableMallocFail(true);

    /* First allocation fails (earliest cleanup path). */
    STUB_ResetMallocCount();
    STUB_SetMallocFailIndex(0);
    (void)OcspTestMallocFlow();

    /* Sampled failure points. */
    for (uint32_t i = OCSP_MALLOC_FAIL_STEP; i < mallocCount; i += OCSP_MALLOC_FAIL_STEP) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        (void)OcspTestMallocFlow();
    }

    /* Last allocation fails (full cleanup path). */
    STUB_ResetMallocCount();
    STUB_SetMallocFailIndex(mallocCount - 1);
    (void)OcspTestMallocFlow();

    STUB_RESTORE(BSL_SAL_Malloc);
EXIT:;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_ROOT_SIGNER_TC055(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_Cert *ee = NULL;
    HITLS_X509_Cert *root = NULL;
    CRYPT_EAL_PkeyCtx *eeKey = NULL;
    CRYPT_EAL_PkeyCtx *rootKey = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a chain where the root directly signs an EE cert, so an OCSP response
     * signed by the root has a single-cert built chain (the root itself). */
    ASSERT_EQ(OcspTestGenKey(&rootKey), 0);
    ASSERT_EQ(OcspTestGenKey(&eeKey), 0);
    ASSERT_EQ(OcspTestCreateCert(&root, rootKey, NULL, rootKey, "Root Direct CA", true), 0);
    ASSERT_EQ(OcspTestCreateCert(&ee, eeKey, root, rootKey, "Root Direct EE", false), 0);

    storeCtx = OcspTestNewStoreCtx(root);
    ASSERT_TRUE(storeCtx != NULL);

    /* CertID references the root-signed EE, so the root is the CertID issuer. */
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, ee, root);
    ASSERT_TRUE(cid != NULL);
    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    HITLS_OCSP_SingleResp *sr = HITLS_OCSP_SingleRespNew(cid, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(sr != NULL);
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, rootKey, NULL, root, NULL, bs, 0), HITLS_PKI_SUCCESS);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(respDer.data != NULL);
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
              HITLS_PKI_SUCCESS);

    /* Root-signed response must verify: the built chain is [root] (1 cert), and the
     * root is the CertID issuer (authorization condition 1). */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);

EXIT:
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
    HITLS_X509_StoreCtxFree(storeCtx);
    HITLS_X509_CertFree(ee);
    HITLS_X509_CertFree(root);
    CRYPT_EAL_PkeyFreeCtx(eeKey);
    CRYPT_EAL_PkeyFreeCtx(rootKey);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_MULTI_HASH_TC056(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a BasicOCSPResponse whose two SingleResponses use different CertID hash
     * algorithms (SHA-1 and SHA-256) for the same issuer (chain1 intermediate).
     * OcspCheckIds leaves outCertId NULL on hash-algorithm mismatch, and the signer
     * must be authorized against each CertID individually (OcspBsMatchIssuerId). */
    CRYPT_EAL_MdCtx *sha1Ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(sha1Ctx != NULL);
    HITLS_OCSP_CertId *cidSha1 = HITLS_OCSP_CertIdNewFromCert(sha1Ctx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cidSha1 != NULL);
    CRYPT_EAL_MdFreeCtx(sha1Ctx);
    HITLS_OCSP_CertId *cidSha256 = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cidSha256 != NULL);

    BSL_TIME now = {0};
    BSL_SAL_SysTimeGet(&now);
    HITLS_OCSP_SingleResp *sr1 = HITLS_OCSP_SingleRespNew(cidSha1, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(sr1 != NULL);
    HITLS_OCSP_SingleResp *sr2 = HITLS_OCSP_SingleRespNew(cidSha256, HITLS_OCSP_CERT_STATUS_REVOKED, &now);
    ASSERT_TRUE(sr2 != NULL);
    BSL_TIME revTime = now;
    revTime.hour -= 1;
    int32_t revReason = HITLS_X509_REVOKED_REASON_KEY_COMPROMISE;
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(sr2, HITLS_OCSP_SINGLERESP_SET_REVOCATION_TIME, &revTime, sizeof(revTime)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(
        HITLS_OCSP_SingleRespCtrl(sr2, HITLS_OCSP_SINGLERESP_SET_REVOCATION_REASON, &revReason, sizeof(revReason)),
        HITLS_PKI_SUCCESS);

    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr1, sizeof(sr1)), HITLS_PKI_SUCCESS);
    sr1 = NULL;
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr2, sizeof(sr2)), HITLS_PKI_SUCCESS);
    sr2 = NULL;
    ASSERT_EQ(
        HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL, bs, 0),
        HITLS_PKI_SUCCESS);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
              HITLS_PKI_SUCCESS);

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);
    /* The signer (chain1 intermediate) is the issuer of BOTH CertIDs (SHA-1 and SHA-256),
     * so the multi-hash response must verify. */
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);

    // Exercise the print APIs on the created request/response (no terminal output).
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_REQ_BYTE_MUTATE_TC057(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_OCSP_Req *parsedReq = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    BSL_Buffer reqDer = {0};
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a signed, correct OCSP request for chain1's EE (issuer = chain1 intermediate). */
    HITLS_OCSP_CertId *certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(certId != NULL);
    HITLS_OCSP_SingleReq *singleReq = HITLS_OCSP_SingleReqNew(certId);
    ASSERT_TRUE(singleReq != NULL);
    certId = NULL; /* ownership transferred */
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, singleReq, sizeof(singleReq)), HITLS_PKI_SUCCESS);
    singleReq = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL, req, 0),
              HITLS_PKI_SUCCESS);

    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);

    /* Sanity: the unmutated request parses and verifies. */
    BSL_Buffer parseBuf = {reqDer.data, reqDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_ReqVerify(parsedReq, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(parsedReq), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
    HITLS_OCSP_ReqFree(parsedReq);
    parsedReq = NULL;

    /* For each byte: +1, then parse and (on success) verify. Any outcome must not crash. */
    for (uint32_t i = 0; i < reqDer.dataLen; i++) {
        uint8_t orig = reqDer.data[i];
        reqDer.data[i] = (uint8_t)(orig + 1);
        parsedReq = NULL;
        BSL_Buffer mutBuf = {reqDer.data, reqDer.dataLen};
        if (HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &mutBuf, &parsedReq) == HITLS_PKI_SUCCESS) {
            (void)HITLS_OCSP_ReqVerify(parsedReq, NULL, storeCtx, 0);
            HITLS_OCSP_ReqFree(parsedReq);
            parsedReq = NULL;
        }
        reqDer.data[i] = orig;
    }

EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_SAL_Free(reqDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_ReqFree(parsedReq);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_RESP_BYTE_MUTATE_TC058(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_OCSP_Resp *parsedResp = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    BSL_Buffer respDer = {0};
    HITLS_OCSP_Resp *resp = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a signed, correct OCSP response for chain1's EE (signer = chain1 intermediate). */
    HITLS_OCSP_SingleResp *singleResp =
        OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(singleResp != NULL);
    HITLS_OCSP_BasicResp *bs =
        OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, &singleResp, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    singleResp = NULL; /* ownership transferred */
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);

    /* Sanity: the unmutated response parses and verifies. */
    BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);
    HITLS_OCSP_BasicResp *parsedBs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
    ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);
    HITLS_OCSP_RespFree(parsedResp);
    parsedResp = NULL;

    /* For each byte: +1, then parse and (on success) verify. Any outcome must not crash. */
    for (uint32_t i = 0; i < respDer.dataLen; i++) {
        uint8_t orig = respDer.data[i];
        respDer.data[i] = (uint8_t)(orig + 1);
        parsedResp = NULL;
        BSL_Buffer mutBuf = {respDer.data, respDer.dataLen};
        if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &mutBuf, &parsedResp) == HITLS_PKI_SUCCESS) {
            HITLS_OCSP_BasicResp *mutBs = NULL;
            if (HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &mutBs, sizeof(mutBs)) ==
                HITLS_PKI_SUCCESS) {
                (void)HITLS_OCSP_BasicRespVerify(mutBs, NULL, storeCtx, 0);
            }
            HITLS_OCSP_RespFree(parsedResp);
            parsedResp = NULL;
        }
        respDer.data[i] = orig;
    }

EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsedResp);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_CERTID_SHA_VERIFY_TC059(void)
{
#if defined(HITLS_PKI_INFO_OCSP) && defined(HITLS_PKI_OCSP)
    HITLS_X509_StoreCtx *storeCtx = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* CertID generation keeps supporting only SHA1/SHA256; parsing and verification
     * accept SHA224/SHA384/SHA512 as well. */
    const int32_t algs[] = {CRYPT_MD_SHA224, CRYPT_MD_SHA384, CRYPT_MD_SHA512};
    const uint32_t hashLens[] = {28, 48, 64};
    storeCtx = OcspTestNewStoreCtx(g_chain1.root);
    ASSERT_TRUE(storeCtx != NULL);

    for (uint32_t k = 0; k < sizeof(algs) / sizeof(algs[0]); k++) {
        CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx((CRYPT_MD_AlgId)algs[k]);
        ASSERT_TRUE(mdCtx != NULL);

        /* Generation rejects the algorithm. */
        HITLS_OCSP_CertId *rejected = HITLS_OCSP_CertIdNewFromCert(mdCtx, g_chain1.ee, g_chain1.intermediate);
        ASSERT_TRUE(rejected == NULL);

        /* Build a CertID with this algorithm via internal fields. */
        HITLS_OCSP_CertId_Internal *cid = BSL_SAL_Calloc(1, sizeof(HITLS_OCSP_CertId_Internal));
        ASSERT_TRUE(cid != NULL);
        cid->hashAlg = (CRYPT_MD_AlgId)algs[k];
        uint8_t hash[64] = {0};
        uint32_t hashLen = sizeof(hash);
        ASSERT_EQ(OcspGetIssuerNameHash(mdCtx, g_chain1.intermediate, hash, &hashLen), HITLS_PKI_SUCCESS);
        ASSERT_EQ(OcspSetHashField((CRYPT_MD_AlgId)algs[k], &cid->issuerNameHash, hash, hashLen), HITLS_PKI_SUCCESS);
        hashLen = sizeof(hash);
        ASSERT_EQ(OcspGetPubKeyHash(mdCtx, g_chain1.intermediate, hash, &hashLen), HITLS_PKI_SUCCESS);
        ASSERT_EQ(OcspSetHashField((CRYPT_MD_AlgId)algs[k], &cid->issuerKeyHash, hash, hashLen), HITLS_PKI_SUCCESS);
        BSL_Buffer serial = {0};
        ASSERT_EQ(HITLS_X509_CertCtrl(g_chain1.ee, HITLS_X509_GET_SERIALNUM, &serial, sizeof(BSL_Buffer)),
                  HITLS_PKI_SUCCESS);
        cid->serialNumber.buff = BSL_SAL_Dump(serial.data, serial.dataLen);
        ASSERT_TRUE(cid->serialNumber.buff != NULL);
        cid->serialNumber.len = serial.dataLen;

        BSL_TIME now = {0};
        BSL_SAL_SysTimeGet(&now);
        HITLS_OCSP_SingleResp *sr =
            HITLS_OCSP_SingleRespNew((HITLS_OCSP_CertId *)cid, HITLS_OCSP_CERT_STATUS_GOOD, &now);
        ASSERT_TRUE(sr != NULL);
        cid = NULL;

        HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
        ASSERT_TRUE(bs != NULL);
        ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
        sr = NULL;
        ASSERT_EQ(HITLS_OCSP_BasicRespSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL,
                                           bs, 0),
                  HITLS_PKI_SUCCESS);
        HITLS_OCSP_Resp *resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
        ASSERT_TRUE(resp != NULL);
        bs = NULL;

        BSL_Buffer respDer = {0};
        ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);
        HITLS_OCSP_Resp *parsedResp = NULL;
        BSL_Buffer parseBuf = {respDer.data, respDer.dataLen};
        ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &parseBuf, &parsedResp), HITLS_PKI_SUCCESS);
        HITLS_OCSP_BasicResp *parsedBs = NULL;
        ASSERT_EQ(HITLS_OCSP_RespCtrl(parsedResp, HITLS_OCSP_RESP_GET_BASIC, &parsedBs, sizeof(parsedBs)),
                  HITLS_PKI_SUCCESS);

        /* Parsed CertID carries the algorithm and the matching hash length. */
        HITLS_OCSP_SingleResp *parsedSr = NULL;
        ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(parsedBs, 0, &parsedSr), HITLS_PKI_SUCCESS);
        HITLS_OCSP_CertId *parsedCertId = NULL;
        ASSERT_EQ(
            HITLS_OCSP_SingleRespCtrl(parsedSr, HITLS_OCSP_SINGLERESP_GET_CERTID, &parsedCertId, sizeof(parsedCertId)),
            HITLS_PKI_SUCCESS);
        CRYPT_MD_AlgId parsedAlg = 0;
        BSL_Buffer nameHash = {0};
        BSL_Buffer keyHash = {0};
        BSL_Buffer parsedSerial = {0};
        ASSERT_EQ(HITLS_OCSP_CertIdGetInfo(parsedCertId, &parsedAlg, &nameHash, &keyHash, &parsedSerial),
                  HITLS_PKI_SUCCESS);
        ASSERT_EQ(parsedAlg, (CRYPT_MD_AlgId)algs[k]);
        ASSERT_EQ(nameHash.dataLen, hashLens[k]);
        ASSERT_EQ(keyHash.dataLen, hashLens[k]);

        /* Verification with this hash algorithm succeeds. */
        ASSERT_EQ(HITLS_OCSP_BasicRespVerify(parsedBs, NULL, storeCtx, 0), HITLS_PKI_SUCCESS);

        /* Exercise the print APIs (no terminal output). */
        ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
        ASSERT_EQ(OcspTestPrintResp(parsedResp), HITLS_PKI_SUCCESS);

        BSL_SAL_Free(respDer.data);
        HITLS_OCSP_RespFree(parsedResp);
        HITLS_OCSP_RespFree(resp);
        HITLS_OCSP_SingleRespFree(sr);
        CRYPT_EAL_MdFreeCtx(mdCtx);
    }

EXIT:
    HITLS_X509_StoreCtxFree(storeCtx);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC060: ReqParseBuff -> ReqGenBuff must preserve the RFC 6960 Request optional field
 * singleRequestExtensions [0]. The encoder used to drop it after parsing. */
/* BEGIN_CASE */
void SDV_OCSP_SINGLEREQ_EXT_ROUNDTRIP_TC060(void)
{
#ifdef HITLS_PKI_OCSP
    /* OCSPRequest ::= SEQUENCE { TBSRequest } with a Request carrying
     * singleRequestExtensions [0] = Extensions { Extension { extnID 1.2.3.4, value "A" } }. */
    uint8_t der[] = {0x30, 0x50, 0x30, 0x4e, 0x30, 0x4c, 0x30, 0x4a, 0x30, 0x3a, 0x30, 0x09, 0x06, 0x05,
                     0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04,
                     0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                     0x13, 0x04, 0x14, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                     0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x02, 0x01, 0x01, 0xa0, 0x0c,
                     0x30, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x01, 0x41};
    BSL_Buffer in = {der, sizeof(der)};
    HITLS_OCSP_Req *req = NULL;
    BSL_Buffer out = {0};
    ASSERT_EQ(HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &in, &req), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(req != NULL);

    /* Re-encoding must reproduce the [0] singleRequestExtensions byte-for-byte. */
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &out), HITLS_PKI_SUCCESS);
    ASSERT_EQ(out.dataLen, sizeof(der));
    ASSERT_EQ(memcmp(out.data, der, sizeof(der)), 0);
    ASSERT_EQ(OcspTestPrintReq(req), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(out.data);
    HITLS_OCSP_ReqFree(req);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* TC061: RespParseBuff -> RespGenBuff must preserve the RFC 6960 SingleResponse optional
 * field singleExtensions [1]. The encoder used to drop it after parsing.
 * Note: the re-encoded response is not byte-identical to the input because the signature
 * AlgorithmIdentifier NULL parameter is re-encoded without the NULL for SHA-1 (a separate,
 * pre-existing behaviour); this test therefore asserts the [1] extension itself survives. */
/* BEGIN_CASE */
void SDV_OCSP_SINGLERESP_EXT_ROUNDTRIP_TC061(void)
{
#ifdef HITLS_PKI_OCSP
    /* BasicOCSPResponse with a SingleResponse carrying singleExtensions [1] =
     * Extensions { Extension { extnID 1.2.3.4, value 0x42 } }, plus a 1-byte signature. */
    uint8_t der[] = {
        0x30, 0x81, 0xaf, 0x0a, 0x01, 0x00, 0xa0, 0x81, 0xa9, 0x30, 0x81, 0xa6, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x81, 0x98, 0x30, 0x81, 0x95, 0x30, 0x81, 0x83, 0xa1, 0x0f, 0x30, 0x0d,
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, 0x43, 0x41, 0x18, 0x0f, 0x32, 0x30, 0x32,
        0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x5f, 0x30, 0x5d, 0x30, 0x3a,
        0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x04, 0x14, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27, 0x02, 0x01, 0x01, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5a, 0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x01,
        0x42, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x03, 0x02, 0x00, 0x41};
    /* singleExtensions [1] = Extensions { Extension { extnID 1.2.3.4, value "B" } } */
    uint8_t extMarker[] = {0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x01, 0x42};
    BSL_Buffer in = {der, sizeof(der)};
    HITLS_OCSP_Resp *resp = NULL;
    BSL_Buffer out = {0};
    bool found = false;
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &in, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);

    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &out), HITLS_PKI_SUCCESS);
    for (uint32_t i = 0; i + sizeof(extMarker) <= out.dataLen; i++) {
        if (memcmp(out.data + i, extMarker, sizeof(extMarker)) == 0) {
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
    ASSERT_EQ(OcspTestPrintResp(resp), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(out.data);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* ============================================================================
 * OCSP-HTTP adapter layer (AR-001 §3.1.8 / §8.5)
 * ============================================================================ */

/* Build a one-SingleRequest OCSP request from the shared cert fixtures. */
static HITLS_OCSP_Req *OcspHttpBuildReq(void)
{
    HITLS_OCSP_CertId *certId = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    if (certId == NULL) {
        return NULL;
    }
    HITLS_OCSP_SingleReq *sr = HITLS_OCSP_SingleReqNew(certId);
    if (sr == NULL) {
        HITLS_OCSP_CertIdFree(certId);
        return NULL;
    }
    HITLS_OCSP_Req *req = HITLS_OCSP_ReqNew();
    if (req == NULL) {
        HITLS_OCSP_SingleReqFree(sr);
        return NULL;
    }
    if (HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)) != HITLS_PKI_SUCCESS) {
        HITLS_OCSP_SingleReqFree(sr);
        HITLS_OCSP_ReqFree(req);
        return NULL;
    }
    return req;
}

/* DER-encode a non-successful OCSPResponse (no BasicOCSPResponse). */
static int32_t OcspHttpBuildRespDer(BSL_Buffer *der)
{
    HITLS_OCSP_Resp *resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR, NULL);
    if (resp == NULL) {
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, der);
    HITLS_OCSP_RespFree(resp);
    return ret;
}

/* Wrap a DER body into a minimal HTTP/1.0 200 response with the OCSP content type. */
static uint8_t *OcspHttpWrapResp(const uint8_t *der, uint32_t derLen, uint32_t *outLen)
{
    char head[160];
    int n =
        snprintf(head, sizeof(head),
                 "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: %u\r\n\r\n", derLen);
    if (n <= 0 || (uint32_t)n >= sizeof(head)) {
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)n + derLen);
    if (buf == NULL) {
        return NULL;
    }
    (void)memcpy(buf, head, (size_t)n);
    (void)memcpy(buf + n, der, derLen);
    *outLen = (uint32_t)n + derLen;
    return buf;
}

/* Parse an absolute HTTP(S) URL into host (authority without port), port and path.
 * Only "http://" / "https://" schemes are accepted; the port defaults to 80/443 and
 * a missing path defaults to "/". Returns HITLS_PKI_SUCCESS on success. */
static int32_t OcspHttpParseUrl(const char *url, char *host, uint32_t hostCap, uint16_t *port, char *path,
                                uint32_t pathCap)
{
    if (url == NULL || host == NULL || port == NULL || path == NULL) {
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    const char *p;
    if (strncmp(url, "http://", 7) == 0) {
        *port = 80;
        p = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        *port = 443;
        p = url + 8;
    } else {
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    const char *q = p;
    while (*q != '\0' && *q != ':' && *q != '/') {
        q++;
    }
    size_t hostLen = (size_t)(q - p);
    if (hostLen == 0 || hostLen >= hostCap) {
        return HITLS_OCSP_ERR_INVALID_PARAM;
    }
    (void)memcpy(host, p, hostLen);
    host[hostLen] = '\0';
    if (*q == ':') {
        const char *portStart = q + 1;
        const char *r = portStart;
        while (*r != '\0' && *r != '/') {
            r++;
        }
        size_t portLen = (size_t)(r - portStart);
        if (portLen == 0 || portLen >= 8) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        char portBuf[8];
        (void)memcpy(portBuf, portStart, portLen);
        portBuf[portLen] = '\0';
        int pv = atoi(portBuf);
        if (pv <= 0 || pv > 65535) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        *port = (uint16_t)pv;
        q = r;
    }
    if (*q == '/') {
        size_t pathLen = strlen(q);
        if (pathLen >= pathCap) {
            return HITLS_OCSP_ERR_INVALID_PARAM;
        }
        (void)memcpy(path, q, pathLen);
        path[pathLen] = '\0';
    } else {
        (void)memcpy(path, "/", 2);
    }
    return HITLS_PKI_SUCCESS;
}

/* Mock hostname resolver: the hermetic suite must not hit the real DNS, so the
 * well-known test hostnames map to fixed addresses (the stub UIO never connects
 * anywhere). */
typedef struct {
    const char *name;
    uint8_t ip[16];
    uint32_t ipLen;
} OcspHttpHostEntry;

static const OcspHttpHostEntry g_ocspHttpHosts[] = {
    {"status.geotrust.com", {10, 1, 2, 3}, 4},
    {"ocsp.example.org", {10, 1, 2, 4}, 4},
};

static int32_t OcspHttpHostToIp(const char *host, uint8_t ip[16], uint32_t *ipLen)
{
    if (host == NULL || ip == NULL || ipLen == NULL) {
        return HITLS_OCSP_ERR_NULL_POINTER;
    }
    for (size_t i = 0; i < sizeof(g_ocspHttpHosts) / sizeof(g_ocspHttpHosts[0]); i++) {
        if (strcmp(g_ocspHttpHosts[i].name, host) == 0) {
            (void)memcpy(ip, g_ocspHttpHosts[i].ip, g_ocspHttpHosts[i].ipLen);
            *ipLen = g_ocspHttpHosts[i].ipLen;
            return HITLS_PKI_SUCCESS;
        }
    }
    return HITLS_OCSP_ERR_INVALID_PARAM;
}

/**
 * @test  SDV_OCSP_HTTP_TC001
 * @title  OCSP-HTTP ReqCtxNew main path
 * @precon  nan
 * @brief
 *    1. Build an OCSP request and a stub UIO.
 *    2. Call HITLS_OCSP_HttpReqCtxNew(uio, path, req).
 * @expect
 *    1. The request and UIO are created successfully.
 *    2. Return a non-NULL context.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC001(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
EXIT:
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC002
 * @title  OCSP-HTTP ReqCtxNew with NULL parameters
 * @precon  nan
 * @brief
 *    1. Build an OCSP request and a stub UIO.
 *    2. Call HITLS_OCSP_HttpReqCtxNew with NULL uio, NULL path and NULL req.
 * @expect
 *    1. The request and UIO are created successfully.
 *    2. All NULL combinations return NULL.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC002(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_TRUE(HITLS_OCSP_HttpReqCtxNew(NULL, "/responder/ocsp", req) == NULL);
    ASSERT_TRUE(HITLS_OCSP_HttpReqCtxNew(uio, NULL, req) == NULL);
    ASSERT_TRUE(HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", NULL) == NULL);
EXIT:
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC003
 * @title  OCSP-HTTP HttpReqCtxExchange round trip
 * @precon  nan
 * @brief
 *    1. Build an OCSP request and a canned HTTP response wrapping a non-successful OCSPResponse.
 *    2. Create the context and call HITLS_OCSP_HttpReqCtxExchange once (the stub
 *       delivers everything in one step).
 * @expect
 *    1. The response is set up and the context created successfully.
 *    2. HttpReqCtxExchange returns HITLS_PKI_SUCCESS, the parsed response status matches,
 *       and the request on the wire carries the OCSP request line, content type and
 *       content length.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC003(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    BSL_Buffer respDer = {0};
    uint8_t *payload = NULL;
    uint32_t payloadLen = 0;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(OcspHttpBuildRespDer(&respDer), HITLS_PKI_SUCCESS);
    payload = OcspHttpWrapResp(respDer.data, respDer.dataLen, &payloadLen);
    ASSERT_TRUE(payload != NULL);
    HttpTestSetResponseBuf(payload, payloadLen);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsed, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR);
    ASSERT_TRUE(HttpTestWrittenContains("POST /responder/ocsp HTTP/1.0\r\n"));
    ASSERT_TRUE(HttpTestWrittenContains("Content-Type: application/ocsp-request\r\n"));
EXIT:
    free(payload);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC004
 * @title  OCSP-HTTP HttpReqCtxExchange non-blocking in progress
 * @precon  nan
 * @brief
 *    1. Build a request and a canned response; make the first write block.
 *    2. Call HITLS_OCSP_HttpReqCtxExchange(ctx, resp) twice.
 * @expect
 *    1. The response is set up and the context created successfully.
 *    2. The first call returns HITLS_OCSP_ERR_IN_PROGRESS and the retry returns HITLS_PKI_SUCCESS.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC004(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    BSL_Buffer respDer = {0};
    uint8_t *payload = NULL;
    uint32_t payloadLen = 0;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(OcspHttpBuildRespDer(&respDer), HITLS_PKI_SUCCESS);
    payload = OcspHttpWrapResp(respDer.data, respDer.dataLen, &payloadLen);
    ASSERT_TRUE(payload != NULL);
    HttpTestSetResponseBuf(payload, payloadLen);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    g_httpWriteBlockFirst = 1;
    int32_t ret = HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed);
    ASSERT_EQ(ret, HITLS_OCSP_ERR_IN_PROGRESS);
    ASSERT_TRUE(parsed == NULL);
    ret = HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
EXIT:
    free(payload);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC005
 * @title  OCSP-HTTP HttpReqCtxExchange passes HTTP errors through
 * @precon  nan
 * @brief
 *    1. Build a request and make the stub write fail.
 *    2. Call HITLS_OCSP_HttpReqCtxExchange once.
 * @expect
 *    1. The context is created successfully.
 *    2. HttpReqCtxExchange returns the HTTP I/O error code.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC005(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    g_httpWriteRet = BSL_UIO_IO_EXCEPTION;
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), BSL_HTTP_ERR_IO);
EXIT:
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC006
 * @title  OCSP-HTTP HttpReqCtxExchange with NULL parameters
 * @precon  nan
 * @brief
 *    1. Build a request and a context.
 *    2. Call HITLS_OCSP_HttpReqCtxExchange with NULL ctx and with NULL resp.
 * @expect
 *    1. The context is created successfully.
 *    2. Both calls return HITLS_OCSP_ERR_NULL_POINTER.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC006(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(NULL, &parsed), HITLS_OCSP_ERR_NULL_POINTER);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, NULL), HITLS_OCSP_ERR_NULL_POINTER);
EXIT:
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC007
 * @title  OCSP-HTTP ReqCtxFree with NULL is safe
 * @precon  nan
 * @brief
 *    1. Call HITLS_OCSP_HttpReqCtxFree(NULL).
 * @expect
 *    1. No operation and no crash.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC007(void)
{
    HITLS_OCSP_HttpReqCtxFree(NULL);
    ASSERT_TRUE(true);
EXIT:
    return;
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC008
 * @title  OCSP-HTTP ReqCtxCtrl round trip and invalid command
 * @precon  nan
 * @brief
 *    1. Build a request and a context.
 *    2. Set/get MAX_RESP_LEN and MAX_RESP_HDR_LINES through the HTTP Client ctrl,
 *       then call an invalid command.
 * @expect
 *    1. The context is created successfully.
 *    2. Both round trips return the same value and the invalid command returns
 *       BSL_HTTP_ERR_PARAM.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC008(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    uint32_t setLen = 50 * 1024;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_LEN, &setLen, sizeof(setLen)),
              HITLS_PKI_SUCCESS);
    uint32_t getLen = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_LEN, &getLen, sizeof(getLen)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(getLen, setLen);
    uint32_t setLines = 64;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_MAX_RESP_HDR_LINES, &setLines, sizeof(setLines)),
              HITLS_PKI_SUCCESS);
    uint32_t getLines = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_MAX_RESP_HDR_LINES, &getLines, sizeof(getLines)),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(getLines, setLines);
    uint32_t dummy = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, 9999, &dummy, sizeof(dummy)), BSL_HTTP_ERR_PARAM);
EXIT:
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC009
 * @title  OCSP-HTTP AddHeader("Host") sets the Host header on the wire
 * @precon  nan
 * @brief
 *    1. Build a request, a canned response and a context; add the Host header.
 *    2. Drive the exchange once.
 * @expect
 *    1. The context is created successfully and the AddHeader call succeeds.
 *    2. HttpReqCtxExchange returns success and the request carries Host: status.geotrust.com.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC009(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    BSL_Buffer respDer = {0};
    uint8_t *payload = NULL;
    uint32_t payloadLen = 0;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(OcspHttpBuildRespDer(&respDer), HITLS_PKI_SUCCESS);
    payload = OcspHttpWrapResp(respDer.data, respDer.dataLen, &payloadLen);
    ASSERT_TRUE(payload != NULL);
    HttpTestSetResponseBuf(payload, payloadLen);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "status.geotrust.com"), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
    ASSERT_TRUE(HttpTestWrittenContains("Host: status.geotrust.com\r\n"));
EXIT:
    free(payload);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC010
 * @title  OCSP-HTTP AddHeader("Host") rejects NULL and bad values
 * @precon  nan
 * @brief
 *    1. Build a request and a context (no Host by default).
 *    2. Add the Host header with NULL, a control-character and an over-long value.
 * @expect
 *    1. The context is created successfully.
 *    2. All calls fail (there is no NULL/fallback host value; values are subject
 *       to the regular header value limits).
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC010(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_NE(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", NULL), HITLS_PKI_SUCCESS);
    ASSERT_NE(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", "bad\r\nX-Inject: 1"), HITLS_PKI_SUCCESS);
    char tooLong[5000];
    (void)memset(tooLong, 'a', sizeof(tooLong) - 1);
    tooLong[sizeof(tooLong) - 1] = '\0';
    ASSERT_NE(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", tooLong), HITLS_PKI_SUCCESS);
EXIT:
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC011
 * @title  End-to-end: AIA URL -> host/port/path -> IP -> UIO -> OCSP exchange
 * @precon  nan
 * @brief
 *    1. Parse the preset certificate carrying an AIA OCSP URL.
 *    2. Extract the URL, split it into host/port/path and resolve the host to an IP.
 *    3. Create a stub UIO, build an OCSP request and send it through the
 *       OCSP-HTTP adapter with the URL host set explicitly.
 * @expect
 *    1. The URL is "http://status.geotrust.com" -> host, port 80 and path "/".
 *    2. The host resolves to 10.1.2.3.
 *    3. HttpReqCtxExchange returns success and the response parses; the request on the wire
 *       carries "POST / HTTP/1.0" and "Host: status.geotrust.com".
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC011(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_X509_Cert *cert = NULL;
    BslList *urls = NULL;
    HITLS_OCSP_Req *req = NULL;
    BSL_Buffer respDer = {0};
    uint8_t *payload = NULL;
    uint32_t payloadLen = 0;
    char host[128] = {0};
    char path[256] = {0};
    uint16_t port = 0;
    uint8_t ip[16] = {0};
    uint32_t ipLen = 0;
    BSL_UIO *uio = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();

    /* 1. Extract the OCSP responder URL from the certificate AIA. */
    BSL_Buffer certBuf = {(uint8_t *)g_certWithOcspUrlDer, sizeof(g_certWithOcspUrlDer)};
    ASSERT_EQ(HITLS_X509_CertParseBuff(BSL_FORMAT_ASN1, &certBuf, &cert), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(cert != NULL);
    ASSERT_EQ(HITLS_OCSP_GetCertOcspUrls(cert, &urls), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(urls != NULL);
    ASSERT_EQ(BSL_LIST_COUNT(urls), 1);
    BSL_Buffer *urlBuf = (BSL_Buffer *)BSL_LIST_GetIndexNode(0, urls);
    ASSERT_TRUE(urlBuf != NULL);

    /* The URL list holds raw bytes without a trailing NUL: copy it bounded by dataLen. */
    char url[256];
    ASSERT_TRUE(urlBuf->dataLen < sizeof(url));
    (void)memcpy(url, urlBuf->data, urlBuf->dataLen);
    url[urlBuf->dataLen] = '\0';

    /* 2. Split the URL into host / port / path. */
    ASSERT_EQ(OcspHttpParseUrl(url, host, sizeof(host), &port, path, sizeof(path)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(strcmp(host, "status.geotrust.com") == 0);
    ASSERT_EQ(port, 80);
    ASSERT_TRUE(strcmp(path, "/") == 0);

    /* 3. Resolve the host to an IP (validates the mock resolver). */
    ASSERT_EQ(OcspHttpHostToIp(host, ip, &ipLen), HITLS_PKI_SUCCESS);
    ASSERT_EQ(ipLen, 4);
    ASSERT_EQ(ip[0], 10);
    ASSERT_EQ(ip[1], 1);
    ASSERT_EQ(ip[2], 2);
    ASSERT_EQ(ip[3], 3);
    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);

    /* 4. Build the OCSP request and a canned HTTP response. */
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(OcspHttpBuildRespDer(&respDer), HITLS_PKI_SUCCESS);
    payload = OcspHttpWrapResp(respDer.data, respDer.dataLen, &payloadLen);
    ASSERT_TRUE(payload != NULL);
    HttpTestSetResponseBuf(payload, payloadLen);

    /* 5. Send through the adapter; the Host header uses the URL authority. */
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, path, req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_HTTP_ReqCtxAddHeader(ctx, "Host", host), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsed != NULL);
    int32_t status = -1;
    ASSERT_EQ(HITLS_OCSP_RespCtrl(parsed, HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, HITLS_OCSP_RESP_STATUS_INTERNAL_ERROR);

    /* 6. The request on the wire uses the parsed path and the URL host. */
    ASSERT_TRUE(HttpTestWrittenContains("POST / HTTP/1.0\r\n"));
    ASSERT_TRUE(HttpTestWrittenContains("Host: status.geotrust.com\r\n"));
EXIT:
    free(payload);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_LIST_FREE(urls, (BSL_LIST_PFUNC_FREE)BslBufferFree);
    HITLS_X509_CertFree(cert);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC012
 * @title  HttpReqCtxExchange rejects a body whose Content-Length disagrees with the DER length
 * @precon  nan
 * @brief
 *    1. Build a request, a valid OCSP response DER and a stub UIO.
 *    2. Serve an HTTP response whose Content-Length is the DER length plus 3 padded
 *       bytes, and one whose body does not start with a SEQUENCE tag.
 * @expect
 *    1. The context is created successfully.
 *    2. The first exchange returns HITLS_OCSP_ERR_LENGTH_MISMATCH, the second
 *       HITLS_OCSP_ERR_INVALID_RESPONSE; no response object is produced.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC012(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_OCSP_Req *req = NULL;
    BSL_Buffer respDer = {0};
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Case 1: Content-Length larger than the DER body (padded with junk). */
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(OcspHttpBuildRespDer(&respDer), HITLS_PKI_SUCCESS);
    uint32_t paddedLen = respDer.dataLen + 3;
    char head[160];
    int hn = snprintf(head, sizeof(head),
                      "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: %u\r\n\r\n",
                      (unsigned)paddedLen);
    ASSERT_TRUE(hn > 0 && (uint32_t)hn < sizeof(head));
    uint8_t *payload = (uint8_t *)malloc((size_t)hn + paddedLen);
    ASSERT_TRUE(payload != NULL);
    (void)memcpy(payload, head, (size_t)hn);
    (void)memcpy(payload + hn, respDer.data, respDer.dataLen);
    (void)memset(payload + hn + respDer.dataLen, 0, 3);
    HttpTestSetResponseBuf(payload, (uint32_t)hn + paddedLen);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_OCSP_ERR_LENGTH_MISMATCH);
    ASSERT_TRUE(parsed == NULL);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    ctx = NULL;
    HITLS_OCSP_ReqFree(req);
    req = NULL;
    BSL_UIO_Free(uio);
    uio = NULL;
    free(payload);
    payload = NULL;

    /* Case 2: body does not start with a SEQUENCE tag. */
    HttpTestReset();
    uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    const char *garbage = "not-an-ocsp-response";
    hn = snprintf(head, sizeof(head),
                  "HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\nContent-Length: %u\r\n\r\n",
                  (unsigned)strlen(garbage));
    ASSERT_TRUE(hn > 0 && (uint32_t)hn < sizeof(head));
    payload = (uint8_t *)malloc((size_t)hn + strlen(garbage));
    ASSERT_TRUE(payload != NULL);
    (void)memcpy(payload, head, (size_t)hn);
    (void)memcpy(payload + hn, garbage, strlen(garbage));
    HttpTestSetResponseBuf(payload, (uint32_t)hn + (uint32_t)strlen(garbage));
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_TRUE(parsed == NULL);
EXIT:
    free(payload);
    BSL_SAL_Free(respDer.data);
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC013
 * @title  OCSP-HTTP HttpReqCtxExchange passes the HTTP timeout through
 * @precon  nan
 * @brief
 *    1. Build a request, a canned response and a context; set a 1 second deadline.
 *    2. Make the first read return in progress and poll HITLS_OCSP_HttpReqCtxExchange
 *       until it is no longer in progress.
 * @expect
 *    1. The context is created successfully and the timeout is set.
 *    2. The poll loop ends with HttpReqCtxExchange returning BSL_HTTP_ERR_TIMEOUT
 *       (the HTTP deadline error passes through
 *       the adapter) and no response is produced.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC013(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    uint32_t timeoutSec = 1;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_SET_TIMEOUT, &timeoutSec, sizeof(timeoutSec)),
              HITLS_PKI_SUCCESS);
    g_httpReadBlockFirst = 1;
    /* Single-step non-blocking exchange: poll until the 1s deadline passes and
     * the HTTP layer reports BSL_HTTP_ERR_TIMEOUT. */
    int32_t ret;
    do {
        ret = HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed);
    } while (ret == HITLS_OCSP_ERR_IN_PROGRESS);
    ASSERT_EQ(ret, BSL_HTTP_ERR_TIMEOUT);
    ASSERT_TRUE(parsed == NULL);
EXIT:
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_HTTP_TC014
 * @title  OCSP-HTTP HttpReqCtxExchange rejects a non-200 HTTP status
 * @precon  nan
 * @brief
 *    1. Build a request, a 400 error response and a context.
 *    2. Call HITLS_OCSP_HttpReqCtxExchange once.
 * @expect
 *    1. The context is created successfully.
 *    2. HttpReqCtxExchange returns HITLS_OCSP_ERR_HTTP_STATUS (not the raw HTTP Content-Type
 *       or parse error) and the status code is retrievable via GET_RESP_STATUS.
 */
/* BEGIN_CASE */
void SDV_OCSP_HTTP_TC014(void)
{
#ifdef HITLS_PKI_OCSP
    HITLS_HTTP_ReqCtx *ctx = NULL;
    HITLS_OCSP_Resp *parsed = NULL;
    HITLS_OCSP_Req *req = NULL;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HttpTestReset();
    BSL_UIO *uio = HttpTestNewUio();
    ASSERT_TRUE(uio != NULL);
    req = OcspHttpBuildReq();
    ASSERT_TRUE(req != NULL);
    ctx = HITLS_OCSP_HttpReqCtxNew(uio, "/responder/ocsp", req);
    ASSERT_TRUE(ctx != NULL);
    HttpTestSetResponse("HTTP/1.0 400 Bad Request\r\n"
                        "Content-Type: text/html\r\n"
                        "Content-Length: 5\r\n"
                        "\r\n"
                        "error");
    ASSERT_EQ(HITLS_OCSP_HttpReqCtxExchange(ctx, &parsed), HITLS_OCSP_ERR_HTTP_STATUS);
    ASSERT_TRUE(parsed == NULL);
    uint32_t status = 0;
    ASSERT_EQ(HITLS_HTTP_ReqCtxCtrl(ctx, HITLS_HTTP_CTRL_GET_RESP_STATUS, &status, sizeof(status)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(status, 400);
EXIT:
    HITLS_OCSP_RespFree(parsed);
    HITLS_OCSP_HttpReqCtxFree(ctx);
    HITLS_OCSP_ReqFree(req);
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */


/**
 * @test  SDV_OCSP_REQ_LIMIT_TC001
 * @title  Adding more than the single-request limit is rejected
 * @precon  nan
 * @brief
 *    1. Add HITLS_OCSP_MAX_SINGLE_REQ single requests to a request.
 *    2. Add one more.
 * @expect
 *    1. The first 1024 additions succeed.
 *    2. The 1025th returns HITLS_OCSP_ERR_TOO_MANY and is not taken by the request.
 */
/* BEGIN_CASE */
void SDV_OCSP_REQ_LIMIT_TC001(void)
{
#ifdef HITLS_PKI_OCSP
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_Req *req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    HITLS_OCSP_SingleReq *lastSr = NULL;
    for (uint32_t i = 0; i < HITLS_OCSP_MAX_SINGLE_REQ; i++) {
        HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
        ASSERT_TRUE(cid != NULL);
        HITLS_OCSP_SingleReq *sr = HITLS_OCSP_SingleReqNew(cid);
        ASSERT_TRUE(sr != NULL);
        ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    }
    HITLS_OCSP_CertId *cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    lastSr = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(lastSr != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, (void *)lastSr, sizeof(lastSr)),
              HITLS_OCSP_ERR_TOO_MANY);
EXIT:
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_SingleReqFree(lastSr); /* rejected, so the caller still owns it */
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_OCSP_RESP_LIMIT_TC002
 * @title  Adding more than the single-response limit is rejected
 * @precon  nan
 * @brief
 *    1. Add HITLS_OCSP_MAX_SINGLE_RESP single responses to a basic response.
 *    2. Add one more.
 * @expect
 *    1. The first 1024 additions succeed.
 *    2. The 1025th returns HITLS_OCSP_ERR_TOO_MANY and is not taken by the response.
 */
/* BEGIN_CASE */
void SDV_OCSP_RESP_LIMIT_TC002(void)
{
#ifdef HITLS_PKI_OCSP
    ASSERT_EQ(OcspTestGlobalSetup(), 0);
    HITLS_OCSP_BasicResp *bs = HITLS_OCSP_BasicRespNew();
    ASSERT_TRUE(bs != NULL);
    HITLS_OCSP_SingleResp *lastSr = NULL;
    for (uint32_t i = 0; i < HITLS_OCSP_MAX_SINGLE_RESP; i++) {
        HITLS_OCSP_SingleResp *sr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate,
                                                             HITLS_OCSP_CERT_STATUS_GOOD);
        ASSERT_TRUE(sr != NULL);
        ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, (void *)sr, sizeof(sr)),
                  HITLS_PKI_SUCCESS);
    }
    lastSr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(lastSr != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespCtrl(bs, HITLS_OCSP_BASICRESP_ADD_RESP, (void *)lastSr, sizeof(lastSr)),
              HITLS_OCSP_ERR_TOO_MANY);
EXIT:
    HITLS_OCSP_BasicRespFree(bs);
    HITLS_OCSP_SingleRespFree(lastSr); /* rejected, so the caller still owns it */
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_NEXTUPDATE_BEFORE_THISUPDATE_TC062(void)
{
#ifdef HITLS_PKI_OCSP
    /* RFC 6960 4.2.2.1: nextUpdate must not precede thisUpdate. Construction is
     * rejected at SET_NEXT_UPDATE; a parsed response is rejected by CheckValidity. */
    HITLS_OCSP_SingleResp *goodSr = NULL;
    HITLS_OCSP_SingleResp *badSr = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_SingleResp *parsedSr = NULL;
    HITLS_OCSP_CertId *cid = NULL;
    BSL_TIME now = {0};
    int64_t nowUtc = 0;
    BSL_TIME badNext = {0};
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Positive control: nextUpdate after thisUpdate passes CheckValidity. */
    goodSr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(goodSr != NULL);
    ASSERT_EQ(HITLS_OCSP_CheckValidity(goodSr, 300, 0), HITLS_PKI_SUCCESS);

    /* Construction path: SET_NEXT_UPDATE rejects nextUpdate (now - 1h) preceding
     * thisUpdate (now), and does not set the field. */
    BSL_SAL_SysTimeGet(&now);
    ASSERT_EQ(BSL_SAL_DateToUtcTimeConvert(&now, &nowUtc), BSL_SUCCESS);
    ASSERT_EQ(BSL_SAL_UtcTimeToDateConvert(nowUtc - 3600, &badNext), BSL_SUCCESS);
    cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    badSr = HITLS_OCSP_SingleRespNew(cid, HITLS_OCSP_CERT_STATUS_GOOD, &now);
    ASSERT_TRUE(badSr != NULL);
    cid = NULL; /* ownership transferred */
    ASSERT_EQ(HITLS_OCSP_SingleRespCtrl(badSr, HITLS_OCSP_SINGLERESP_SET_NEXT_UPDATE, &badNext, sizeof(BSL_TIME)),
              HITLS_OCSP_ERR_INVALID_PARAM);

    /* Verification path (RFC client-side): parse a response whose nextUpdate
     * (2024) precedes thisUpdate (2025); CheckValidity must reject it. */
    uint8_t der[] = {
        0x30, 0x81, 0xb4, 0x0a, 0x01, 0x00, 0xa0, 0x81, 0xae, 0x30, 0x81, 0xab, 0x06, 0x09, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x81, 0x9d, 0x30, 0x81, 0x9a, 0x30, 0x81, 0x88,
        0xa1, 0x0f, 0x30, 0x0d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02, 0x43,
        0x41, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0x30, 0x64, 0x30, 0x62, 0x30, 0x3a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
        0x1a, 0x05, 0x00, 0x04, 0x14, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x04, 0x14, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x02,
        0x01, 0x01, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30,
        0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
        0x1a, 0x05, 0x00, 0x03, 0x02, 0x00, 0x41,
    };
    BSL_Buffer in = {der, sizeof(der)};
    ASSERT_EQ(HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &in, &resp), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(resp != NULL);
    ASSERT_EQ(HITLS_OCSP_RespCtrl(resp, HITLS_OCSP_RESP_GET_BASIC, &bs, sizeof(bs)), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(bs != NULL);
    ASSERT_EQ(HITLS_OCSP_BasicRespGetRespByIndex(bs, 0, &parsedSr), HITLS_PKI_SUCCESS);
    ASSERT_TRUE(parsedSr != NULL);
    ASSERT_EQ(HITLS_OCSP_CheckValidity(parsedSr, 300, 0), HITLS_OCSP_ERR_VALIDITY);

EXIT:
    HITLS_OCSP_SingleRespFree(goodSr);
    HITLS_OCSP_SingleRespFree(badSr);
    HITLS_OCSP_RespFree(resp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_OCSP_MALFORMED_DER_TC063(void)
{
#ifdef HITLS_PKI_OCSP
    /* Malformed request/response DER must fail parsing with the request/response
     * parse-failure code, and the error-stack top must match the return code. */
    HITLS_OCSP_CertId *cid = NULL;
    HITLS_OCSP_SingleReq *sr = NULL;
    HITLS_OCSP_Req *req = NULL;
    HITLS_OCSP_Req *parsedReq = NULL;
    HITLS_OCSP_SingleResp *goodSr = NULL;
    HITLS_OCSP_SingleResp *srArr[1] = {NULL};
    HITLS_OCSP_BasicResp *bs = NULL;
    HITLS_OCSP_Resp *resp = NULL;
    HITLS_OCSP_Resp *parsedResp = NULL;
    BSL_Buffer reqDer = {0};
    BSL_Buffer respDer = {0};
    uint8_t bad[4096] = {0};
    BSL_Buffer badBuf = {0};
    bool found = false;
    int32_t ret = 0;
    ASSERT_EQ(OcspTestGlobalSetup(), 0);

    /* Build a valid signed request. */
    cid = HITLS_OCSP_CertIdNewFromCert(g_mdCtx, g_chain1.ee, g_chain1.intermediate);
    ASSERT_TRUE(cid != NULL);
    sr = HITLS_OCSP_SingleReqNew(cid);
    ASSERT_TRUE(sr != NULL);
    cid = NULL;
    req = HITLS_OCSP_ReqNew();
    ASSERT_TRUE(req != NULL);
    ASSERT_EQ(HITLS_OCSP_ReqCtrl(req, HITLS_OCSP_REQ_ADD_SINGLEREQ, sr, sizeof(sr)), HITLS_PKI_SUCCESS);
    sr = NULL;
    ASSERT_EQ(HITLS_OCSP_ReqSign(CRYPT_MD_SHA256, g_chain1.intermediateKey, NULL, g_chain1.intermediate, NULL, req, 0),
              HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_OCSP_ReqGenBuff(BSL_FORMAT_ASN1, req, &reqDer), HITLS_PKI_SUCCESS);

    /* 1. Request DER with trailing garbage -> INVALID_REQUEST. */
    ASSERT_TRUE(reqDer.dataLen + 2 <= sizeof(bad));
    memcpy(bad, reqDer.data, reqDer.dataLen);
    bad[reqDer.dataLen] = 0xAA;
    bad[reqDer.dataLen + 1] = 0xBB;
    badBuf = (BSL_Buffer){bad, reqDer.dataLen + 2};
    ret = HITLS_OCSP_ReqParseBuff(BSL_FORMAT_ASN1, &badBuf, &parsedReq);
    ASSERT_EQ(ret, HITLS_OCSP_ERR_INVALID_REQUEST);
    ASSERT_EQ(BSL_ERR_GetError(), HITLS_OCSP_ERR_INVALID_REQUEST);
    ASSERT_TRUE(parsedReq == NULL);

    /* Build a valid signed response (good status, byName responderID). */
    goodSr = OcspTestCreateSingleResp(g_mdCtx, g_chain1.ee, g_chain1.intermediate, HITLS_OCSP_CERT_STATUS_GOOD);
    ASSERT_TRUE(goodSr != NULL);
    srArr[0] = goodSr;
    bs = OcspTestCreateBasicResp(g_chain1.intermediate, g_chain1.intermediateKey, NULL, srArr, 1, NULL);
    ASSERT_TRUE(bs != NULL);
    resp = HITLS_OCSP_RespNew(HITLS_OCSP_RESP_STATUS_SUCCESSFUL, bs);
    ASSERT_TRUE(resp != NULL);
    bs = NULL;
    ASSERT_EQ(HITLS_OCSP_RespGenBuff(BSL_FORMAT_ASN1, resp, &respDer), HITLS_PKI_SUCCESS);

    /* 2. Response DER with trailing garbage -> INVALID_RESPONSE. */
    ASSERT_TRUE(respDer.dataLen + 1 <= sizeof(bad));
    memset(bad, 0, sizeof(bad));
    memcpy(bad, respDer.data, respDer.dataLen);
    bad[respDer.dataLen] = 0xAA;
    badBuf = (BSL_Buffer){bad, respDer.dataLen + 1};
    ret = HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &badBuf, &parsedResp);
    ASSERT_EQ(ret, HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_EQ(BSL_ERR_GetError(), HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_TRUE(parsedResp == NULL);

    /* 3. certStatus tag good [0] (0x80) patched to byKey [2] (0xa2), a cross-context
     * tag that passes the CHOICE whitelist but is invalid for CertStatus ->
     * INVALID_RESPONSE. */
    memset(bad, 0, sizeof(bad));
    memcpy(bad, respDer.data, respDer.dataLen);
    found = false;
    for (uint32_t i = 0; i + 3 < respDer.dataLen; i++) {
        if (bad[i] == 0x80 && bad[i + 1] == 0x00 && bad[i + 2] == 0x18) {
            bad[i] = 0xA2;
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
    badBuf = (BSL_Buffer){bad, respDer.dataLen};
    ret = HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &badBuf, &parsedResp);
    ASSERT_EQ(ret, HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_EQ(BSL_ERR_GetError(), HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_TRUE(parsedResp == NULL);

    /* 4. ResponderID byName [1] tag (0xa1) patched to good [0] (0x80), a cross-context
     * tag that passes the CHOICE whitelist but is invalid for ResponderID ->
     * INVALID_RESPONSE. Locate the byName TLV as the one immediately before the first
     * GeneralizedTime (producedAt). */
    memset(bad, 0, sizeof(bad));
    memcpy(bad, respDer.data, respDer.dataLen);
    uint32_t prodAt = UINT32_MAX;
    for (uint32_t i = 0; i + 1 < respDer.dataLen; i++) {
        if (bad[i] == 0x18 && bad[i + 1] == 0x0f) {
            prodAt = i;
            break;
        }
    }
    ASSERT_TRUE(prodAt != UINT32_MAX);
    found = false;
    for (uint32_t i = 0; i + 1 < prodAt; i++) {
        /* byName ::= [1] <len> <len bytes of Name>, ending exactly at producedAt. */
        if (bad[i] == 0xa1 && bad[i + 1] == (prodAt - i - 2)) {
            bad[i] = 0x80;
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);
    badBuf = (BSL_Buffer){bad, respDer.dataLen};
    ret = HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &badBuf, &parsedResp);
    ASSERT_EQ(ret, HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_EQ(BSL_ERR_GetError(), HITLS_OCSP_ERR_INVALID_RESPONSE);
    ASSERT_TRUE(parsedResp == NULL);

EXIT:
    BSL_SAL_FREE(reqDer.data);
    BSL_SAL_FREE(respDer.data);
    HITLS_OCSP_ReqFree(req);
    HITLS_OCSP_RespFree(resp);
    HITLS_OCSP_ReqFree(parsedReq);
    HITLS_OCSP_RespFree(parsedResp);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */
