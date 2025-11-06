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

/* BEGIN_HEADER */
#include <stdio.h>
#include <stdbool.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "bsl_obj.h"
#include "bsl_types.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_params_key.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_x509_verify.h"
#include "hitls_x509_local.h"
/* END_HEADER */

static inline void UnusedParam1(int param1, int param2, int param3)
{
    (void)param1;
    (void)param2;
    (void)param3;
}


static inline void UnusedParam2(int param1, int param2, void *param3)
{
    (void)param1;
    (void)param2;
    (void)param3;
}

static bool PkiSkipTest(int32_t algId, int32_t format)
{
#ifndef HITLS_BSL_PEM
    if (format == BSL_FORMAT_PEM) {
        return true;
    }
#else
    (void)format;
#endif
    switch (algId) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
        case BSL_CID_RSASSAPSS:
            return false;
#endif
#ifdef HITLS_CRYPTO_ECDSA
        case CRYPT_PKEY_ECDSA:
            return false;
#endif
#ifdef HITLS_CRYPTO_SM2
        case CRYPT_PKEY_SM2:
            return false;
#endif
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_PKEY_ED25519:
            return false;
#endif
        default:
            return true;
    }
}

#ifdef HITLS_CRYPTO_KEY_ENCODE

#ifdef HITLS_CRYPTO_RSA
static int32_t SetRsaPara(CRYPT_EAL_PkeyCtx *pkey)
{
    uint8_t e[] = {1, 0, 1};  // RSA public exponent
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3; // public exponent length = 3
    para.para.rsaPara.bits = 2048;
    return CRYPT_EAL_PkeySetPara(pkey, &para);
}

static int32_t SetRsaPssPara(CRYPT_EAL_PkeyCtx *pkey)
{
    int32_t mdId = CRYPT_MD_SHA256;
    int32_t saltLen = 20; // 20 bytes salt
    BSL_Param pssParam[4] = {
    {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
    {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
    BSL_PARAM_END};
    return CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
}
#endif // HITLS_CRYPT_RSA

static CRYPT_EAL_PkeyCtx *GenKey(int32_t algId, int32_t curveId)
{
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId == BSL_CID_RSASSAPSS ? BSL_CID_RSA : algId);
    ASSERT_NE(pkey, NULL);

    if (algId == CRYPT_PKEY_ECDSA) {
        ASSERT_EQ(CRYPT_EAL_PkeySetParaById(pkey, curveId), CRYPT_SUCCESS);
    }

#ifdef HITLS_CRYPTO_RSA
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
    }
    if (algId == BSL_CID_RSASSAPSS) {
        ASSERT_EQ(SetRsaPara(pkey), CRYPT_SUCCESS);
        ASSERT_EQ(SetRsaPssPara(pkey), CRYPT_SUCCESS);
    }
#endif
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    return pkey;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return NULL;
}

/**
 * Generate DER/PEM public/private key: rsa, ecc, sm2, ed25519
 */
static int32_t TestEncodeKey(int32_t algId, int32_t type, int32_t curveId, char *path)
{
    BSL_Buffer encode = {0};
    int32_t ret = CRYPT_MEM_ALLOC_FAIL;

    CRYPT_EAL_PkeyCtx *pkey = GenKey(algId, curveId);
    ASSERT_NE(pkey, NULL);

#ifdef HITLS_BSL_SAL_FILE
    if (path != NULL) {
        ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_ASN1, type, path), CRYPT_SUCCESS);
    }
#ifdef HITLS_BSL_PEM
    if (path != NULL) {
        ASSERT_EQ(CRYPT_EAL_EncodeFileKey(pkey, NULL, BSL_FORMAT_PEM, type, path), CRYPT_SUCCESS);
    }
#endif
#else
    (void)path;
#endif
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1, type, &encode), CRYPT_SUCCESS);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_PEM, type, &encode), CRYPT_SUCCESS);
    BSL_SAL_FREE(encode.data);
#endif

    ret = CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}
#endif // HITLS_CRYPTO_KEY_ENCODE

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CSR_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
static char g_sm2DefaultUserid[] = "1234567812345678";

static void SetSignParam(int32_t algId, int32_t mdId, HITLS_X509_SignAlgParam *algParam, CRYPT_RSA_PssPara *pssParam)
{
    if (algId == BSL_CID_RSASSAPSS) {
        algParam->algId = BSL_CID_RSASSAPSS;
        pssParam->mdId = mdId;
        pssParam->mgfId = mdId;
        pssParam->saltLen = 20; // 20 bytes salt
        algParam->rsaPss = *pssParam;
    }
    if (algId == BSL_CID_SM2DSA) {
        algParam->algId = BSL_CID_SM2DSAWITHSM3;
        algParam->sm2UserId.data = (uint8_t *)g_sm2DefaultUserid;
        algParam->sm2UserId.dataLen = (uint32_t)strlen(g_sm2DefaultUserid);
    }
    
}
#endif

#if defined(HITLS_PKI_X509_CRL_GEN) || defined(HITLS_PKI_X509_CRT_GEN)
static BslList* GenDNList(void)
{
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};

    BslList *dirNames = HITLS_X509_DnListNew();
    ASSERT_NE(dirNames, NULL);

    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_AddDnName(dirNames, dnName2, 1), HITLS_PKI_SUCCESS);
    return dirNames;

EXIT:
    HITLS_X509_DnListFree(dirNames);
    return NULL;
}

static BslList* GenGeneralNameList(void)
{
    char *str = "test";
    HITLS_X509_GeneralName *email = NULL;
    HITLS_X509_GeneralName *dns = NULL;
    HITLS_X509_GeneralName *dname = NULL;
    HITLS_X509_GeneralName *uri = NULL;
    HITLS_X509_GeneralName *ip = NULL;

    BslList *names = BSL_LIST_New(sizeof(HITLS_X509_GeneralName));
    ASSERT_NE(names, NULL);

    email = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dns = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    dname = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    uri = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ip = BSL_SAL_Malloc(sizeof(HITLS_X509_GeneralName));
    ASSERT_TRUE(email != NULL && dns != NULL && dname != NULL && uri != NULL && ip != NULL);

    email->type = HITLS_X509_GN_EMAIL;
    dns->type = HITLS_X509_GN_DNS;
    uri->type = HITLS_X509_GN_URI;
    dname->type = HITLS_X509_GN_DNNAME;
    ip->type = HITLS_X509_GN_IP;
    email->value.dataLen = strlen(str);
    dns->value.dataLen = strlen(str);
    uri->value.dataLen = strlen(str);
    dname->value.dataLen = sizeof(BslList *);
    ip->value.dataLen = strlen(str);
    email->value.data = BSL_SAL_Dump(str, strlen(str));
    dns->value.data = BSL_SAL_Dump(str, strlen(str));
    uri->value.data = BSL_SAL_Dump(str, strlen(str));
    dname->value.data = (uint8_t *)GenDNList();
    ip->value.data = BSL_SAL_Dump(str, strlen(str));
    ASSERT_TRUE(email->value.data != NULL && dns->value.data != NULL && uri->value.data != NULL && dname->value.data != NULL && ip->value.data != NULL);

    ASSERT_EQ(BSL_LIST_AddElement(names, email, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dns, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, uri, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, dname, BSL_LIST_POS_END), 0);
    ASSERT_EQ(BSL_LIST_AddElement(names, ip, BSL_LIST_POS_END), 0);

    return names;
EXIT:
    HITLS_X509_FreeGeneralName(email);
    HITLS_X509_FreeGeneralName(dns);
    HITLS_X509_FreeGeneralName(dname);
    HITLS_X509_FreeGeneralName(uri);
    HITLS_X509_FreeGeneralName(ip);
    BSL_LIST_FREE(names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return NULL;
}
#endif

#ifdef HITLS_PKI_X509_CRL_GEN
static int32_t SetCrlEntry(HITLS_X509_Crl *crl)
{
    int32_t ret = 1;
    BSL_TIME revokeTime = {2030, 1, 1, 0, 0, 0, 0, 0};
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    HITLS_X509_RevokeExtReason reason = {0, 1};  // keyCompromise
    BSL_TIME invalidTime = revokeTime;
    HITLS_X509_RevokeExtTime invalidTimeExt = {false, invalidTime};
    
    BslList *names = NULL;
    HITLS_X509_CrlEntry *entry = HITLS_X509_CrlEntryNew();
    ASSERT_NE(entry, NULL);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM, serialNum, sizeof(serialNum)),0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(BSL_TIME)),0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason,
        sizeof(HITLS_X509_RevokeExtReason)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_INVALID_TIME, &invalidTimeExt,
        sizeof(HITLS_X509_RevokeExtTime)), 0);
    HITLS_X509_RevokeExtCertIssuer certIssuer = {true, NULL};
    certIssuer.issuerName = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_CERTISSUER,
        &certIssuer, sizeof(HITLS_X509_RevokeExtCertIssuer)), 0);
    ASSERT_EQ(HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_GET_REVOKED_CERTISSUER, &names, sizeof(BslList *)), 0);
    ASSERT_EQ(names->count, 5);
    ASSERT_EQ(names->dataSize, 24);
    HITLS_X509_GeneralName *ptr = names->first->data;
    ASSERT_EQ(ptr->type, HITLS_X509_GN_EMAIL);
    ASSERT_EQ(ptr->value.dataLen, 4);
    ASSERT_EQ(memcmp(ptr->value.data, "test", ptr->value.dataLen), 0);
    ptr = names->last->data;
    ASSERT_EQ(ptr->type, HITLS_X509_GN_IP);
    ASSERT_EQ(ptr->value.dataLen, 4);
    ASSERT_EQ(memcmp(ptr->value.data, "test", ptr->value.dataLen), 0);

    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, 0), 0);

    ret = 0;
EXIT:
    HITLS_X509_ClearGeneralNames(names);
    BSL_SAL_Free(names);
    HITLS_X509_CrlEntryFree(entry);
    BSL_LIST_FREE(certIssuer.issuerName, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}
#endif // HITLS_PKI_X509_CRL_GEN

#ifdef HITLS_PKI_X509_CSR_GEN
static int32_t FillExt(HITLS_X509_Ext *ext)
{
    HITLS_X509_ExtBCons bCons = {true, false, 1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    return 0;
EXIT:
    return 1;
}
#endif // HITLS_PKI_X509_CSR_GEN

#ifdef HITLS_PKI_X509_CRT_GEN
static void FreeListData(void *data)
{
    (void)data;
    return;
}

static int32_t SetCertExt(HITLS_X509_Cert *cert)
{
    int32_t ret = 1;
    uint8_t kid[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    HITLS_X509_ExtBCons bCons = {true, true, 1};
    HITLS_X509_ExtKeyUsage ku = {true, HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_NON_REPUDIATION};
    HITLS_X509_ExtAki aki = {true, {kid, sizeof(kid)}, NULL, {0}};
    HITLS_X509_ExtSki ski = {true, {kid, sizeof(kid)}};
    HITLS_X509_ExtExKeyUsage exku = {true, NULL};
    HITLS_X509_ExtSan san = {true, NULL};
    BSL_Buffer oidBuff = {0};
    BslOidString *oid = NULL;

    BslList *oidList = BSL_LIST_New(sizeof(BSL_Buffer));
    ASSERT_TRUE(oidList != NULL);
    oid = BSL_OBJ_GetOID(BSL_CID_KP_SERVERAUTH);
    ASSERT_NE(oid, NULL);
    oidBuff.data = (uint8_t *)oid->octs;
    oidBuff.dataLen = oid->octetLen;
    ASSERT_EQ(BSL_LIST_AddElement(oidList, &oidBuff, BSL_LIST_POS_END), 0);

    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bCons, sizeof(HITLS_X509_ExtBCons)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &ku, sizeof(HITLS_X509_ExtKeyUsage)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(HITLS_X509_ExtSki)), 0);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_AKI, &aki, sizeof(HITLS_X509_ExtAki)), 0);

    exku.oidList = oidList;
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_EXKUSAGE, &exku, sizeof(HITLS_X509_ExtExKeyUsage)), 0);

    san.names = GenGeneralNameList();
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SAN, &san, sizeof(HITLS_X509_ExtSan)), 0);

    ret = 0;
EXIT:
    BSL_LIST_FREE(oidList, (BSL_LIST_PFUNC_FREE)FreeListData);
    BSL_LIST_FREE(san.names, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeGeneralName);
    return ret;
}
#endif // HITLS_PKI_X509_CRT_GEN

/* BEGIN_CASE */
void SDV_PKI_GEN_KEY_TC001(int algId, int type, int curveId)
{
#ifdef HITLS_CRYPTO_KEY_ENCODE
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.key";
    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(TestEncodeKey(algId, type, curveId, path), CRYPT_SUCCESS);

EXIT:
    TestRandDeInit();
    remove(path);
#else
    UnusedParam1(algId, type, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_ENCKEY_TC001(int algId, int curveId, int symId, Hex *pwd)
{
#if defined(HITLS_CRYPTO_KEY_ENCODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    CRYPT_Pbkdf2Param param = {
        .pbesId = BSL_CID_PBES2,
        .pbkdfId = BSL_CID_PBKDF2,
        .hmacId = CRYPT_MAC_HMAC_SHA256,
        .symId = symId,
        .pwd = pwd->x,
        .pwdLen = pwd->len,
        .saltLen = 16,
        .itCnt = 2000,
    };
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Buffer encode = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    pkey = GenKey(algId, curveId);
    ASSERT_NE(pkey, NULL);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, &paramEx, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_ENCRYPT, &encode), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_FREE(encode.data);
#else
    (void)algId;
    (void)curveId;
    (void)symId;
    (void)pwd;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_KEY_FILE_TC001(int algId, int format, int type, char *path)
{
#if defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)path;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_ENCKEY_FILE_TC001(int algId, int format, int type, char *path, Hex *pass)
{
#if defined(HITLS_BSL_SAL_FILE) && defined(HITLS_CRYPTO_KEY_DECODE) && defined(HITLS_CRYPTO_KEY_EPKI)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, pass->x, pass->len, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)path;
    (void)pass;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_KEY_BUFF_TC001(int algId, int format, int type, Hex *encode)
{
#ifdef HITLS_CRYPTO_KEY_DECODE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;

    TestMemInit();
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(format, type, (BSL_Buffer *)encode, NULL, 0, &pkey), CRYPT_SUCCESS);
    ASSERT_NE(pkey, NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    (void)algId;
    (void)format;
    (void)type;
    (void)encode;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_CRL_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CRL_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.crl";
    HITLS_X509_Crl *crl = NULL;
    uint32_t version = 1;
    BslList *issuer = NULL;
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    uint8_t crlNumber[1] = {0x11};
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer encode = {0};
    HITLS_X509_ExtCrlNumber crlNumberExt = {false, {crlNumber, 1}};

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *prvKey = GenKey(algId, curveId);
    ASSERT_NE(prvKey, NULL);
    crl = HITLS_X509_CrlNew();
    ASSERT_NE(crl, NULL);

    issuer = GenDNList();
    ASSERT_NE(issuer, NULL);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_ISSUER_DN, issuer, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCrlEntry(crl), 0);
    ASSERT_EQ(HITLS_X509_CrlCtrl(crl, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumberExt, sizeof(HITLS_X509_ExtCrlNumber)), 0);

    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CrlSign(hashId, prvKey, NULL, crl), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CrlSign(hashId, prvKey, &algParam, crl), HITLS_PKI_SUCCESS);
    }

#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_ASN1, crl, path), HITLS_PKI_SUCCESS);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CrlGenFile(BSL_FORMAT_PEM, crl, path), HITLS_PKI_SUCCESS);
#endif
#endif
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_ASN1, crl, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CrlGenBuff(BSL_FORMAT_PEM, crl, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(prvKey);
    HITLS_X509_CrlFree(crl);
    HITLS_X509_DnListFree(issuer);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CRL_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRL_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Crl *crl = NULL;

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CrlParseFile(format, path, &crl), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CrlFree(crl);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CRL_BUFF_TC001(int algId, int format, Hex *encode)
{
#ifdef HITLS_PKI_X509_CRL_PARSE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Crl *crl = NULL;

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CrlParseBuff(format, (BSL_Buffer *)encode, &crl), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CrlFree(crl);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_CSR_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CSR_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.csr";
    HITLS_X509_Csr *csr = NULL;
    BSL_Buffer encode = {0};
    HITLS_X509_DN dnName1[1] = {{BSL_CID_AT_COMMONNAME, (uint8_t *)"OH", 2}};
    HITLS_X509_DN dnName2[1] = {{BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2}};
    HITLS_X509_Attrs *attrs = NULL;
    HITLS_X509_Ext *ext = NULL;
    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);
    ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    ASSERT_NE(ext, NULL);

    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName1, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_ADD_SUBJECT_NAME, dnName2, 1), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_CSR_GET_ATTRIBUTES, &attrs, sizeof(HITLS_X509_Attrs *)), 0);

    ASSERT_EQ(FillExt(ext), 0);
    ASSERT_EQ(HITLS_X509_AttrCtrl(attrs, HITLS_X509_ATTR_SET_REQUESTED_EXTENSIONS, ext, 0), 0);

    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, NULL, csr), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CsrSign(hashId, key, &algParam, csr), HITLS_PKI_SUCCESS);
    }


#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_ASN1, csr, path), 0);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CsrGenFile(BSL_FORMAT_PEM, csr, path), 0);
#endif
#endif
    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_ASN1, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CsrFree(csr);
    HITLS_X509_ExtFree(ext);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CSR_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CSR_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Csr *csr = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CsrParseFile(format, path, &csr), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CsrFree(csr);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CSR_BUFF_TC001(int algId, int format, Hex *encode)
{
#if defined(HITLS_PKI_X509_CSR_PARSE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Csr *csr = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CsrParseBuff(format, (BSL_Buffer *)encode, &csr), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CsrFree(csr);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_GEN_CERT_TC001(int algId, int hashId, int curveId)
{
#ifdef HITLS_PKI_X509_CRT_GEN
    if (PkiSkipTest(algId, BSL_FORMAT_ASN1)) {
        SKIP_TEST();
    }

    char *path = "tmp.cert";
    HITLS_X509_Cert *cert = NULL;
    uint32_t version = 2; // v3 cert
    uint8_t serialNum[4] = {0x11, 0x22, 0x33, 0x44};
    BSL_TIME beforeTime = {2025, 1, 1, 0, 0, 0, 0, 0};
    BSL_TIME afterTime = {2035, 1, 1, 0, 0, 0, 0, 0};
    BslList *dnList = NULL;

    HITLS_X509_SignAlgParam algParam = {0};
    CRYPT_RSA_PssPara pssParam = {0};
    BSL_Buffer encode = {0};

    TestMemInit();
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyCtx *key = GenKey(algId, curveId);
    ASSERT_NE(key, NULL);
    cert = HITLS_X509_CertNew();
    ASSERT_NE(cert, NULL);

    // set cert info
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(BSL_TIME)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, key, 0), HITLS_PKI_SUCCESS);
    dnList = GenDNList();
    ASSERT_NE(dnList, NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, dnList, sizeof(BslList)), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertExt(cert), 0);

    // sign cert
    SetSignParam(algId, hashId, &algParam, &pssParam);
    if (algId == CRYPT_PKEY_RSA) {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, NULL, cert), HITLS_PKI_SUCCESS);
    } else {
        ASSERT_EQ(HITLS_X509_CertSign(hashId, key, &algParam, cert), HITLS_PKI_SUCCESS);
    }

    // generate cert file
#ifdef HITLS_BSL_SAL_FILE
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_ASN1, cert, path), HITLS_PKI_SUCCESS);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CertGenFile(BSL_FORMAT_PEM, cert, path), HITLS_PKI_SUCCESS);
#endif
#endif
    // generate cert buff
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
#ifdef HITLS_BSL_PEM
    ASSERT_EQ(HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, cert, &encode), 0);
    BSL_SAL_FREE(encode.data);
#endif

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_X509_CertFree(cert);
    HITLS_X509_DnListFree(dnList);
    remove(path);
#else
    UnusedParam1(algId, hashId, curveId);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_FILE_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT_PARSE) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CertFree(cert);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_BUFF_TC001(int algId, int format, Hex *encode)
{
#ifdef HITLS_PKI_X509_CRT_PARSE
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseBuff(format, (BSL_Buffer *)encode, &cert), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CertFree(cert);
#else
    UnusedParam2(algId, format, encode);
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_PKI_PARSE_CERT_FILE_CONTAIN_T61_TC001(int algId, int format, char *path)
{
#if defined(HITLS_PKI_X509_CRT) && defined(HITLS_BSL_SAL_FILE)
    if (PkiSkipTest(algId, format)) {
        SKIP_TEST();
    }

    HITLS_X509_Cert *cert = NULL;
    HITLS_X509_Cert *certCpy = NULL;
    BSL_Buffer buff = {0};

    TestMemInit();
    ASSERT_EQ(HITLS_X509_CertParseFile(format, path, &cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertGenBuff(format, cert, &buff), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseBuff(format, &buff, &certCpy), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(buff.data);
    HITLS_X509_CertFree(cert);
    HITLS_X509_CertFree(certCpy);
#else
    UnusedParam2(algId, format, path);
    SKIP_TEST();
#endif
}
/* END_CASE */

