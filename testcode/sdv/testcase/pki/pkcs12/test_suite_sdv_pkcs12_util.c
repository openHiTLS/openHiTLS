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

#include "bsl_sal.h"
#include "securec.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_errno.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "hitls_pkcs12_local.h"
#include "hitls_crl_local.h"
#include "hitls_cert_type.h"
#include "hitls_cert_local.h"
#include "bsl_types.h"
#include "crypt_errno.h"
#include "stub_utils.h"
#include "bsl_list_internal.h"
#include "crypt_eal_rand.h"
#include "stub_utils.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_x509.h"
/* END_HEADER */

#if (defined(HITLS_PKI_PKCS12_GEN) || defined(HITLS_PKI_PKCS12_PARSE)) && defined(HITLS_CRYPTO_PROVIDER)
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
#endif

/* Platform-specific dynamic library extension for testing */
#ifdef __APPLE__
#define BSL_SAL_DL_EXT "dylib"
#else
#define BSL_SAL_DL_EXT "so"
#endif

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET4(int32_t, HITLS_PKCS12_CalMac, HITLS_PKCS12 *, BSL_Buffer *, BSL_Buffer *, BSL_Buffer *);

static int32_t SetCertBag(HITLS_PKCS12 *p12, HITLS_X509_Cert *cert)
{
    HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert); // new a cert Bag
    ASSERT_NE(certBag, NULL);
    char *name = "I am a x509CertBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, certBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(certBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t SetEntityCertBag(HITLS_PKCS12 *p12, HITLS_X509_Cert *cert)
{
    HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert); // new a cert Bag
    ASSERT_NE(certBag, NULL);
    char *name = "I am a entity cert bag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(certBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t SetEntityKeyBag(HITLS_PKCS12 *p12, CRYPT_EAL_PkeyCtx *cert)
{
    HITLS_PKCS12_Bag *pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, cert); // new a cert Bag
    ASSERT_NE(pkeyBag, NULL);
    char *name = "I am a p8 encrypted bag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(pkeyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, pkeyBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(pkeyBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t NewAndSetKeyBag(HITLS_PKCS12 *p12, int algId)
{
    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_ProviderPkeyNewCtx(p12->libCtx, algId, 0, p12->attrName);
    ASSERT_NE(key, NULL);
    if (algId == BSL_CID_RSA) {
        CRYPT_EAL_PkeyPara para = {.id = CRYPT_PKEY_RSA};
        uint8_t e[] = {1, 0, 1};
        para.para.rsaPara.e = e;
        para.para.rsaPara.eLen = 3;
        para.para.rsaPara.bits = 1024;
        ASSERT_TRUE(CRYPT_EAL_PkeySetPara(key, &para) == CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyGen(key), 0);
    HITLS_PKCS12_Bag *keyBag = HITLS_PKCS12_BagNew(BSL_CID_KEYBAG, 0, key); // new a key Bag
    ASSERT_NE(keyBag, NULL);
    char *name = "I am a keyBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_KEYBAG, keyBag, 0), 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_PKCS12_BagFree(keyBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t NewAndSetSecretBag(HITLS_PKCS12 *p12)
{
    char *secret = "this is the secret.";
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)secret;
    buffer.dataLen = strlen(secret);
    // new a secret Bag
    HITLS_PKCS12_Bag *secretBag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_PKCS7_SIMPLEDATA, &buffer);
    ASSERT_NE(secretBag, NULL);
    char *name = "I am an attribute of secretBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer2 = {0};
    buffer2.data = (uint8_t *)name;
    buffer2.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer2, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(secretBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t SetCrlBag(HITLS_PKCS12 *p12, HITLS_X509_Crl *crl)
{
    HITLS_PKCS12_Bag *crlBag = HITLS_PKCS12_BagNew(BSL_CID_CRLBAG, BSL_CID_X509CRL, crl); // new a crl Bag
    ASSERT_NE(crlBag, NULL);
    char *name = "I am a x509CrlBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(crlBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CRLBAG, crlBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(crlBag);
    return HITLS_PKI_SUCCESS;
}

/**
 * For test generating a .p12 inlcuding keyBag, certBag, p8KeyBag and secretBag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_KEYBAGS_TC001(char *pkeyPath, char *enCertPath, char *ca1CertPath, char *otherCertPath,
    char *crlPath)
{
#ifndef HITLS_PKI_PKCS12_GEN
    (void)pkeyPath;
    (void)enCertPath;
    (void)ca1CertPath;
    (void)otherCertPath;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
#ifdef HITLS_PKI_PKCS12_PARSE
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
#endif
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_X509_Cert *ca1Cert = NULL;
    HITLS_X509_Cert *otherCert = NULL;
    HITLS_X509_Crl *crl = NULL;
    int32_t mdId = CRYPT_MD_SHA1;
    BSL_Buffer output = {0};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12 *p12_1 = NULL;
    BSL_ASN1_List *certList = NULL;
    BSL_ASN1_List *keyList = NULL;
    BSL_ASN1_List *secretBags = NULL;
    BSL_ASN1_List *crlBags = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, ca1CertPath, &ca1Cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, otherCertPath, &otherCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CrlParseFile(BSL_FORMAT_ASN1, crlPath, &crl), HITLS_PKI_SUCCESS);

    // Add the entity cert to p12.
    ASSERT_EQ(SetEntityCertBag(p12, enCert), HITLS_PKI_SUCCESS);
    // Add the entity key to p12.
    ASSERT_EQ(SetEntityKeyBag(p12, pkey), HITLS_PKI_SUCCESS);
    // Add the ca cert to p12.
    ASSERT_EQ(SetCertBag(p12, ca1Cert), HITLS_PKI_SUCCESS);
    // Add the other cert to p12.
    ASSERT_EQ(SetCertBag(p12, otherCert), HITLS_PKI_SUCCESS);
    // Add the crl to p12.
    ASSERT_EQ(SetCrlBag(p12, crl), HITLS_PKI_SUCCESS);
    // Gen and add key bag to p12.
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_RSA), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_ED25519), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetSecretBag(p12), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId)), 0);
    // Gen a p12.
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);
#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CERTBAGS, &certList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CRLBAGS, &crlBags, 0), 0);

    ASSERT_EQ(BSL_LIST_COUNT(certList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 1);
    ASSERT_EQ(BSL_LIST_COUNT(crlBags), 1);
    ASSERT_NE(p12_1->entityCert, NULL);
    ASSERT_NE(p12_1->key, NULL);
#endif
    certList = NULL;
    keyList = NULL;
    secretBags = NULL;
    crlBags = NULL;
    BSL_SAL_FREE(output.data);
    output.dataLen = 0;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), 0);
    HITLS_PKCS12_Free(p12_1);
    p12_1 = NULL;
#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, false), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CERTBAGS, &certList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CRLBAGS, &crlBags, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(certList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 1);
    ASSERT_EQ(BSL_LIST_COUNT(crlBags), 1);
    ASSERT_NE(p12_1->entityCert, NULL);
    ASSERT_NE(p12_1->key, NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(enCert);
    HITLS_X509_CertFree(ca1Cert);
    HITLS_X509_CertFree(otherCert);
    HITLS_X509_CrlFree(crl);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */

/**
 * For test ctrl of get key bags from p12.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CTRL_GET_KEYBAGS_TC001(void)
{
#ifndef HITLS_PKI_PKCS12_GEN
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
#ifdef HITLS_PKI_PKCS12_PARSE
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
#endif
    BSL_ASN1_List *keyList = NULL;
    BSL_Buffer output = {0};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12_Bag *bag = NULL;
    uint8_t bufferValue[20] = {0}; // 20 bytes is enough for the attr value.
    uint32_t bufferValueLen = 20;
    int32_t id = 0;
    BSL_Buffer buffer = {.data = bufferValue, .dataLen = bufferValueLen};
    char *attrName = "I am a keyBag";
    CRYPT_EAL_PkeyCtx *key = NULL;
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_RSA), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_ED25519), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetSecretBag(p12), HITLS_PKI_SUCCESS);
    // Gen a p12.
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);

#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_NE(keyList, NULL);
    bag = BSL_LIST_GET_FIRST(keyList);
    while (bag != NULL) {
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_VALUE, &key, 0), 0);
        ASSERT_NE(key, NULL);
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(int32_t)), 0);
        ASSERT_EQ(id, BSL_CID_KEYBAG);
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
        ASSERT_COMPARE("compare key bag attr", buffer.data, buffer.dataLen, attrName, strlen(attrName));
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ATTR, &buffer, BSL_CID_LOCALKEYID),
            HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES);
        bag = BSL_LIST_GET_NEXT(keyList);
        CRYPT_EAL_PkeyFreeCtx(key);
        key = NULL;
    }
#endif
EXIT:
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */

/**
 * For test parse multi bags in p12, including certBag, keyBag, secretBag, p8ShroudedKeyBag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MULBAG_TC001(Hex *mulBag, int hasMac)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)mulBag;
    (void)hasMac;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer buffer = {.data = (uint8_t *)mulBag->x, .dataLen = mulBag->len};
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12, hasMac == 1), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->certList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->keyList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->secretBags), 0);
    ASSERT_NE(p12->key, NULL);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_PKI_PKCS12_PARSE) && defined(HITLS_PKI_PKCS12_GEN)

#define HITLS_P12_LIB_NAME "libprovider_load_p12." BSL_SAL_DL_EXT
#define HITLS_P12_PROVIDER_ATTR "provider?=p12Load"
#define HITLS_P12_PROVIDER_PATH "provider_test_data/path1"

static CRYPT_EAL_LibCtx *P12_ProviderLoadWithDefault(void)
{
    int32_t ret = CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0);
    if (ret != CRYPT_SUCCESS && ret != CRYPT_EAL_ERR_DRBG_REPEAT_INIT) {
        ASSERT_EQ(ret, CRYPT_SUCCESS);
    }

    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);

    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, HITLS_P12_PROVIDER_PATH), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, HITLS_P12_LIB_NAME, NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, 0, "default", NULL, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderRandInitCtx(libCtx, CRYPT_RAND_SHA256, HITLS_P12_PROVIDER_ATTR, NULL, 0, NULL),
        CRYPT_SUCCESS);
    return libCtx;

EXIT:
    CRYPT_EAL_LibCtxFree(libCtx);
    return NULL;
}

static int32_t STUB_HITLS_PKCS12_CalMac(HITLS_PKCS12 *p12, BSL_Buffer *pwd, BSL_Buffer *initData, BSL_Buffer *output)
{
    (void)p12;
    (void)pwd;
    (void)initData;
    uint8_t *temp = BSL_SAL_Malloc(32);
    ASSERT_TRUE(temp != NULL);
    uint8_t outBuf[32] = {0xe3, 0x69, 0x5a, 0x9a, 0xfe, 0x27, 0x53, 0x4c,
        0x95, 0x17, 0x67, 0xa2, 0x3f, 0x83, 0x9f, 0x94,
        0x55, 0xb7, 0xf9, 0x00, 0x4b, 0xbc, 0x28, 0xbb,
        0x9d, 0x59, 0x73, 0xbb, 0x91, 0xd0, 0x7c, 0x53};
    memcpy(temp, outBuf, 32);
    output->data = temp;
    output->dataLen = 32;
EXIT:
    return CRYPT_SUCCESS;
}

#endif

/**
 * For test parse p12 with provider.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_WITH_PROVIDER_TC001(Hex *mulBag)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_CRYPTO_PROVIDER)
    (void)mulBag;
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    libCtx = P12_ProviderLoadWithDefault();
    ASSERT_TRUE(libCtx != NULL);
    
    char *pwd = "123456";
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer buffer = {.data = (uint8_t *)mulBag->x, .dataLen = mulBag->len};
    ASSERT_EQ(HITLS_PKCS12_ProviderParseBuff(libCtx, HITLS_P12_PROVIDER_ATTR, "ASN1", &buffer, &pwdParam, &p12, true),
        HITLS_PKCS12_ERR_VERIFY_FAIL); // mac has been installed.
    STUB_REPLACE(HITLS_PKCS12_CalMac, STUB_HITLS_PKCS12_CalMac);
    ASSERT_EQ(HITLS_PKCS12_ProviderParseBuff(libCtx, HITLS_P12_PROVIDER_ATTR, "ASN1", &buffer, &pwdParam, &p12, true),
        HITLS_PKI_SUCCESS);
    ASSERT_NE(p12, NULL);
    ASSERT_NE(BSL_LIST_COUNT(p12->certList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->keyList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->secretBags), 0);
    ASSERT_NE(p12->key, NULL);
EXIT:
    HITLS_PKCS12_Free(p12);
    CRYPT_EAL_RandDeinitEx(libCtx);
    CRYPT_EAL_LibCtxFree(libCtx);
    STUB_RESTORE(HITLS_PKCS12_CalMac);
#endif
}
/* END_CASE */

/**
 * For test encode p12 with provider.
*/
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_WITH_PROVIDER_TC001(void)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_CRYPTO_PROVIDER)
    SKIP_TEST();
#else
    CRYPT_EAL_LibCtx *libCtx = NULL;
    libCtx = P12_ProviderLoadWithDefault();
    ASSERT_TRUE(libCtx != NULL);
    BSL_Buffer output = {0};
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SM3, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_ProviderNew(libCtx, HITLS_P12_PROVIDER_ATTR);
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_RSA), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output.data);
    HITLS_PKCS12_Free(p12);
    CRYPT_EAL_RandDeinitEx(libCtx);
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_PKCS12_PARSE_STUB_TC001
 * title 1. Test the parse p12 with stub malloc fail (adaptive)
 * preCondition NA
 * @brief
 *   1. Probe phase: Run once successfully to count total malloc calls
 *   2. Test phase: Iteratively fail each malloc and verify proper error handling
 * @expect
 *   1. Probe phase succeeds and counts n malloc calls
 *   2. Each malloc failure is handled correctly without memory leaks
 */
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_STUB_TC001(Hex *mulBag, int hasMac)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_CRYPTO_PROVIDER)
    (void)mulBag;
    (void)hasMac;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer buffer = {.data = (uint8_t *)mulBag->x, .dataLen = mulBag->len};
    uint32_t totalMallocCount = 0;
    int32_t ret;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12, hasMac == 1), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    HITLS_PKCS12_Free(p12);
    p12 = NULL;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12, hasMac == 1);
        if (ret == HITLS_PKI_SUCCESS) {
            HITLS_PKCS12_Free(p12);
            p12 = NULL;
        }
    }
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * @test SDV_PKCS12_ENCODE_STUB_TC001
 * title 1. Test the encode p12 with stub malloc fail (adaptive)
 *
 */
/* BEGIN_CASE */
void SDV_PKCS12_ENCODE_STUB_TC001(Hex *mulBag, int hasMac)
{
#if !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_CRYPTO_PROVIDER)
    (void)mulBag;
    (void)hasMac;
    SKIP_TEST();
#else
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer buffer = {.data = (uint8_t *)mulBag->x, .dataLen = mulBag->len};
    (void)hasMac;
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SM3, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
    BSL_Buffer output = {0};
    uint32_t totalMallocCount = 0;

    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12, hasMac == 1), 0);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - run once successfully to count malloc calls */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKI_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_Free(output.data);
    output.data = NULL;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKI_SUCCESS);
    }
EXIT:
    STUB_RESTORE(BSL_SAL_Malloc);
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */

/**
 * @test SDV_PKCS12_CERTCHAIN_BUILD_TC001
 * title: Test P12 certificate chain encode/decode and chain building
 * 1. Load certificates from testcode/testdata/cert/chain/sm2-v3 (ca.der, inter.der, end.der)
 * 2. Add certificates to P12
 * 3. Encode P12 to buffer
 * 4. Decode buffer back to P12
 * 5. Build certificate chain with decoded certificates
 * 6. Verify chain building succeeds
 */
/* BEGIN_CASE */
void SDV_PKCS12_CERTCHAIN_BUILD_TC001(void)
{
#if !defined(HITLS_PKI_PKCS12_GEN) || !defined(HITLS_PKI_PKCS12_PARSE) || !defined(HITLS_PKI_X509_VFY)
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);

    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};

    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_Cert *interCert = NULL;
    HITLS_X509_Cert *endCert = NULL;
    HITLS_PKCS12 *p12 = NULL;
    HITLS_PKCS12 *p12Decoded = NULL;
    BSL_Buffer output = {0};
    BSL_ASN1_List *certList = NULL;
    HITLS_X509_StoreCtx *storeCtx = NULL;
    HITLS_X509_List *chain = NULL;

    // Step 1: Load certificates from sm2-v3 directory
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/sm2-v3/ca.der", &caCert),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/sm2-v3/inter.der", &interCert),
        HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, "../testdata/cert/chain/sm2-v3/end.der", &endCert),
        HITLS_PKI_SUCCESS);

    // Step 2: Create P12 and add certificates
    p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);

    ASSERT_EQ(SetCertBag(p12, caCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertBag(p12, interCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(SetCertBag(p12, endCert), HITLS_PKI_SUCCESS);

    // Encode P12 to buffer
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), HITLS_PKI_SUCCESS);
    ASSERT_NE(output.data, NULL);
    ASSERT_NE(output.dataLen, 0);

    // Decode buffer back to P12
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12Decoded, true), HITLS_PKI_SUCCESS);
    ASSERT_NE(p12Decoded, NULL);

    // Get certificate list from decoded P12
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12Decoded, HITLS_PKCS12_GET_CERTBAGS, &certList, 0), HITLS_PKI_SUCCESS);
    ASSERT_NE(certList, NULL);
    ASSERT_EQ(BSL_LIST_COUNT(certList), 3);

    // Create store context and build certificate chain
    storeCtx = HITLS_X509_StoreCtxNew();
    ASSERT_NE(storeCtx, NULL);

    // Extract certificates from decoded P12 and add to store
    HITLS_PKCS12_Bag *bag = BSL_LIST_GET_FIRST(certList);
    HITLS_X509_Cert *cert1 = NULL;
    HITLS_X509_Cert *cert2 = NULL;
    HITLS_X509_Cert *cert3 = NULL;
    int certIndex = 0;

    while (bag != NULL) {
        HITLS_X509_Cert *cert = NULL;
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_VALUE, &cert, 0), HITLS_PKI_SUCCESS);
        ASSERT_NE(cert, NULL);

        if (certIndex == 0) {
            cert1 = cert;
            // Add CA cert to store as trusted certificate
            ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, 0),
                HITLS_PKI_SUCCESS);
        } else if (certIndex == 1) {
            cert2 = cert;
            // Add intermediate cert to store
            ASSERT_EQ(HITLS_X509_StoreCtxCtrl(storeCtx, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, 0),
                HITLS_PKI_SUCCESS);
        } else if (certIndex == 2) {
            cert3 = cert;
        }

        certIndex++;
        bag = BSL_LIST_GET_NEXT(certList);
    }

    // Build certificate chain using the end certificate
    ASSERT_EQ(HITLS_X509_CertChainBuild(storeCtx, true, cert3, &chain), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertVerify(storeCtx, chain), HITLS_PKI_SUCCESS);

EXIT:
    HITLS_X509_CertFree(caCert);
    HITLS_X509_CertFree(interCert);
    HITLS_X509_CertFree(endCert);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12Decoded);
    BSL_SAL_Free(output.data);
    HITLS_X509_StoreCtxFree(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_CertFree(cert1);
    HITLS_X509_CertFree(cert2);
    HITLS_X509_CertFree(cert3);
#endif
}
/* END_CASE */
