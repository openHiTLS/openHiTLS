/*
 * PKI end-to-end example.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "bsl_err.h"
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
#include "hitls_pki_csr.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_types.h"
#include "hitls_pki_utils.h"
#include "hitls_pki_x509.h"

static int32_t DemoValidity(BSL_TIME *before, BSL_TIME *after)
{
    int32_t ret = BSL_SAL_SysTimeGet(before);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *after = *before;
    after->year += 10;
    if (after->month == 2 && after->day == 29) {
        after->day = 28;
    }
    return BSL_SUCCESS;
}

#define CHAIN_DIR "assets/tls_ecdsa_der/"
#define CMS_FILE "assets/pki/p256_attached.cms"
#define CMS_MSG_FILE "assets/pki/msg.txt"
#define CMS_CA_FILE "assets/pki/ca_cert.pem"

typedef struct {
    CRYPT_EAL_PkeyCtx *key;
    HITLS_X509_Cert *cert;
} GeneratedIdentity;

int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len);

static void PkiPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void PkiPrintPreview(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    uint32_t previewLen = len > 64 ? 64 : len;

    printf("%s: ", label);
    for (i = 0; i < previewLen; ++i) {
        uint8_t c = data[i];
        putchar((c >= 32 && c <= 126) ? (int)c : '.');
    }
    if (len > previewLen) {
        printf("...");
    }
    printf("\n");
}

static int32_t PkiReadBinaryFile(const char *path, BSL_Buffer *buffer)
{
    uint8_t *data = NULL;
    uint32_t readLen = 0;
    int32_t ret;

    ret = BSL_SAL_ReadFile(path, &data, &readLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    buffer->data = data;
    buffer->dataLen = readLen;
    return HITLS_PKI_SUCCESS;
}

static int32_t PkiGenerateRsa2048Key(CRYPT_EAL_PkeyCtx **key)
{
    static uint8_t exponent[] = {0x01, 0x00, 0x01};
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret;

    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_RSA, CRYPT_EAL_PKEY_SIGN_OPERATE, NULL);
    if (ctx == NULL) {
        return -1;
    }

    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = 2048;
    para.para.rsaPara.e = exponent;
    para.para.rsaPara.eLen = sizeof(exponent);

    ret = CRYPT_EAL_PkeySetPara(ctx, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_PkeyGen(ctx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(ctx);
        return ret;
    }

    *key = ctx;
    return HITLS_PKI_SUCCESS;
}

static int32_t PkiBuildDn(BslList **dnList, const char *commonName)
{
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"openHiTLS Demo", 13};
    HITLS_X509_DN dnCN = {BSL_CID_AT_COMMONNAME, (uint8_t *)commonName, (uint32_t)strlen(commonName)};
    BslList *list = HITLS_X509_DnListNew();
    int32_t ret;

    if (list == NULL) {
        return -1;
    }

    ret = HITLS_X509_AddDnName(list, &dnCountry, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(list);
        return ret;
    }
    ret = HITLS_X509_AddDnName(list, &dnOrg, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(list);
        return ret;
    }
    ret = HITLS_X509_AddDnName(list, &dnCN, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(list);
        return ret;
    }

    *dnList = list;
    return HITLS_PKI_SUCCESS;
}

static int32_t PkiGenerateSelfSignedCa(GeneratedIdentity *identity)
{
    uint8_t serialNum[] = {0x01, 0x23, 0x45, 0x67, 0x89};
    uint8_t skiBytes[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    BSL_TIME beforeTime;
    BSL_TIME afterTime;
    if (DemoValidity(&beforeTime, &afterTime) != BSL_SUCCESS) {
        return -1;
    }
    HITLS_X509_ExtBCons bcons = {true, true, 0};
    HITLS_X509_ExtKeyUsage keyUsage = {
        true,
        HITLS_X509_EXT_KU_DIGITAL_SIGN | HITLS_X509_EXT_KU_KEY_CERT_SIGN | HITLS_X509_EXT_KU_CRL_SIGN
    };
    HITLS_X509_ExtSki ski = {false, {skiBytes, sizeof(skiBytes)}};
    BslList *subjectDn = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *key = NULL;
    int32_t version = HITLS_X509_VERSION_3;
    int32_t ret;

    ret = PkiGenerateRsa2048Key(&key);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = PkiBuildDn(&subjectDn, "openHiTLS Demo Root CA");
    if (ret != HITLS_PKI_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(key);
        return ret;
    }

    cert = HITLS_X509_ProviderCertNew(NULL, NULL);
    if (cert == NULL) {
        HITLS_X509_DnListFree(subjectDn);
        CRYPT_EAL_PkeyFreeCtx(key);
        return -1;
    }

    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_VERSION, &version, sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SERIALNUM, serialNum, sizeof(serialNum));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_BEFORE_TIME, &beforeTime, sizeof(beforeTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_AFTER_TIME, &afterTime, sizeof(afterTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_PUBKEY, key, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_SUBJECT_DN, subjectDn, sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_SET_ISSUER_DN, subjectDn, sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_BCONS, &bcons, sizeof(bcons));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_KUSAGE, &keyUsage, sizeof(keyUsage));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_SET_SKI, &ski, sizeof(ski));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertSign(CRYPT_MD_SHA256, key, NULL, cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    identity->key = key;
    identity->cert = cert;
    HITLS_X509_DnListFree(subjectDn);
    return HITLS_PKI_SUCCESS;

cleanup:
    HITLS_X509_DnListFree(subjectDn);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(key);
    return ret;
}

static int32_t PkiGenerateCsr(CRYPT_EAL_PkeyCtx *key, HITLS_X509_Csr **csr)
{
    HITLS_X509_Csr *tmp = NULL;
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"openHiTLS Demo", 13};
    HITLS_X509_DN dnCN = {BSL_CID_AT_COMMONNAME, (uint8_t *)"openHiTLS Demo CSR", 18};
    int32_t ret;

    tmp = HITLS_X509_ProviderCsrNew(NULL, NULL);
    if (tmp == NULL) {
        return -1;
    }

    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_SET_PUBKEY, key, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnCountry, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnOrg, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrCtrl(tmp, HITLS_X509_ADD_SUBJECT_NAME, &dnCN, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CsrSign(CRYPT_MD_SHA256, key, NULL, tmp);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    *csr = tmp;
    return HITLS_PKI_SUCCESS;

cleanup:
    HITLS_X509_CsrFree(tmp);
    return ret;
}

static int32_t PkiGenerateCrl(CRYPT_EAL_PkeyCtx *issuerKey, HITLS_X509_Cert *issuerCert, HITLS_X509_Crl **crl)
{
    uint8_t revokedSerial[] = {0x55, 0xaa, 0x10, 0x20};
    uint8_t crlNumberBytes[] = {0x01};
    BSL_TIME thisUpdate;
    BSL_TIME nextUpdate;
    if (DemoValidity(&thisUpdate, &nextUpdate) != BSL_SUCCESS) {
        return -1;
    }
    BSL_TIME revokeTime = thisUpdate;
    HITLS_X509_RevokeExtReason reason = {true, HITLS_X509_REVOKED_REASON_KEY_COMPROMISE};
    HITLS_X509_ExtCrlNumber crlNumber = {false, {crlNumberBytes, sizeof(crlNumberBytes)}};
    BslList *issuerDn = NULL;
    HITLS_X509_CrlEntry *entry = NULL;
    HITLS_X509_Crl *tmp = NULL;
    int32_t version = HITLS_X509_VERSION_2;
    int32_t ret;

    tmp = HITLS_X509_CrlNew();
    if (tmp == NULL) {
        return -1;
    }

    ret = HITLS_X509_CertCtrl(issuerCert, HITLS_X509_GET_ISSUER_DN, &issuerDn, sizeof(BslList *));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_SET_ISSUER_DN, issuerDn, sizeof(BslList));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_SET_VERSION, &version, sizeof(version));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_SET_BEFORE_TIME, &thisUpdate, sizeof(thisUpdate));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_SET_AFTER_TIME, &nextUpdate, sizeof(nextUpdate));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    entry = HITLS_X509_CrlEntryNew();
    if (entry == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_SERIALNUM,
        revokedSerial, sizeof(revokedSerial));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REVOKE_TIME, &revokeTime, sizeof(revokeTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlEntryCtrl(entry, HITLS_X509_CRL_SET_REVOKED_REASON, &reason, sizeof(reason));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_CRL_ADD_REVOKED_CERT, entry, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlCtrl(tmp, HITLS_X509_EXT_SET_CRLNUMBER, &crlNumber, sizeof(crlNumber));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlSign(CRYPT_MD_SHA256, issuerKey, NULL, tmp);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    *crl = tmp;
    HITLS_X509_CrlEntryFree(entry);
    return HITLS_PKI_SUCCESS;

cleanup:
    HITLS_X509_CrlEntryFree(entry);
    HITLS_X509_CrlFree(tmp);
    return ret;
}

static int32_t PkiAddCertToStore(HITLS_X509_StoreCtx *store, const char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", path, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_DEEP_COPY_SET_CA, cert, sizeof(HITLS_X509_Cert *));
    HITLS_X509_CertFree(cert);
    if (ret != HITLS_PKI_SUCCESS) {
    }
    return ret;
}

static int32_t PkiAddCertToChain(HITLS_X509_List *chain, const char *path)
{
    HITLS_X509_Cert *cert = NULL;
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", path, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(chain, cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CertFree(cert);
        return ret;
    }
    return HITLS_PKI_SUCCESS;
}

#include "bsl_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_params.h"
#include "hitls_pki_pkcs12.h"

static int32_t DemoCertificateFlow(const GeneratedIdentity *identity)
{
    uint8_t digest[32];
    uint32_t digestLen = sizeof(digest);
    BSL_Buffer pem = {0};
    HITLS_X509_Cert *parsed = NULL;
    int32_t ret;

    printf("=== Certificate Parse / Generate ===\n");
    ret = HITLS_X509_CertVerifyByPubKey(identity->cert, identity->key);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, identity->cert, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    printf("Generated self-signed CA certificate: %u bytes PEM\n", pem.dataLen);
    BSL_SAL_Free(pem.data);
    pem.data = NULL;
    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "ASN1", CHAIN_DIR "server.der", &parsed);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertDigest(parsed, CRYPT_MD_SHA256, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    PkiPrintHex("server.der SHA-256", digest, digestLen);
    ret = 0;

cleanup:
    HITLS_X509_CertFree(parsed);
    BSL_SAL_Free(pem.data);
    return ret;
}

static int32_t DemoCrlFlow(const GeneratedIdentity *identity)
{
    BSL_Buffer pem = {0};
    HITLS_X509_Crl *crl = NULL;
    int32_t ret;

    printf("\n=== CRL Parse / Generate ===\n");
    ret = PkiGenerateCrl(identity->key, identity->cert, &crl);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CrlVerify(identity->key, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlGenBuff(BSL_FORMAT_PEM, crl, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Generated CRL PEM: %u bytes\n", pem.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(pem.data);
    HITLS_X509_CrlFree(crl);
    return ret;
}

static int32_t DemoCsrFlow(CRYPT_EAL_PkeyCtx *key)
{
    BSL_Buffer pem = {0};
    HITLS_X509_Csr *csr = NULL;
    int32_t ret;

    printf("\n=== CSR Parse / Generate ===\n");
    ret = PkiGenerateCsr(key, &csr);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_CsrGenBuff(BSL_FORMAT_PEM, csr, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Generated CSR PEM: %u bytes\n", pem.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(pem.data);
    HITLS_X509_CsrFree(csr);
    return ret;
}

static int32_t DemoPkcs12Flow(const GeneratedIdentity *identity)
{
    char password[] = "123456";
    BSL_Buffer pwd = {(uint8_t *)password, (uint32_t)strlen(password)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &pwd, .macPwd = &pwd};
    CRYPT_Pbkdf2Param pbParam = {
        BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC, 16,
        (uint8_t *)password, (uint32_t)strlen(password), 2048
    };
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macKdf = {8, 2048, BSL_CID_SHA256, (uint8_t *)password, (uint32_t)strlen(password)};
    HITLS_PKCS12_MacParam macParam = {.para = &macKdf, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, macParam};
    HITLS_PKCS12 *created = NULL;
    HITLS_PKCS12 *roundTrip = NULL;
    HITLS_PKCS12_Bag *keyBag = NULL;
    HITLS_PKCS12_Bag *certBag = NULL;
    BSL_Buffer out = {0};
    int32_t mdId = CRYPT_MD_SHA1;
    int32_t ret;

    printf("\n=== PKCS12 Parse / Generate ===\n");
    created = HITLS_PKCS12_ProviderNew(NULL, NULL);
    if (created == NULL) {
        return -1;
    }
    keyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, identity->key);
    certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, identity->cert);
    if (keyBag == NULL || certBag == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_PKCS12_Ctrl(created, HITLS_PKCS12_SET_ENTITY_KEYBAG, keyBag, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_Ctrl(created, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_Ctrl(created, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(mdId));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, created, &encodeParam, true, &out);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_PKCS12_ProviderParseBuff(NULL, NULL, "ASN1", &out, &pwdParam, &roundTrip, true);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Generated and re-parsed PKCS12 buffer: %u bytes\n", out.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(out.data);
    HITLS_PKCS12_BagFree(certBag);
    HITLS_PKCS12_BagFree(keyBag);
    HITLS_PKCS12_Free(roundTrip);
    HITLS_PKCS12_Free(created);
    return ret;
}

static int32_t DemoChainFlow(void)
{
    HITLS_X509_StoreCtx *store = NULL;
    HITLS_X509_List *chain = NULL;
    int64_t verifyTime = (int64_t)time(NULL);
    int32_t depth = 4;
    int32_t ret;

    printf("\n=== Certificate Chain Verify ===\n");
    store = HITLS_X509_ProviderStoreCtxNew(NULL, NULL);
    if (store == NULL) {
        return -1;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, &depth, sizeof(depth));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_TIME, &verifyTime, sizeof(verifyTime));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = PkiAddCertToStore(store, CHAIN_DIR "ca.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (chain == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = PkiAddCertToChain(chain, CHAIN_DIR "server.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = PkiAddCertToChain(chain, CHAIN_DIR "inter.der");
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerify(store, chain);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Certificate chain verification succeeded.\n");
    ret = 0;

cleanup:
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    HITLS_X509_StoreCtxFree(store);
    return ret;
}

static int32_t DemoCmsFlow(void)
{
    BSL_Buffer msg = {0};
    BSL_Buffer output = {0};
    BSL_Param params[2];
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;
    HITLS_CMS *cms = NULL;
    int32_t ret;

    printf("\n=== CMS Verify Output ===\n");
    ret = PkiReadBinaryFile(CMS_MSG_FILE, &msg);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "PEM", CMS_CA_FILE, &caCert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (caCertList == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = BSL_LIST_AddElement(caCertList, caCert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        goto cleanup;
    }
    caCert = NULL;
    params[0] = (BSL_Param){HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, caCertList, 0, 0};
    params[1] = (BSL_Param)BSL_PARAM_END;
    ret = HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, CMS_FILE, &cms);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataVerify(cms, &msg, params, &output);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    PkiPrintPreview("Verified content preview", output.data, output.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(msg.data);
    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(caCert);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int main(void)
{
    GeneratedIdentity identity = {0};
    int32_t ret;

    printf("=== openHiTLS PKI Full Example ===\n\n");
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }
    ret = PkiGenerateSelfSignedCa(&identity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoCertificateFlow(&identity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoCrlFlow(&identity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoCsrFlow(identity.key);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoPkcs12Flow(&identity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoChainFlow();
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = DemoCmsFlow();
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("\nAll PKI demo flows completed successfully.\n");
    ret = 0;

cleanup:
    HITLS_X509_CertFree(identity.cert);
    CRYPT_EAL_PkeyFreeCtx(identity.key);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
