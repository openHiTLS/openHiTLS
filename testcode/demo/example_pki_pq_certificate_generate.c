/*
 * Post-quantum PKI certificate generation example.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
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

#define PQ_CERT_PARAMETER_ID CRYPT_MLDSA_TYPE_MLDSA_44

typedef struct {
    CRYPT_EAL_PkeyCtx *key;
    HITLS_X509_Cert *cert;
} GeneratedPqIdentity;

static void PqCertPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static CRYPT_EAL_PkeyCtx *PqCertNewMldsaCtx(void)
{
    return CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_DSA, CRYPT_EAL_PKEY_SIGN_OPERATE, "provider=default");
}

static int32_t PqCertGenerateMldsaKey(CRYPT_EAL_PkeyCtx **key)
{
    CRYPT_EAL_PkeyCtx *ctx = NULL;
    int32_t ret;

    ctx = PqCertNewMldsaCtx();
    if (ctx == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(ctx, PQ_CERT_PARAMETER_ID);
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

static int32_t PqCertBuildDn(BslList **dnList, const char *commonName)
{
    HITLS_X509_DN dnCountry = {BSL_CID_AT_COUNTRYNAME, (uint8_t *)"CN", 2};
    HITLS_X509_DN dnOrg = {BSL_CID_AT_ORGANIZATIONNAME, (uint8_t *)"openHiTLS PQ Demo", 17};
    HITLS_X509_DN dnCn = {BSL_CID_AT_COMMONNAME, (uint8_t *)commonName, (uint32_t)strlen(commonName)};
    BslList *list = NULL;
    int32_t ret;

    list = HITLS_X509_DnListNew();
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
    ret = HITLS_X509_AddDnName(list, &dnCn, 1);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_X509_DnListFree(list);
        return ret;
    }

    *dnList = list;
    return HITLS_PKI_SUCCESS;
}

static int32_t PqCertGenerateSelfSignedCa(GeneratedPqIdentity *identity)
{
    uint8_t serialNum[] = {0x50, 0x51, 0x52, 0x53};
    uint8_t skiBytes[] = {0x10, 0x22, 0x34, 0x46, 0x58, 0x6a, 0x7c, 0x8e};
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

    ret = PqCertGenerateMldsaKey(&key);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }

    ret = PqCertBuildDn(&subjectDn, "openHiTLS ML-DSA Root CA");
    if (ret != HITLS_PKI_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(key);
        return ret;
    }

    cert = HITLS_X509_CertNew();
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

int main(void)
{
    GeneratedPqIdentity identity = {0};
    BSL_Buffer pem = {0};
    uint8_t digest[32];
    uint32_t digestLen = sizeof(digest);
    int32_t signAlg = 0;
    int32_t mdAlg = 0;
    int32_t ret;

    printf("=== PQ Certificate Generate Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PqCertGenerateSelfSignedCa(&identity);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertVerifyByPubKey(identity.cert, identity.key);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CheckKey(identity.cert, identity.key);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(identity.cert, HITLS_X509_GET_SIGNALG, &signAlg, sizeof(signAlg));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertCtrl(identity.cert, HITLS_X509_GET_SIGN_MDALG, &mdAlg, sizeof(mdAlg));
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertDigest(identity.cert, CRYPT_MD_SHA256, digest, &digestLen);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CertGenBuff(BSL_FORMAT_PEM, identity.cert, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Generated ML-DSA self-signed CA certificate: %u bytes PEM\n", pem.dataLen);
    printf("Certificate signature algorithm id: %d\n", signAlg);
    printf("Certificate digest algorithm id: %d\n", mdAlg);
    PqCertPrintHex("Certificate SHA-256", digest, digestLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(pem.data);
    HITLS_X509_CertFree(identity.cert);
    CRYPT_EAL_PkeyFreeCtx(identity.key);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
