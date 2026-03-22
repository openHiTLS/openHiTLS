/*
 * PKI CRL generation example.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_crl.h"
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

typedef struct {
    CRYPT_EAL_PkeyCtx *key;
    HITLS_X509_Cert *cert;
} GeneratedIdentity;

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

int main(void)
{
    GeneratedIdentity issuer = {0};
    HITLS_X509_Crl *crl = NULL;
    BSL_Buffer pem = {0};
    int32_t ret;

    printf("=== PKI CRL Generate Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PkiGenerateSelfSignedCa(&issuer);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    /*
     * PkiGenerateCrl internally demonstrates the generation path:
     * CrlNew -> CrlCtrl(SET_ISSUER_DN/SET_VERSION/SET_TIME/ADD_REVOKED/SET_CRLNUMBER)
     * -> CrlSign -> CrlGenBuff.
     */
    ret = PkiGenerateCrl(issuer.key, issuer.cert, &crl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlVerify(issuer.key, crl);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_X509_CrlGenBuff(BSL_FORMAT_PEM, crl, &pem);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Generated CRL and verified signature: %u bytes PEM\n", pem.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(pem.data);
    HITLS_X509_CrlFree(crl);
    HITLS_X509_CertFree(issuer.cert);
    CRYPT_EAL_PkeyFreeCtx(issuer.key);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
