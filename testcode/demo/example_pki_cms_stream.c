/*
 * PKI CMS streaming sign and verify example.
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
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"
#include "crypt_eal_codecs.h"
#include "bsl_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_params.h"

#define RSA_PEM_DIR "assets/pki_rsa_pem/"
#define EXAMPLE_CMS_SIGNERINFO_V1 0x01

int32_t HITLS_CMS_GenBuff(int32_t format, HITLS_CMS *cms, const BSL_Param *param, BSL_Buffer *encode);

static int32_t CmsStreamSignDemo(BSL_Buffer *encodedCms)
{
    static const char *message = "openHiTLS CMS streaming signing example";
    HITLS_CMS *cms = NULL;
    HITLS_X509_Cert *cert = NULL;
    CRYPT_EAL_PkeyCtx *key = NULL;
    HITLS_X509_List *certChain = NULL;
    BSL_Param initParams[2];
    BSL_Buffer chunk1 = {(uint8_t *)message, 10};
    BSL_Buffer chunk2 = {(uint8_t *)message + 10, 12};
    BSL_Buffer chunk3 = {(uint8_t *)message + 22, (uint32_t)strlen(message) - 22};
    int32_t mdId = BSL_CID_SHA256;
    int32_t rsaSignMd = CRYPT_MD_SHA256;
    int32_t version = EXAMPLE_CMS_SIGNERINFO_V1;
    BSL_Param params[6];
    int32_t ret;

    cms = HITLS_CMS_ProviderNew(NULL, NULL, BSL_CID_PKCS7_SIGNEDDATA);
    if (cms == NULL) {
        return -1;
    }

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "PEM", RSA_PEM_DIR "server.pem", &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_DecodeFileKey(BSL_FORMAT_PEM, CRYPT_PRIKEY_PKCS8_UNENCRYPT,
        RSA_PEM_DIR "server.key.pem", NULL, 0, &key);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyCtrl(key, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &rsaSignMd, sizeof(rsaSignMd));
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    certChain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (certChain == NULL) {
        ret = -1;
        goto cleanup;
    }
    ret = BSL_LIST_AddElement(certChain, cert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_Ctrl(cms, HITLS_CMS_SET_MSG_MD, &mdId, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    initParams[0] = (BSL_Param){HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0};
    initParams[1] = (BSL_Param)BSL_PARAM_END;
    ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_SIGN, cms, initParams);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataUpdate(cms, &chunk1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataUpdate(cms, &chunk2);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataUpdate(cms, &chunk3);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    params[0] = (BSL_Param){HITLS_CMS_PARAM_PRIVATE_KEY, BSL_PARAM_TYPE_CTX_PTR,
        key, sizeof(CRYPT_EAL_PkeyCtx *), 0};
    params[1] = (BSL_Param){HITLS_CMS_PARAM_DEVICE_CERT, BSL_PARAM_TYPE_CTX_PTR,
        cert, sizeof(HITLS_X509_Cert *), 0};
    params[2] = (BSL_Param){HITLS_CMS_PARAM_SIGNERINFO_VERSION, BSL_PARAM_TYPE_INT32,
        &version, sizeof(version), 0};
    params[3] = (BSL_Param){HITLS_CMS_PARAM_DIGEST, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0};
    params[4] = (BSL_Param){HITLS_CMS_PARAM_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR,
        certChain, sizeof(HITLS_X509_List *), 0};
    params[5] = (BSL_Param)BSL_PARAM_END;

    ret = HITLS_CMS_DataFinal(cms, params);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_GenBuff(BSL_FORMAT_ASN1, cms, NULL, encodedCms);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    printf("Streaming sign succeeded with chunk sizes: %u, %u, %u\n",
        chunk1.dataLen, chunk2.dataLen, chunk3.dataLen);
    printf("Signer certificate: %sserver.pem\n", RSA_PEM_DIR);
    printf("Generated CMS buffer size: %u bytes\n", encodedCms->dataLen);
    ret = HITLS_PKI_SUCCESS;

cleanup:
    HITLS_CMS_Free(cms);
    BSL_LIST_FreeWithoutData(certChain);
    HITLS_X509_CertFree(cert);
    CRYPT_EAL_PkeyFreeCtx(key);
    return ret;
}

static int32_t CmsStreamVerifyDemo(const BSL_Buffer *encodedCms)
{
    static const char *message = "openHiTLS CMS streaming signing example";
    BSL_Buffer chunk1 = {(uint8_t *)message, 10};
    BSL_Buffer chunk2 = {(uint8_t *)message + 10, 12};
    BSL_Buffer chunk3 = {(uint8_t *)message + 22, (uint32_t)strlen(message) - 22};
    HITLS_X509_List *caCertList = NULL;
    HITLS_CMS *cms = NULL;
    BSL_Param verifyParams[3];
    int32_t ret;

    ret = HITLS_X509_ProviderCertParseBundleFile(NULL, NULL, "PEM", RSA_PEM_DIR "cert_chain.pem", &caCertList);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    if (BSL_LIST_COUNT(caCertList) > 0) {
        BSL_LIST_DeleteNode(caCertList, BSL_LIST_FirstNode(caCertList), (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    }
    if (BSL_LIST_COUNT(caCertList) == 0) {
        ret = -1;
        goto cleanup;
    }
    ret = HITLS_CMS_ProviderParseBuff(NULL, NULL, NULL, encodedCms, &cms);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataInit(HITLS_CMS_OPT_VERIFY, cms, NULL);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    ret = HITLS_CMS_DataUpdate(cms, &chunk1);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataUpdate(cms, &chunk2);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataUpdate(cms, &chunk3);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    /* Reuse the trusted CA list during streaming verification to validate the signer chain. */
    verifyParams[0] = (BSL_Param){HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR,
        caCertList, sizeof(HITLS_X509_List *), 0};
    verifyParams[1] = (BSL_Param)BSL_PARAM_END;
    ret = HITLS_CMS_DataFinal(cms, verifyParams);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Streaming verify succeeded with chunk sizes: %u, %u, %u\n",
        chunk1.dataLen, chunk2.dataLen, chunk3.dataLen);
    ret = HITLS_PKI_SUCCESS;

cleanup:
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int main(void)
{
    BSL_Buffer encodedCms = {0};
    int32_t ret;

    printf("=== PKI CMS Streaming Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = CmsStreamSignDemo(&encodedCms);
    if (ret == HITLS_PKI_SUCCESS) {
        ret = CmsStreamVerifyDemo(&encodedCms);
    }

    BSL_SAL_Free(encodedCms.data);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
