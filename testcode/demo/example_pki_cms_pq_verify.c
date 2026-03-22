/*
 * Post-quantum CMS verification example.
 */

#include <stdint.h>
#include <stdio.h>

#include "bsl_list.h"
#include "bsl_params.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_params.h"

#define PQ_CMS_DIR "assets/pki_cms_pq/"
#define PQ_CMS_ATTACHED_FILE PQ_CMS_DIR "mldsa44_attached.cms"
#define PQ_CMS_DETACHED_FILE PQ_CMS_DIR "mldsa44_detached.cms"
#define PQ_CMS_CA_FILE PQ_CMS_DIR "ca_cert.pem"
#define PQ_CMS_MSG_FILE "assets/pki/msg.txt"

int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len);

static int32_t PqCmsReadBinaryFile(const char *path, BSL_Buffer *buffer)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    int32_t ret;

    ret = BSL_SAL_ReadFile(path, &data, &dataLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    buffer->data = data;
    buffer->dataLen = dataLen;
    return HITLS_PKI_SUCCESS;
}

static void PqCmsPrintPreview(const char *label, const uint8_t *data, uint32_t len)
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

static int32_t PqCmsBuildVerifyParams(HITLS_X509_List **caCertList, BSL_Param params[2])
{
    HITLS_X509_Cert *caCert = NULL;
    int32_t ret;

    *caCertList = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (*caCertList == NULL) {
        return -1;
    }

    ret = HITLS_X509_ProviderCertParseFile(NULL, NULL, "PEM", PQ_CMS_CA_FILE, &caCert);
    if (ret != HITLS_PKI_SUCCESS) {
        return ret;
    }
    ret = BSL_LIST_AddElement(*caCertList, caCert, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        HITLS_X509_CertFree(caCert);
        return ret;
    }

    /* Pass the trusted CA list into CMS verification so PQ SignedData chain validation can find issuers. */
    params[0] = (BSL_Param){HITLS_CMS_PARAM_CA_CERT_LISTS, BSL_PARAM_TYPE_CTX_PTR, *caCertList, 0, 0};
    params[1] = (BSL_Param)BSL_PARAM_END;
    return HITLS_PKI_SUCCESS;
}

static int32_t PqCmsVerifyAttached(void)
{
    HITLS_X509_List *caCertList = NULL;
    HITLS_CMS *cms = NULL;
    BSL_Buffer output = {0};
    BSL_Param params[2];
    int32_t ret;

    ret = PqCmsBuildVerifyParams(&caCertList, params);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, PQ_CMS_ATTACHED_FILE, &cms);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataVerify(cms, NULL, params, &output);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Verified ML-DSA attached CMS: %s\n", PQ_CMS_ATTACHED_FILE);
    printf("Attached content length: %u bytes\n", output.dataLen);
    PqCmsPrintPreview("Attached content preview", output.data, output.dataLen);
    ret = HITLS_PKI_SUCCESS;

cleanup:
    BSL_SAL_Free(output.data);
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

static int32_t PqCmsVerifyDetached(void)
{
    HITLS_X509_List *caCertList = NULL;
    HITLS_CMS *cms = NULL;
    BSL_Buffer msg = {0};
    BSL_Buffer output = {0};
    BSL_Param params[2];
    int32_t ret;

    ret = PqCmsReadBinaryFile(PQ_CMS_MSG_FILE, &msg);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = PqCmsBuildVerifyParams(&caCertList, params);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_ProviderParseFile(NULL, NULL, NULL, PQ_CMS_DETACHED_FILE, &cms);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = HITLS_CMS_DataVerify(cms, &msg, params, &output);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    printf("Verified ML-DSA detached CMS: %s\n", PQ_CMS_DETACHED_FILE);
    printf("Detached content length: %u bytes\n", output.dataLen);
    PqCmsPrintPreview("Detached content preview", output.data, output.dataLen);
    ret = HITLS_PKI_SUCCESS;

cleanup:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(msg.data);
    HITLS_CMS_Free(cms);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    return ret;
}

int main(void)
{
    int32_t ret;

    printf("=== PQ CMS Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PqCmsVerifyAttached();
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }
    ret = PqCmsVerifyDetached();
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
