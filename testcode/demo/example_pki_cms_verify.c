/*
 * PKI CMS SignedData verification example.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_types.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "hitls_pki_x509.h"
#include "hitls_pki_cms.h"
#include "bsl_params.h"

#define CMS_FILE "assets/pki/p256_attached.cms"
#define CMS_MSG_FILE "assets/pki/msg.txt"
#define CMS_CA_FILE "assets/pki/ca_cert.pem"

int32_t BSL_SAL_ReadFile(const char *path, uint8_t **buff, uint32_t *len);

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

#include "bsl_params.h"
#include "hitls_pki_cms.h"
#include "hitls_pki_params.h"

int main(void)
{
    BSL_Buffer msg = {0};
    BSL_Buffer output = {0};
    BSL_Param params[2];
    HITLS_X509_Cert *caCert = NULL;
    HITLS_X509_List *caCertList = NULL;
    HITLS_CMS *cms = NULL;
    int32_t ret;

    printf("=== PKI CMS Verify Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = PkiReadBinaryFile(CMS_MSG_FILE, &msg);
    if (ret != HITLS_PKI_SUCCESS) {
        goto cleanup;
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

    /* Pass the trusted CA list into CMS verification so SignedData chain validation can find issuers. */
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

    printf("Verified CMS SignedData: %s\n", CMS_FILE);
    printf("Verified content length: %u bytes\n", output.dataLen);
    PkiPrintPreview("Verified content preview", output.data, output.dataLen);
    ret = 0;

cleanup:
    BSL_SAL_Free(output.data);
    BSL_SAL_Free(msg.data);
    HITLS_CMS_Free(cms);
    HITLS_X509_CertFree(caCert);
    BSL_LIST_FREE(caCertList, (BSL_LIST_PFUNC_FREE)HITLS_X509_CertFree);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
