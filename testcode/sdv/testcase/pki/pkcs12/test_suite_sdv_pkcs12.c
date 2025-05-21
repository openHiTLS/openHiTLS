#include "test_common.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_load_key.h" // For CRYPT_EAL_LoadPrivateKeyBuff
#include "sal_file.h" // For BSL_SAL_ReadFileFull, BSL_SAL_GetFileSize
#include "bsl_err_internal.h" // For BSL_ERR_SetErrorStringFile, BSL_ERR_GetErrorCode
#include "bsl_tool.h" // For BSL_TOOL_MemCmp
#include "bsl_check.h" // For BSL_ASSERT_NOT_NULL

// Test data paths
#define TEST_DATA_BASE_DIR "testcode/testdata/" 
#define PKCS12_TEST_DATA_DIR TEST_DATA_BASE_DIR "pki/pkcs12/"

#define RECIPIENT_PRIVKEY_PEM PKCS12_TEST_DATA_DIR "recipient_privkey.pem"
#define CONTENT_CERT_PEM PKCS12_TEST_DATA_DIR "content_cert.pem"
#define CONTENT_PRIVKEY_PEM PKCS12_TEST_DATA_DIR "content_privkey.pem" 
#define PFX_ENVELOPED_P12 PKCS12_TEST_DATA_DIR "test_pfx_enveloped.p12"
#define PFX_PASSWORD_P12 PKCS12_TEST_DATA_DIR "test_pfx_password.p12" 
#define PFX_PASSWORD_HEX_P12 PKCS12_TEST_DATA_DIR "test_pfx_password.hex"


// Forward declarations
static CRYPT_EAL_PkeyCtx *LoadPrivateKeyFromFile(const char *filepath, const char *password);
static HITLS_X509_Cert *LoadCertificateFromFile(const char *filepath);
static int32_t LoadFileToBuffer(const char *filepath, BSL_Buffer *buffer);
static bool CompareCertificates(HITLS_X509_Cert *cert1, HITLS_X509_Cert *cert2);
static int32_t CreatePfxFileFromHex(const char* hex_filepath, const char* output_pfx_filepath);

static int32_t LoadFileToBuffer(const char *filepath, BSL_Buffer *buffer)
{
    BSL_ASSERT_NOT_NULL(filepath);
    BSL_ASSERT_NOT_NULL(buffer);

    long fileSize = BSL_SAL_GetFileSize(filepath);
    if (fileSize <= 0) {
        TEST_LOG_ERROR("Failed to get file size or file is empty: %s (size: %ld)", filepath, fileSize);
        return BSL_ERRNO_FILE_READ_FAILED;
    }

    buffer->data = (uint8_t *)BSL_SAL_Malloc((size_t)fileSize);
    if (buffer->data == NULL) {
        TEST_LOG_ERROR("Malloc failed for file buffer for %s", filepath);
        return BSL_ERRNO_MEM_ALLOC_FAILED;
    }
    buffer->dataLen = (uint32_t)fileSize;

    if (BSL_SAL_ReadFileFull(filepath, buffer->data, buffer->dataLen, &buffer->dataLen) != BSL_SUCCESS) {
        TEST_LOG_ERROR("Failed to read file: %s", filepath);
        BSL_SAL_Free(buffer->data);
        buffer->data = NULL;
        buffer->dataLen = 0;
        return BSL_ERRNO_FILE_READ_FAILED;
    }
    return BSL_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *LoadPrivateKeyFromFile(const char *filepath, const char *password)
{
    BSL_ASSERT_NOT_NULL(filepath);
    BSL_Buffer keyBuffer = {0};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer pwd = {0};

    if (LoadFileToBuffer(filepath, &keyBuffer) != BSL_SUCCESS) {
        // Error logged in LoadFileToBuffer
        return NULL;
    }

    if (password != NULL) {
        pwd.data = (uint8_t*)password;
        pwd.dataLen = (uint32_t)strlen(password);
    }

    int32_t ret = CRYPT_EAL_LoadPrivateKeyBuff(&keyBuffer, password ? &pwd : NULL, &pkeyCtx);
    if (ret != BSL_SUCCESS) {
        TEST_LOG_ERROR("CRYPT_EAL_LoadPrivateKeyBuff failed for %s with ret: %x. BSL_ERR: %x", filepath, ret, BSL_ERR_GetErrorCode());
        BSL_SAL_Free(keyBuffer.data);
        return NULL;
    }

    BSL_SAL_Free(keyBuffer.data);
    return pkeyCtx;
}

static HITLS_X509_Cert *LoadCertificateFromFile(const char *filepath)
{
    BSL_ASSERT_NOT_NULL(filepath);
    BSL_Buffer certBuffer = {0};
    HITLS_X509_Cert *cert = NULL;

    if (LoadFileToBuffer(filepath, &certBuffer) != BSL_SUCCESS) {
        // Error logged in LoadFileToBuffer
        return NULL;
    }

    int32_t ret = HITLS_X509_CertParseBuff(BSL_FORMAT_PEM, &certBuffer, &cert);
    if (ret != HITLS_PKI_SUCCESS) {
        TEST_LOG_ERROR("HITLS_X509_CertParseBuff failed for %s with ret: %d. BSL_ERR: %x", filepath, ret, BSL_ERR_GetErrorCode());
        BSL_SAL_Free(certBuffer.data);
        return NULL;
    }

    BSL_SAL_Free(certBuffer.data);
    return cert;
}

static bool CompareCertificates(HITLS_X509_Cert *cert1, HITLS_X509_Cert *cert2)
{
    if (cert1 == NULL || cert2 == NULL) {
        TEST_LOG_ERROR("One or both certificates are NULL for comparison.");
        return false;
    }

    BSL_Buffer buf1 = {0}, buf2 = {0};
    bool result = false;

    if (HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert1, &buf1) != HITLS_PKI_SUCCESS) {
        TEST_LOG_ERROR("Failed to generate ASN1 for cert1. BSL_ERR: %x", BSL_ERR_GetErrorCode());
        goto cleanup;
    }
    if (HITLS_X509_CertGenBuff(BSL_FORMAT_ASN1, cert2, &buf2) != HITLS_PKI_SUCCESS) {
        TEST_LOG_ERROR("Failed to generate ASN1 for cert2. BSL_ERR: %x", BSL_ERR_GetErrorCode());
        goto cleanup;
    }

    if (buf1.dataLen == 0 || buf2.dataLen == 0) {
        TEST_LOG_ERROR("One or both certificate ASN1 encodings are zero length.");
        goto cleanup;
    }
    
    if (buf1.dataLen == buf2.dataLen && BSL_TOOL_MemCmp(buf1.data, buf2.data, buf1.dataLen) == 0) {
        result = true;
    } else {
        TEST_LOG_ERROR("Certificate comparison failed. Lengths: %u vs %u.", buf1.dataLen, buf2.dataLen);
    }

cleanup:
    BSL_SAL_Free(buf1.data); 
    BSL_SAL_Free(buf2.data);
    return result;
}

static int32_t CreatePfxFileFromHex(const char* hex_filepath, const char* output_pfx_filepath) {
    if (BSL_SAL_GetFileSize(output_pfx_filepath) > 0) {
        return BSL_SUCCESS; // File already exists
    }

    char command[512];
    // Ensure paths are quoted if they might contain spaces (though unlikely here)
    sprintf(command, "xxd -r -p \"%s\" \"%s\"", hex_filepath, output_pfx_filepath);
    
    TEST_LOG_INFO("Attempting to create PFX from hex: %s", command);
    int sys_ret = system(command); 
    
    if (sys_ret == 0 && BSL_SAL_GetFileSize(output_pfx_filepath) > 0) {
        TEST_LOG_INFO("Successfully created %s from %s", output_pfx_filepath, hex_filepath);
        return BSL_SUCCESS;
    } else {
        TEST_LOG_ERROR("Failed to convert %s to %s using xxd. System ret: %d, output file size: %ld",
                       hex_filepath, output_pfx_filepath, sys_ret, BSL_SAL_GetFileSize(output_pfx_filepath));
        // Attempt to remove potentially empty/corrupt output file
        remove(output_pfx_filepath);
        return BSL_ERRNO_FILE_OPERATION_FAILED;
    }
}


static int32_t test_pkcs12_parse_enveloped_data_success(void)
{
    HITLS_PKCS12 *p12 = NULL;
    CRYPT_EAL_PkeyCtx *recipientKey = NULL;
    HITLS_X509_Cert *expectedCert = NULL;
    HITLS_X509_Cert *extractedCert = NULL;
    BSL_Buffer pfxBuffer = {0};
    int32_t ret;

    TEST_LOG_INFO("Starting test_pkcs12_parse_enveloped_data_success");

    TEST_CASE_REQUIRE_TRUE_MSG(LoadFileToBuffer(PFX_ENVELOPED_P12, &pfxBuffer) == BSL_SUCCESS, "Load PFX_ENVELOPED_P12 failed");
    
    recipientKey = LoadPrivateKeyFromFile(RECIPIENT_PRIVKEY_PEM, NULL);
    TEST_CASE_REQUIRE_TRUE_MSG(recipientKey != NULL, "LoadPrivateKeyFromFile for recipient failed");

    expectedCert = LoadCertificateFromFile(CONTENT_CERT_PEM);
    TEST_CASE_REQUIRE_TRUE_MSG(expectedCert != NULL, "LoadCertificateFromFile for content_cert failed");
    
    HITLS_PKCS12_PwdParam pwdParam = {0};
    pwdParam.recipientPkeyCtx = recipientKey;

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &pfxBuffer, &pwdParam, &p12, false); // false for no MAC check
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKI_SUCCESS, "HITLS_PKCS12_ParseBuff for EnvelopedData failed. BSL_ERR: %x", BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(p12 != NULL, "p12 context is NULL after successful parse");

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, (void**)&extractedCert, 0);
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKI_SUCCESS, "HITLS_PKCS12_Ctrl GET_ENTITY_CERT failed. BSL_ERR: %x", BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(extractedCert != NULL, "Extracted certificate is NULL");
    
    TEST_CASE_REQUIRE_TRUE_MSG(CompareCertificates(expectedCert, extractedCert), "Extracted certificate does not match expected content certificate");

    HITLS_PKCS12_Free(p12);
    CRYPT_EAL_PkeyFreeCtx(recipientKey);
    HITLS_X509_CertFree(expectedCert);
    HITLS_X509_CertFree(extractedCert);
    BSL_SAL_Free(pfxBuffer.data);

    TEST_LOG_INFO("Finished test_pkcs12_parse_enveloped_data_success");
    return TEST_RESULT_SUCCESS;
}

static int32_t test_pkcs12_parse_enveloped_data_no_key(void)
{
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer pfxBuffer = {0};
    int32_t ret;
    TEST_LOG_INFO("Starting test_pkcs12_parse_enveloped_data_no_key");

    TEST_CASE_REQUIRE_TRUE_MSG(LoadFileToBuffer(PFX_ENVELOPED_P12, &pfxBuffer) == BSL_SUCCESS, "Load PFX_ENVELOPED_P12 failed");

    HITLS_PKCS12_PwdParam pwdParam = {0}; 
    pwdParam.recipientPkeyCtx = NULL;

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &pfxBuffer, &pwdParam, &p12, false);
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKCS12_ERR_NO_RECIPIENT_KEY, "ParseBuff with NULL recipient key did not return HITLS_PKCS12_ERR_NO_RECIPIENT_KEY. Got %x, BSL_ERR: %x", ret, BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(p12 == NULL, "p12 context should be NULL on failure");

    BSL_SAL_Free(pfxBuffer.data);
    TEST_LOG_INFO("Finished test_pkcs12_parse_enveloped_data_no_key");
    return TEST_RESULT_SUCCESS;
}

static int32_t test_pkcs12_parse_enveloped_data_wrong_key(void)
{
    HITLS_PKCS12 *p12 = NULL;
    CRYPT_EAL_PkeyCtx *wrongKey = NULL;
    BSL_Buffer pfxBuffer = {0};
    int32_t ret;
    TEST_LOG_INFO("Starting test_pkcs12_parse_enveloped_data_wrong_key");

    TEST_CASE_REQUIRE_TRUE_MSG(LoadFileToBuffer(PFX_ENVELOPED_P12, &pfxBuffer) == BSL_SUCCESS, "Load PFX_ENVELOPED_P12 failed");
    
    wrongKey = LoadPrivateKeyFromFile(CONTENT_PRIVKEY_PEM, NULL); 
    TEST_CASE_REQUIRE_TRUE_MSG(wrongKey != NULL, "LoadPrivateKeyFromFile for wrongKey failed");
    
    HITLS_PKCS12_PwdParam pwdParam = {0};
    pwdParam.recipientPkeyCtx = wrongKey;

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &pfxBuffer, &pwdParam, &p12, false);
    TEST_CASE_REQUIRE_TRUE_MSG(ret != HITLS_PKI_SUCCESS, "ParseBuff with wrong key succeeded unexpectedly");
    TEST_LOG_INFO("ParseBuff with wrong key returned %x, BSL_ERR: %x", ret, BSL_ERR_GetErrorCode());
    // A more specific check could be BSL_ERR_GetErrorCode() == BSL_ERRNO_PKEY_DECRYPT_FAILED or similar CMS error
    TEST_CASE_REQUIRE_TRUE_MSG(p12 == NULL, "p12 context should be NULL on failure");

    CRYPT_EAL_PkeyFreeCtx(wrongKey);
    BSL_SAL_Free(pfxBuffer.data);
    TEST_LOG_INFO("Finished test_pkcs12_parse_enveloped_data_wrong_key");
    return TEST_RESULT_SUCCESS;
}

static int32_t test_pkcs12_parse_password_basic_regression(void)
{
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer pfxBuffer = {0};
    HITLS_X509_Cert *extractedCert = NULL;
    CRYPT_EAL_PkeyCtx *extractedKey = NULL;
    int32_t ret;
    TEST_LOG_INFO("Starting test_pkcs12_parse_password_basic_regression");

    if (CreatePfxFileFromHex(PFX_PASSWORD_HEX_P12, PFX_PASSWORD_P12) != BSL_SUCCESS) {
        TEST_LOG_INFO("Skipping password PFX regression test as %s could not be created from %s.", PFX_PASSWORD_P12, PFX_PASSWORD_HEX_P12);
        return TEST_RESULT_SKIP;
    }

    TEST_CASE_REQUIRE_TRUE_MSG(LoadFileToBuffer(PFX_PASSWORD_P12, &pfxBuffer) == BSL_SUCCESS, "Load PFX_PASSWORD_P12 failed");

    BSL_Buffer macPwd = {(uint8_t*)"password", (uint32_t)strlen("password")};
    BSL_Buffer encPwd = {(uint8_t*)"password", (uint32_t)strlen("password")};
    HITLS_PKCS12_PwdParam pwdParam = {&macPwd, &encPwd, NULL};

    ret = HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &pfxBuffer, &pwdParam, &p12, true); // true for MAC check
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKI_SUCCESS, "HITLS_PKCS12_ParseBuff for password PFX failed. BSL_ERR: %x", BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(p12 != NULL, "p12 is NULL after password PFX parse");

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_CERT, (void**)&extractedCert, 0);
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKI_SUCCESS, "GET_ENTITY_CERT from password PFX failed. BSL_ERR: %x", BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(extractedCert != NULL, "Extracted cert from password PFX is NULL");

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEY, (void**)&extractedKey, 0);
    TEST_CASE_NRESULTS_MSG(ret, HITLS_PKI_SUCCESS, "GET_ENTITY_KEY from password PFX failed. BSL_ERR: %x", BSL_ERR_GetErrorCode());
    TEST_CASE_REQUIRE_TRUE_MSG(extractedKey != NULL, "Extracted key from password PFX is NULL");

    HITLS_PKCS12_Free(p12);
    HITLS_X509_CertFree(extractedCert);
    CRYPT_EAL_PkeyFreeCtx(extractedKey);
    BSL_SAL_Free(pfxBuffer.data);

    TEST_LOG_INFO("Finished test_pkcs12_parse_password_basic_regression");
    return TEST_RESULT_SUCCESS;
}

// Dummy test case to represent potentially existing tests in the file.
static int32_t test_pkcs12_existing_placeholder(void)
{
    TEST_LOG_INFO("Running existing placeholder test.");
    // Imagine existing test logic here...
    return TEST_RESULT_SUCCESS;
}

void AddSuiteSdvPkcs12Test(void)
{
    // It's important to call AddTestCase for any tests that were already in this file.
    // If this is a new file, or if we are intentionally replacing all old tests,
    // then only the new ones are needed.
    // Assuming for this exercise we are adding to potentially existing tests:
    AddTestCase("test_pkcs12_existing_placeholder", test_pkcs12_existing_placeholder);


    // Add new tests for EnvelopedData
    AddTestCase("test_pkcs12_parse_enveloped_data_success", test_pkcs12_parse_enveloped_data_success);
    AddTestCase("test_pkcs12_parse_enveloped_data_no_key", test_pkcs12_parse_enveloped_data_no_key);
    AddTestCase("test_pkcs12_parse_enveloped_data_wrong_key", test_pkcs12_parse_enveloped_data_wrong_key);
    
    // Add regression test for basic password parsing
    AddTestCase("test_pkcs12_parse_password_basic_regression", test_pkcs12_parse_password_basic_regression);
}

#ifndef TC_MANUAL
void AppMain(void) 
{
    SdvTestRun("PKCS12_TEST_SUITE"); 
    AddSuiteSdvPkcs12Test(); 
    SdvTestRunCases("PKCS12_TEST_CASES", false); 
}
#endif