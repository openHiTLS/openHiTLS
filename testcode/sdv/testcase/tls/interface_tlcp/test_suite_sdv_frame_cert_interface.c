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
/* INCLUDE_BASE test_suite_interface */

#include <stdio.h>
#include "hitls_error.h"
#include "hitls_pki_errno.h"
#include "hitls_cert.h"
#include "hitls.h"
#include "hitls_func.h"
#include "securec.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert_mgr_ctx.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "session.h"
#include "bsl_list.h"
#include "bsl_sal.h"
#include "bsl_uio.h"
#include "alert.h"
#include "cert_callback.h"
#include "crypt_eal_rand.h"
#include "hitls_crypt_reg.h"
#include "hitls_crypt_init.h"
#include "uio_base.h"
#include "hitls_pki_types.h"
/* END_HEADER */

#define BUF_MAX_SIZE 4096
int32_t g_uiPort = 18886;
static int TestHITLS_VerifyCb(int32_t isPreverifyOk, HITLS_CERT_StoreCtx *storeCtx)
{
    (void)isPreverifyOk;
    (void)storeCtx;
    return 0;
}

static int32_t TestPasswordCb(char *buf, int32_t bufLen, int32_t flag, void *userdata)
{
    (void)flag;
    char *passwd = NULL;
    static char pass[] = "123456";
    if (userdata != NULL) {
        passwd = userdata;
    } else {
        passwd = pass;
    }
    int32_t len = strlen(passwd);
    if (len > bufLen) {
        return -1;
    }

    memcpy(buf, passwd, len);
    return len;
}

static uint32_t ReadFileBuffer(const char *filePath, char *data)
{
    FILE *fd;
    uint32_t size;
    uint32_t bytes;

    fd = fopen(filePath, "rb");
    if (fd == NULL) {
        return 0;
    }

    (void)fseek(fd, 0, SEEK_END);
    size = (uint32_t)ftell(fd);
    rewind(fd);

    bytes = (uint32_t)fread(data, 1, size, fd);
    (void)fclose(fd);
    if (bytes != size) {
        return 0;
    }

    return bytes;
}

/* @
* @test    UT_TLS_CERT_CM_SetVerifyDepth_API_TC001
* @title   The input parameter of the HITLS_SetVerifyDepth interface is replaced.
* @precon  This test case covers the HITLS_SetVerifyDepth, HITLS_GetVerifyDepth
* @brief   1.Invoke the HITLS_SetVerifyDepth interface. The value of ctx is empty and the value of depth is not empty.
*            Expected result 1 is obtained.
*          2.Invoke the HITLS_SetVerifyDepth interface. The values of ctx and depth are not empty.
*            Expected result 2 is obtained.
*          3.Invoke the HITLS_GetVerifyDepth interface. The ctx field is empty and the depth address is not empty.
*            Expected result 1 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns HITLS_NULL_INPUT
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetVerifyDepth_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    uint32_t depth = 5;
    int32_t dep = 0;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetVerifyDepth(NULL, depth) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetVerifyDepth(ctx, depth), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyDepth(ctx, &dep) == HITLS_SUCCESS);
    ASSERT_EQ(depth, dep);
    ASSERT_TRUE(HITLS_GetVerifyDepth(NULL, &dep) == HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CFG_SetDefaultPasswordCb_FUNC_001
* @title   Set the password callback and set the user data defaultPasswdCbUserdata.
* @precon  This test case covers the HITLS_CFG_SetDefaultPasswordCb, HITLS_CFG_GetDefaultPasswordCb,
*          HITLS_CFG_SetDefaultPasswordCbUserdata, HITLS_CFG_GetDefaultPasswordCbUserdata
* @brief   1. Create a CTX object. Expected result 1 is obtained.
*          2. Set the password callback and set the incorrect user data defaultPasswdCbUserdata.
*             Expected result 2 is obtained.
* @expect  1. Created successfully.
*          2. Failed to load the encrypted private key file.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_SetDefaultPasswordCb_FUNC_001(int version, char *keyFile, char *userdata)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ASSERT_TRUE(HITLS_CFG_SetDefaultPasswordCb(tlsConfig, TestPasswordCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDefaultPasswordCb(tlsConfig) == TestPasswordCb);
    ASSERT_TRUE(HITLS_CFG_SetDefaultPasswordCbUserdata(tlsConfig, userdata)== HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDefaultPasswordCbUserdata(tlsConfig) == userdata);

#ifdef HITLS_TLS_FEATURE_PROVIDER
    ASSERT_EQ(HITLS_CFG_ProviderLoadKeyFile(tlsConfig, keyFile, "ASN1", NULL),
        HITLS_CFG_ERR_LOAD_KEY_FILE);
#else
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(tlsConfig, keyFile, TLS_PARSE_FORMAT_ASN1), HITLS_CFG_ERR_LOAD_KEY_FILE);
#endif

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_SetDefaultPasswordCbUserdata_API_TC001
* @title   The input parameter of the HITLS_SetDefaultPasswordCbUserdata interface is replaced.
* @precon  This test case covers the HITLS_SetDefaultPasswordCbUserdata, HITLS_GetDefaultPasswordCbUserdata
* @brief   1.Invoke the HITLS_SetDefaultPasswordCbUserdata interface. The value of ctx is empty and the value of
*            userdata is not empty. Expected result 1 is obtained.
*          2.Invoke the HITLS_SetDefaultPasswordCbUserdata interface. The values of ctx and userdata are not empty.
*            Expected result 2 is obtained.
*          3.Invoke the HITLS_GetDefaultPasswordCbUserdata interface and leave ctx blank. Expected result 3 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
*          3.Returns NULL
           
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetDefaultPasswordCbUserdata_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    char *userData = "123456";

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_SetDefaultPasswordCbUserdata(NULL, userData) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetDefaultPasswordCbUserdata(ctx, userData) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetDefaultPasswordCbUserdata(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetDefaultPasswordCbUserdata(ctx) == userData);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CFG_LoadCertFile_API_TC001
* @title   HITLS_CFG_LoadCertFile Loading a Device Certificate from a File
* @precon  This test case covers the HITLS_CFG_LoadCertFile, HITLS_CFG_SetDefaultPasswordCbUserdata,
*          HITLS_CFG_GetDefaultPasswordCbUserdata, HITLS_CFG_LoadKeyFile
* @brief   1. Apply for a configuration file. Expected result 1 is obtained.
*          2. Load an incorrect path. Expected result 2 is obtained.
*          3. Use the same keyword "123456" for mac word and pass word. Expected result 3 is obtained.
* @expect  1. The application is successful.
*          2. Failed to load the certificate.
*          3. The certificate is loaded successfully.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_LoadCertFile_API_TC001(int version, char *certFile1, char *certFile2, char *keyFile2, char *userdata)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ASSERT_EQ(
        HITLS_CFG_LoadCertFile(tlsConfig, certFile1, TLS_PARSE_FORMAT_ASN1), HITLS_CFG_ERR_LOAD_CERT_FILE);
    ASSERT_TRUE(HITLS_CFG_SetDefaultPasswordCbUserdata(tlsConfig, userdata) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetDefaultPasswordCbUserdata(tlsConfig) == userdata);
    ASSERT_TRUE(HITLS_CFG_LoadCertFile(tlsConfig, certFile2, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ASSERT_TRUE(HITLS_CFG_ProviderLoadKeyFile(tlsConfig, keyFile2, "ASN1", NULL) == HITLS_SUCCESS);
#else
    ASSERT_TRUE(HITLS_CFG_LoadKeyFile(tlsConfig, keyFile2, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
#endif
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test  UT_TLS_CERT_CFG_LoadCertBuffer_FUNC_001
* @title  HITLS_CFG_LoadCertBuffer Loads and Obtains the Device Certificate from the Buffer
* @precon  nan
* @brief  1. Create a CTX object. Expected result 1 is obtained.
*         2. In the local context, the store is not initialized. Invoke HITLS_CFG_GetCertificate to obtain the device
*            certificate. Expected result 2 is obtained.
*         3. Call the interface to convert the certificate file into a buffer. Expected result 3 is obtained.
*         4. Delete one byte from the buffer, that is, buffer1. Expected result 4 is obtained.
*         5. Add one byte to the buffer, that is, buffer2. Expected result 5 is obtained.
*         6. Call the interface to set the device certificate through buffer1. Expected result 6 is obtained.
*         7. Call the interface to set the device certificate through buffer2. Expected result 7 is obtained.
*         8. Call the interface to set the device certificate through the buffer. Expected result 8 is obtained.
*         9. Call the interface repeatedly to set the device certificate through the buffer. Expected result 9 is
*            obtained.
* @expect 1. Created successfully.
*         2. The obtained content is empty.
*         3. The file is converted successfully.
*         4. Deleted successfully.
*         5. Adding succeeded.
*         6. Failed to load the device certificate.
*         7. Failed to load the device certificate.
*         8. Succeeded in loading the device certificate.
*         9. Failed to load the device certificate.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_LoadCertBuffer_FUNC_001(int version, char *certPath)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    uint8_t buf[BUF_MAX_SIZE] = {0};
    uint32_t bufLen = ReadFileBuffer(certPath, (char *)buf);
    ASSERT_TRUE(buf != NULL);
    ASSERT_TRUE(bufLen <= BUF_MAX_SIZE);
    uint8_t buf2[BUF_MAX_SIZE]  = {0};
    (void)memcpy_s(buf2, bufLen, buf, bufLen);

    buf2[bufLen - 1] = 'b';
    buf2[bufLen] = 0;
    uint8_t buf1[BUF_MAX_SIZE]  = {0};
    (void)memcpy_s(buf1, bufLen, buf, bufLen);

    buf1[bufLen - 2] = 0;
    ASSERT_TRUE(HITLS_CFG_LoadCertBuffer(tlsConfig, buf, bufLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
    ASSERT_EQ(
        HITLS_CFG_LoadCertBuffer(tlsConfig, buf1, bufLen - 1, TLS_PARSE_FORMAT_ASN1), HITLS_CFG_ERR_LOAD_CERT_BUFFER);
    ASSERT_TRUE(HITLS_CFG_LoadCertBuffer(tlsConfig, buf2, bufLen + 1, TLS_PARSE_FORMAT_ASN1) != HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_LoadCertBuffer(tlsConfig, buf, bufLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_LoadCertFile_API_TC001
* @title   The input parameter of the HITLS_LoadCertFile interface is replaced.
* @precon  nan
* @brief   1.Invoke the HITLS_LoadCertFile interface. The ctx field is empty, the device certificate file name is not
*            empty, and the certificate format is PEM. Expected result 1 is obtained.
*          2.Invoke the HITLS_LoadCertFile interface. The ctx parameter is not empty, the device certificate file name
*            is not empty, and the certificate format is PEM. Expected result 2 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_LoadCertFile_API_TC001(int version, char *certFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_LoadCertFile(NULL, NULL, TLS_PARSE_FORMAT_ASN1) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_LoadCertFile(ctx, certFile, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test     UT_TLS_CERT_CM_LoadCertBuffer_API_TC001
* @title    The input parameter of the HITLS_LoadCertBuffer interface is replaced.
* @precon   nan
* @brief   1.Invoke the HITLS_LoadCertBuffer interface. The ctx field is empty, the certificate buffer is not empty, the
*            buffer length is the actual buffer length, and the certificate format is PEM. Expected result 1 is
*            displayed.
*          2.Invoke the HITLS_LoadCertBuffer interface. Ensure that ctx is not empty, the device certificate file name
*            is not empty, and the certificate format is PEM. Expected result 2 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_LoadCertBuffer_API_TC001(int version, char *certFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    uint8_t certBuffer[BUF_MAX_SIZE] = {0};
    uint32_t certBuffLen = ReadFileBuffer(certFile, (char *)certBuffer);
    ASSERT_TRUE(certBuffLen <= BUF_MAX_SIZE);
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_LoadCertBuffer(NULL, certBuffer, certBuffLen, TLS_PARSE_FORMAT_ASN1) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_LoadCertBuffer(ctx, certBuffer, certBuffLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */


/* @
* @test  UT_TLS_CERT_CFG_LoadKeyBuffer_FUNC_TC001
* @title  Load the private key from buffer by using HITLS_CFG_LoadKeyBuffer interface
* @precon  nan
* @brief  1. Apply for a configuration file. Expected result 1 is obtained
*       2. Call the API to convert the certificate file into a buffer. Expected result 2 is displayed
*       3. Delete one byte from the buffer, that is, buf1. Expected result 3 is obtained
*       4. Add one byte to the buffer, that is, buf2. Expected result 4
*       5. Call the interface to load the private key through buf1. Expected result 5
*       6. Call the interface to load the private key through buf2. Expected result 6
*       7. Invoke the interface to load the private key through the buffer. Expected result 7
*       8. Invoke the interface repeatedly to load the private key through the buffer. Expected result 8 is obtained
* @expect  1. The application is successful.
*       2. The file is converted successfully.
*       3. The deletion is successful.
*       4. The addition is successful.
*       5. The private key fails to be loaded.
*       6. The private key success to be loaded.
*       7. The private key is loaded.
*       8. The private key fails to be loaded
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_LoadKeyBuffer_FUNC_TC001(int version, char *keyPath)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    uint8_t buf[BUF_MAX_SIZE] = {0};
    uint32_t bufLen = ReadFileBuffer(keyPath, (char *)buf);
    ASSERT_TRUE(buf != NULL);
    ASSERT_TRUE(bufLen <= BUF_MAX_SIZE);
    uint8_t buf2[BUF_MAX_SIZE]  = {0};
    memcpy_s(buf2, bufLen, buf, bufLen);
    buf2[bufLen - 1] = 'a';
    buf2[bufLen] = 0;
    uint8_t buf1[BUF_MAX_SIZE]  = {0};
    memcpy_s(buf1, bufLen, buf, bufLen);
    buf1[bufLen - 2] = 0;
    ASSERT_TRUE(HITLS_CFG_LoadKeyBuffer(tlsConfig, buf, bufLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
    ASSERT_EQ(
        HITLS_CFG_LoadKeyBuffer(tlsConfig, buf1, bufLen - 1, TLS_PARSE_FORMAT_ASN1), HITLS_CFG_ERR_LOAD_KEY_BUFFER);
    ASSERT_EQ(
        HITLS_CFG_LoadKeyBuffer(tlsConfig, buf2, bufLen + 1, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_LoadKeyBuffer(tlsConfig, buf, bufLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test     UT_TLS_CERT_CM_LoadKeyFile_API_TC001
* @title    The error input parameter for HITLS_LoadKeyFile
* @precon   nan
* @brief  1.Invoke the HITLS_LoadKeyFile interface. The ctx field is empty, the private key file name is not empty,
*           and the private key format is PEM. Expected result 1
*         2.Invoke the HITLS_LoadKeyFile interface. The ctx field is not empty. The private key file name is not empty
*           and the private key is in PEM format. Expected result 2 is obtained
* @expect 1.Back HITLS_NULL_INPUT
*         2.Back HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_LoadKeyFile_API_TC001(int version, char *keyFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_LoadKeyFile(NULL, keyFile, TLS_PARSE_FORMAT_ASN1) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_LoadKeyFile(ctx, keyFile, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test      UT_TLS_SetAndGetCert_FUNC_TC001
* @title     Set and get verify result
* @precon    nan
* @brief  1. Construct the CTX configuration and initialize the session and certificate management. Expected results 1
*         2. Call HITLS_GetVerifyResult to query the peer certificate verification result of the current context. Expected result 2
*         3. Call HITLS_SetVerifyResult to set the peer certificate verification result of the current context. Expected result 3
*         4. Call HITLS_GetVerifyResult to query the peer certificate verification result of the current context. Expected result 4 is obtained
* @expect 1. Initialization succeeded.
*         2. The verification result is 0.
*         3. The setting result is successful.
*         4. The verification result is the set value
@ */
/* BEGIN_CASE */
void UT_TLS_SetAndGetCert_FUNC_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    HITLS_ERROR result;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_GetVerifyResult(ctx, &result) == HITLS_SUCCESS);
    ASSERT_EQ(result, HITLS_X509_V_OK);
    ASSERT_TRUE(HITLS_SetVerifyResult(ctx, (HITLS_ERROR)HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyResult(ctx, &result) == HITLS_SUCCESS);
    ASSERT_TRUE(result == (HITLS_ERROR)HITLS_X509_ERR_ISSUE_CERT_NOT_FOUND);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_LoadKeyBuffer_API_TC001
* @title   The error input parameter for HITLS_LoadKeyBuffer
* @precon  nan
* @brief   1. Invoke the HITLS_LoadKeyBuffer interface. The ctx field is empty, the private key buffer is not empty,
*             the buffer length is the actual buffer length, and the private key format is PEM. Expected result 1 is
*             displayed.
*          2. Invoke the HITLS_LoadKeyBuffer interface. The ctx and private key buffer are not empty, the buffer length
*             is the actual buffer length, and the private key format is pem. The expected result is 1
* @expect  1. HITLS_NULL_INPUT is returned
*          2. HITLS_SUCCESS is returned
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_LoadKeyBuffer_API_TC001(int version, char *keyFile)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    uint8_t keyBuffer[BUF_MAX_SIZE] = {0};
    uint32_t keyBuffLen = ReadFileBuffer(keyFile, (char *)keyBuffer);
    ASSERT_TRUE(keyBuffLen <= BUF_MAX_SIZE);
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);

    ASSERT_TRUE(HITLS_LoadKeyBuffer(NULL, keyBuffer, keyBuffLen, TLS_PARSE_FORMAT_ASN1) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_LoadKeyBuffer(ctx, keyBuffer, keyBuffLen, TLS_PARSE_FORMAT_ASN1) == HITLS_SUCCESS);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/* @
* @test   UT_TLS_CERT_CFG_SetTlcpCertificate_FUNC_001
*         If an unrecognized record type is received, ignore it.
* @title  There are only four types of record layers.
* @precon Test Content: Record layer protocols include: handshake, alarm, and password specification change.
*         To support protocol extensions, the record layer protocol may support other record types.
*         Any new record types should be deassigned in addition to the Content Type values assigned for the types
*         described above.
*         In this test case, interface HITLS_CFG_SetTlcpCertificate, HITLS_CFG_SetTlcpPrivateKey is invoked at the
*         bottom layer.
* @brief  After the link is set up, the server receives abnormal messages (the recordType is 99) after receiving
*         app data. The server is expected to return an alert.
* @expect 1. HITLS_REC_ERR_RECV_UNEXPECTED_MSG is returned
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_SetTlcpCertificate_FUNC_001(void)
{
    FRAME_Init();
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLCPConfig();
    ASSERT_TRUE(tlsConfig != NULL);

    uint16_t cipherSuite[] = {HITLS_ECDHE_SM4_CBC_SM3, HITLS_ECC_SM4_CBC_SM3};
    HITLS_CFG_SetCipherSuites(tlsConfig, cipherSuite, sizeof(cipherSuite) / sizeof(uint16_t));

    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    client = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, true);
    server = FRAME_CreateTLCPLink(tlsConfig, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);
    ASSERT_TRUE(clientTlsCtx->state == CM_STATE_IDLE);
    ASSERT_TRUE(serverTlsCtx->state == CM_STATE_IDLE);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    uint8_t dataBuf[] = "Hello World!";
    uint8_t readBuf[READ_BUF_SIZE];
    uint32_t readbytes;
    uint32_t writeLen;
    ASSERT_EQ(HITLS_Write(client->ssl, dataBuf, sizeof(dataBuf), &writeLen), HITLS_SUCCESS);
    ASSERT_TRUE(FRAME_TrasferMsgBetweenLink(client, server) == HITLS_SUCCESS);
    FrameUioUserData *ioServerData = BSL_UIO_GetUserData(server->io);
    ioServerData->recMsg.msg[0] = 0x99u;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readbytes), HITLS_REC_ERR_RECV_UNEXPECTED_MSG);
    ALERT_Info info = { 0 };
    ALERT_GetInfo(server->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_UNEXPECTED_MESSAGE);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CFG_SetVerifyCb_API_TC001
* @title   HITLS_CFG_SetVerifyCb interface input parameter test
* @precon  This test case covers the HITLS_CFG_SetVerifyCb, HITLS_CFG_GetVerifyCb
* @brief   1. Invoke the HITLS_CFG_SetVerifyCb interface. Input empty tlsConfig and non-empty certificate verification
*          callback. Expected result 1
*          2. Invoke the HITLS_CFG_SetVerifyCb interface. Input non-empty tlsConfig and non-empty certificate
*          verification callback. Expected result 3
*          3. Invoke the HITLS_CFG_GetVerifyCb interface. Input empty tlsConfig, Expected result 2
*          4. Invoke the HITLS_CFG_SetVerifyCb interface. Input empty tlsConfig->certMgrCtx, and non-empty certificate
*          verification callback, Expected result 1
*          5. Invoke the HITLS_CFG_GetVerifyCb interface. Input empty tlsConfig->certMgrCtx, Expected result 2
*          Expected result 2
* @expect  1. Return HITLS_NULL_INPUT
*          2. Return NULL
*          3. Return HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CFG_SetVerifyCb_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ASSERT_TRUE(HITLS_CFG_SetVerifyCb(NULL, TestHITLS_VerifyCb) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_SetVerifyCb(tlsConfig, TestHITLS_VerifyCb) == HITLS_SUCCESS);

    ASSERT_TRUE(HITLS_CFG_GetVerifyCb(tlsConfig) == TestHITLS_VerifyCb);
    ASSERT_TRUE(HITLS_CFG_GetVerifyCb(NULL) == NULL);
    SAL_CERT_MgrCtxFree(tlsConfig->certMgrCtx);
    tlsConfig->certMgrCtx = NULL;
    ASSERT_TRUE(HITLS_CFG_SetVerifyCb(tlsConfig, TestHITLS_VerifyCb) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetVerifyCb(tlsConfig) == NULL);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_SetVerifyCb_API_TC001
* @title   HITLS_SetVerifyCb interface input parameter test
* @precon  This test case covers the HITLS_SetVerifyCb, HITLS_GetVerifyCb
* @brief   1.Invoke the HITLS_SetVerifyCb interface. Input empty ctx and non-empty certificate verification
*          callback. Expected result 1
*          2.Invoke the HITLS_SetVerifyCb interface. Input non-empty ctx and non-empty certificate verification
*          callback. Expected result 2
*          3.Invoke the HITLS_GetVerifyCb interface. Input empty ctx, Expected result 3
* @expect  1.Return HITLS_NULL_INPUT
*          2.Return HITLS_SUCCESS
*          3.Return NULL
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetVerifyCb_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_SetVerifyCb(NULL, TestHITLS_VerifyCb) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_SetVerifyCb(ctx, TestHITLS_VerifyCb) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyCb(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetVerifyCb(ctx) == TestHITLS_VerifyCb);
EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

/*
* @test UT_TLS_CERT_GET_CERTIFICATE_API_TC001
*
* @title Overwrite the input parameter of the HITLS_GetCertificate interface.
*
* @brief
* 1. Invoke the HITLS_GetCertificate interface and leave ctx blank. Expected result 1.
* 2. Invoke the HITLS_GetPeerCertificate interface and leave ctx blank. Expected result 1.
* 3. Invoke the HITLS_GetPeerCertificate interface. The value of ctx is not empty and the value of ctx->session is empty.
*    Expected result 1.
* 4. Invoke the HITLS_GetPeerCertChain interface and leave ctx blank. Expected result 1.
* 5. Invoke the HITLS_GetPeerCertChain interface. The value of ctx is not empty and the value of ctx->session is empty.
*    Expected result 1 .
* @expect 1.  Return NULL.
* @prior Level 1
* @auto TRUE
*/

/* BEGIN_CASE */
void UT_TLS_CERT_GET_CERTIFICATE_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ASSERT_TRUE(HITLS_GetCertificate(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertificate(NULL) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertChain(NULL) == NULL);
    ctx->session = NULL;
    ASSERT_TRUE(HITLS_GetPeerCertificate(ctx) == NULL);
    ASSERT_TRUE(HITLS_GetPeerCertChain(ctx) == NULL);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */

void StubListDataDestroy(void *data)
{
    BSL_SAL_FREE(data);
    return;
}

/* @
* @test  UT_TLS_CERT_GET_CALIST_FUNC_TC001
*
* @title Obtain the peer certificate chain and trusted CA list.
*
* @brief
*   1. Construct the CTX configuration. Expected result 1.
*   2. Invoke HITLS_GetPeerCertChain to obtain the peer certificate chain. Expected result 2.
*   3. Configure a certificate management instance for the session instance. Expected result 3.
*   4. Add the session instance to the SSL instance. Expected result 4.
*   5. If no certificate is loaded to the peer end, call HITLS_GetPeerCertificate to obtain the peer certificate.
*   Expected result 5.
*   6. Create a peer certificate management instance and a certificate chain. Expected result 6.
*   7. Add the created certificates to the certificate linked list one by one. Expected result 7.
*   8. Invoke HITLS_GetPeerCertChain to obtain the peer certificate chain. Expected result 8.
*   9. Invoke the HITLS_GetPeerCAList client certificate authority (CA) list. Expected result 9.
* @expect
*   1. The creation is successful.
*   2. Obtaining failed. The session is empty.
*   3. The setting is successful, and the interface returns 0.
*   4. If the setting is successful, the interface returns 0.
*   5. Failed to obtain the certificate. The certificate is empty.
*   6. The peerCert and certificate chain are successfully created.
*   7. The interface returns 0.
*   8. The certificate successfully. The obtained peer certificate chain is correct. The obtained cert is
*    correct.
*   9. The obtained CA certificate list is correct. The obtained cert is correct.
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_GET_CALIST_FUNC_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);
    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    ctx->isClient = true;

    HITLS_Session *session = HITLS_SESS_New();
    ASSERT_TRUE(session != NULL);
    CERT_Pair *peerCert = (CERT_Pair *)BSL_SAL_Calloc(1u, sizeof(CERT_Pair));

    HITLS_CERT_X509 *cert1 = (HITLS_CERT_X509 *)BSL_SAL_Calloc(1u, sizeof(HITLS_CERT_X509));
    HITLS_CERT_X509 *cert2 = (HITLS_CERT_X509 *)BSL_SAL_Calloc(1u, sizeof(HITLS_CERT_X509));
    HITLS_CERT_X509 *cert3 = (HITLS_CERT_X509 *)BSL_SAL_Calloc(1u, sizeof(HITLS_CERT_X509));

    peerCert->chain = (HITLS_CERT_Chain *)BSL_LIST_New(sizeof(HITLS_CERT_X509 *));
    ASSERT_TRUE(peerCert->chain != NULL);

    HITLS_CERT_Chain *certChain = peerCert->chain;

    int32_t ret = BSL_LIST_AddElement((BslList *)certChain, cert1, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == 0);
    ret = BSL_LIST_AddElement((BslList *)certChain, cert2, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == 0);
    ret = BSL_LIST_AddElement((BslList *)certChain, cert3, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == 0);

    ret = SESS_SetPeerCert(session, peerCert, false);
    ASSERT_TRUE(ret == HITLS_SUCCESS);


    ASSERT_TRUE(HITLS_SetSession(ctx, session) == HITLS_SUCCESS);


    HITLS_CERT_Chain *getCertChain = HITLS_GetPeerCertChain(ctx);
    ASSERT_TRUE(getCertChain != NULL);

    HITLS_TrustedCAList *tmpCAList = ctx->peerInfo.caList;

    HITLS_TrustedCANode *newNode1 = (HITLS_TrustedCANode *)BSL_SAL_Calloc(1, sizeof(HITLS_TrustedCANode));
    ASSERT_TRUE(newNode1 != NULL);
    newNode1->caType = HITLS_TRUSTED_CA_X509_NAME;
    newNode1->data = NULL;
    newNode1->dataSize = 0;

    HITLS_TrustedCANode *newNode2 = (HITLS_TrustedCANode *)BSL_SAL_Calloc(1, sizeof(HITLS_TrustedCANode));
    ASSERT_TRUE(newNode2 != NULL);
    newNode2->caType = HITLS_TRUSTED_CA_X509_NAME;
    newNode2->data = NULL;
    newNode2->dataSize = 0;
    ret = BSL_LIST_AddElement((BslList *)tmpCAList, newNode1, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == 0);

    ret = BSL_LIST_AddElement((BslList *)tmpCAList, newNode2, BSL_LIST_POS_END);
    ASSERT_TRUE(ret == 0);
    HITLS_TrustedCAList *caList = HITLS_GetPeerCAList(ctx);
    ASSERT_TRUE(caList != NULL);
    ASSERT_EQ(caList->count, 2);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    BSL_LIST_DeleteAll((BslList *)peerCert->chain, StubListDataDestroy);
    HITLS_SESS_Free(session);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_LOAD_FILE_FUNC_TC001
* @title   HITLS_CFG_LoadCrlFile interface functional test
* @precon  This test case covers the HITLS_CFG_LoadCrlFile interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_LOAD_FILE_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Test successful CRL file loading
    int32_t ret = HITLS_CFG_LoadCrlFile(config, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameters
    ret = HITLS_CFG_LoadCrlFile(NULL, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_LoadCrlFile(config, NULL, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_LoadCrlFile(config, "", TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_LOAD_BUFFER_FUNC_TC001
* @title   HITLS_CFG_LoadCrlBuffer interface functional test
* @precon  This test case covers the HITLS_CFG_LoadCrlBuffer interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_LOAD_BUFFER_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Read CRL file content
    FILE *file = fopen(crlPath, "rb");
    ASSERT_TRUE(file != NULL);

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    ASSERT_TRUE(fileSize > 0);

    uint8_t *crlData = (uint8_t *)BSL_SAL_Malloc(fileSize);
    ASSERT_TRUE(crlData != NULL);

    size_t bytesRead = fread(crlData, 1, fileSize, file);
    fclose(file);
    ASSERT_EQ(bytesRead, (size_t)fileSize);

    // Test successful CRL buffer loading
    int32_t ret = HITLS_CFG_LoadCrlBuffer(config, crlData, fileSize, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameters
    ret = HITLS_CFG_LoadCrlBuffer(NULL, crlData, fileSize, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_LoadCrlBuffer(config, NULL, fileSize, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

    ret = HITLS_CFG_LoadCrlBuffer(config, crlData, 0, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    BSL_SAL_Free(crlData);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_CTX_LOAD_FILE_FUNC_TC001
* @title   HITLS_LoadCrlFile interface functional test
* @precon  This test case covers the HITLS_LoadCrlFile runtime context interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_CTX_LOAD_FILE_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Test successful CRL file loading in context
    int32_t ret = HITLS_LoadCrlFile(ctx, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameters
    ret = HITLS_LoadCrlFile(NULL, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_CTX_LOAD_BUFFER_FUNC_TC001
* @title   HITLS_LoadCrlBuffer interface functional test
* @precon  This test case covers the HITLS_LoadCrlBuffer runtime context interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_CTX_LOAD_BUFFER_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Read CRL file content
    FILE *file = fopen(crlPath, "rb");
    ASSERT_TRUE(file != NULL);

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    ASSERT_TRUE(fileSize > 0);

    uint8_t *crlData = (uint8_t *)BSL_SAL_Malloc(fileSize);
    ASSERT_TRUE(crlData != NULL);

    size_t bytesRead = fread(crlData, 1, fileSize, file);
    fclose(file);
    ASSERT_EQ(bytesRead, (size_t)fileSize);

    // Test successful CRL buffer loading in context
    int32_t ret = HITLS_LoadCrlBuffer(ctx, crlData, fileSize, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameters
    ret = HITLS_LoadCrlBuffer(NULL, crlData, fileSize, TLS_PARSE_FORMAT_ASN1);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    BSL_SAL_Free(crlData);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_CFG_CLEAR_FUNC_TC001
* @title   HITLS_CFG_ClearVerifyCrls interface functional test
* @precon  This test case covers the HITLS_CFG_ClearVerifyCrls interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_CFG_CLEAR_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Load CRL file first
    int32_t ret = HITLS_CFG_LoadCrlFile(config, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test successful CRL clearing
    ret = HITLS_CFG_ClearVerifyCrls(config);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Load CRL again to verify clearing worked
    ret = HITLS_CFG_LoadCrlFile(config, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameter
    ret = HITLS_CFG_ClearVerifyCrls(NULL);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test    UT_TLS_CRL_CTX_CLEAR_FUNC_TC001
* @title   HITLS_ClearVerifyCrls interface functional test
* @precon  This test case covers the HITLS_ClearVerifyCrls runtime context interface
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_CTX_CLEAR_FUNC_TC001(void)
{
    HitlsInit();
    HITLS_Config *config = HITLS_CFG_NewTLSConfig();
    ASSERT_TRUE(config != NULL);

    HITLS_Ctx *ctx = HITLS_New(config);
    ASSERT_TRUE(ctx != NULL);

    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Load CRL file first
    int32_t ret = HITLS_LoadCrlFile(ctx, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test successful CRL clearing
    ret = HITLS_ClearVerifyCrls(ctx);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Load CRL again to verify clearing worked
    ret = HITLS_LoadCrlFile(ctx, crlPath, TLS_PARSE_FORMAT_ASN1);
    ASSERT_EQ(ret, HITLS_SUCCESS);

    // Test invalid parameter
    ret = HITLS_ClearVerifyCrls(NULL);
    ASSERT_NE(ret, HITLS_SUCCESS);

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */


/* @
* @test    UT_TLS_CRL_VERIFICATION_HANDSHAKE_TC001
* @title   CRL verification in TLS handshake functional test
* @precon  This test case covers CRL functionality during TLS handshake process
@ */
/* BEGIN_CASE */
void UT_TLS_CRL_VERIFICATION_HANDSHAKE_TC001(void)
{
    HitlsInit();
    FRAME_Init();

    // Test data paths
    const char *serverCertPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.der";
    const char *serverKeyPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.key.der";
    const char *intCaPath = "../testdata/tls/certificate/der/ed25519/ed25519.intca.der";
    const char *caCertPath = "../testdata/tls/certificate/der/ed25519/ed25519.ca.der";
    const char *crlPath = "../testdata/tls/certificate/der/ed25519/ed25519.crl.der";

    // Test 1: Handshake without CRL - should succeed
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    // Configure server with certificate and key
    ASSERT_EQ(HITLS_CFG_LoadCertFile(config, serverCertPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(config, serverKeyPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);

    HITLS_CERT_X509 *caCert = HITLS_CFG_ParseCert(config, (const uint8_t *)caCertPath, strlen(caCertPath), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(caCert != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(config, caCert, TLS_CERT_STORE_TYPE_DEFAULT, false), HITLS_SUCCESS);

    caCert = HITLS_CFG_ParseCert(config, (const uint8_t *)intCaPath, strlen(intCaPath), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(caCert != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(config, caCert, TLS_CERT_STORE_TYPE_DEFAULT, false), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    // Attempt handshake without CRL - should succeed
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    FRAME_FreeLink(client);
    FRAME_FreeLink(server);

    server = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    client = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(HITLS_CFG_LoadCrlFile(config, crlPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
    
    HITLS_CFG_SetVerifyFlags(config, HITLS_X509_VFY_FLAG_CRL_DEV);
    
    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    HITLS_ERROR ret;
    HITLS_GetVerifyResult(client->ssl, &ret);
    ASSERT_EQ(ret, HITLS_X509_ERR_VFY_CERT_REVOKED);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */


/* @
* @test    UT_TLS_PARTIAL_CHAIN_VERIFICATION_HANDSHAKE_TC001(void)
* @title   Partial chain verification in TLS handshake functional test
* @precon  This test case covers partial chain verification functionality during TLS handshake process
@ */
/* BEGIN_CASE */
void UT_TLS_PARTIAL_CHAIN_VERIFICATION_HANDSHAKE_TC001(int partialChain, int expectRet)
{
    HitlsInit();
    FRAME_Init();

    // Test data paths
    const char *serverCertPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.der";
    const char *serverKeyPath = "../testdata/tls/certificate/der/ed25519/ed25519.end.key.der";
    const char *intCaPath = "../testdata/tls/certificate/der/ed25519/ed25519.intca.der";

    // Test 1: Handshake without CRL - should succeed
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);
    if (partialChain == 1) {
        HITLS_CFG_SetVerifyFlags(config, HITLS_X509_VFY_FLAG_PARTIAL_CHAIN);
    }

    // Configure server with certificate and key
    ASSERT_EQ(HITLS_CFG_LoadCertFile(config, serverCertPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_LoadKeyFile(config, serverKeyPath, TLS_PARSE_FORMAT_ASN1), HITLS_SUCCESS);

    HITLS_CERT_X509 *caCert = HITLS_CFG_ParseCert(config, (const uint8_t *)intCaPath, strlen(intCaPath),
        TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_ASN1);
    ASSERT_TRUE(caCert != NULL);
    ASSERT_EQ(HITLS_CFG_AddCertToStore(config, caCert, TLS_CERT_STORE_TYPE_DEFAULT, false), HITLS_SUCCESS);

    FRAME_LinkObj *server = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(server != NULL);

    FRAME_LinkObj *client = FRAME_CreateLinkBase(config, BSL_UIO_TCP, false);
    ASSERT_TRUE(client != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), expectRet);
EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test    UT_TLS_CERT_CM_SetVerifyFlags_API_TC001
* @title   The input parameter of the HITLS_CFG_SetVerifyFlags interface is replaced.
* @precon  This test case covers the HITLS_CFG_SetVerifyFlags, HITLS_CFG_GetVerifyFlags
* @brief   1.Invoke the HITLS_CFG_SetVerifyFlags interface. The value of ctx is empty and the value of flags is 5.
*            Expected result 1 is obtained.
*          2.Invoke the HITLS_CFG_SetVerifyFlags interface. The values of ctx and flags are not empty.
*            Expected result 2 is obtained.
*          3.Invoke the HITLS_CFG_GetVerifyFlags interface. The ctx field is empty and the ff address is not empty.
*            Expected result 1 is obtained.
*          4.Invoke the HITLS_CFG_GetVerifyFlags interface. The values of ctx and ff address are not empty.
*            Expected result 2 is obtained.
* @expect  1.Returns HITLS_NULL_INPUT
*          2.Returns HITLS_SUCCESS
@ */
/* BEGIN_CASE */
void UT_TLS_CERT_CM_SetVerifyFlags_API_TC001(int version)
{
    HitlsInit();
    HITLS_Config *tlsConfig = NULL;
    HITLS_Ctx *ctx = NULL;
    uint32_t flags = 5;
    uint32_t ff = 0;

    tlsConfig = HitlsNewCtx(version);
    ASSERT_TRUE(tlsConfig != NULL);

    ASSERT_TRUE(HITLS_CFG_SetVerifyFlags(NULL, flags) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetVerifyFlags(tlsConfig, flags), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_GetVerifyFlags(tlsConfig, &ff) == HITLS_SUCCESS);
    ASSERT_EQ(flags, ff);
    ASSERT_TRUE(HITLS_CFG_GetVerifyFlags(NULL, &ff) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_CFG_GetVerifyFlags(tlsConfig, NULL) == HITLS_NULL_INPUT);

    ctx = HITLS_New(tlsConfig);
    ASSERT_TRUE(ctx != NULL);
    flags = 10;
    uint32_t ff2 = 0;
    ASSERT_TRUE(HITLS_SetVerifyFlags(NULL, flags) == HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetVerifyFlags(ctx, flags), HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_GetVerifyFlags(ctx, &ff2) == HITLS_SUCCESS);
    ASSERT_EQ((flags | ff), ff2);
    ASSERT_TRUE(HITLS_GetVerifyFlags(NULL, &ff2) == HITLS_NULL_INPUT);
    ASSERT_TRUE(HITLS_GetVerifyFlags(ctx, NULL) == HITLS_NULL_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
}
/* END_CASE */
