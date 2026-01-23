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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include "securec.h"
#include "bsl_sal.h"
#include "frame_tls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "frame_io.h"
#include "uio_abstraction.h"
#include "tls.h"
#include "tls_config.h"
#include "hitls_type.h"
#include "hitls_func.h"
#include "hitls.h"
#include "pack.h"
#include "bsl_err.h"
#include "bsl_bytes.h"
#include "custom_extensions.h"
#include "frame_tls.h"
#include "alert.h"
#include "frame_link.h"

#define CUSTOM_EXTENTIONS_TYPE_1                      0x00001
#define CUSTOM_EXTENTIONS_TYPE_2                      0x00002

// Simple add_cb function, allocates buffer with 1 byte length and 1 byte data
int SimpleAddCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, uint8_t **out, uint32_t *outLen,
    HITLS_CERT_X509 *cert, uint32_t certId, uint32_t *alert, void *addArg)
{
    (void)ctx;
    (void)extType;
    (void)context;
    (void)cert;
    (void)certId;
    (void)alert;
    (void)addArg;
    *out = malloc(sizeof(uint16_t));
    if (*out == NULL) {
        return -1;
    }
    uint32_t bufOffset = 0;
    (*out)[bufOffset] = 0xAA;
    bufOffset++;
    *outLen = bufOffset;
    return HITLS_ADD_CUSTOM_EXTENSION_RET_PACK;
}

// Simple free_cb function, frees the allocated data
void SimpleFreeCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, uint8_t *out, void *addArg)
{
    (void)ctx;
    (void)extType;
    (void)context;
    (void)addArg;
    BSL_SAL_Free(out);
}

// Simple parse_cb function, reads the length and data, checks the data
int SimpleParseCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, const uint8_t **in, uint32_t *inLen,
    HITLS_CERT_X509 *cert, uint32_t certId, uint32_t *alert, void *parseArg)
{
    (void)ctx;
    (void)extType;
    (void)context;
    (void)cert;
    (void)certId;
    (void)alert;
    (void)parseArg;

    if (*inLen <= 0) {
        return 0;
    }
    // Pass the data pointer to BSL_SAL_Dump
    uint8_t *dumpedData = BSL_SAL_Dump(*in, *inLen);
    if (dumpedData == NULL) {
        return 1;  // Processing failed
    }

    // Check the first byte of the returned data
    if (dumpedData[0] != 0xAA) {
        BSL_SAL_Free(dumpedData);  // Free memory
        return 1;
    }

    BSL_SAL_Free(dumpedData);  // Free memory
    return 0;
}

/* END_HEADER */

/** @
 * @test  SDV_TLS_PACK_CUSTOM_EXTENSIONS_API_TC001
 * @title Test the single extension packing function of the PackCustomExtensions interface
 * @precon None
 * @brief
 * 1. Initialize the TLS context and configure a single custom extension (no callback). Expected result 1.
 * 2. Call the PackCustomExtensions interface and verify the packing result. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, packing length is 0 (no data without callback).
 @ */
/* BEGIN_CASE */
void SDV_TLS_PACK_CUSTOM_EXTENSIONS_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint16_t extType = CUSTOM_EXTENTIONS_TYPE_1;
    uint32_t context = 1;

    // Configure a single custom extension
    CustomExtMethods exts = {0};
    CustomExtMethod meth = {0};
    meth.extType = extType;
    meth.context = context;
    meth.addCb = NULL;  // No callback
    meth.freeCb = NULL;  // No callback
    exts.meths = &meth;
    exts.methsCount = 1;
    ctx->config.tlsConfig.customExts = &exts;

    uint32_t bufOffset = 0;
    uint8_t *buffAddr = &buf[0];
    PackPacket pkt = {.buf = &buffAddr, .bufLen = &bufLen, .bufOffset = &bufOffset};
    // Call the interface under test
    // Verify the return value is success
    ASSERT_EQ(PackCustomExtensions(ctx, &pkt, context, NULL, 0), HITLS_SUCCESS);
    ctx->config.tlsConfig.customExts = NULL;
    ASSERT_EQ(len, 0);  // No data packed without add_cb

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_PARSE_CUSTOM_EXTENSIONS_API_TC001
 * @title Test the single extension parsing function of the ParseCustomExtensions interface
 * @precon None
 * @brief
 * 1. Initialize the TLS context and configure a single custom extension (no callback). Expected result 1.
 * 2. Prepare a buffer containing a single extension and call the ParseCustomExtensions interface. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, buffer offset is updated correctly.
 @ */
/* BEGIN_CASE */
void SDV_TLS_PARSE_CUSTOM_EXTENSIONS_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0xAA};  // ext_type=1, len=0
    uint32_t bufOffset = 0;
    uint16_t extType = CUSTOM_EXTENTIONS_TYPE_1;
    uint32_t context = 1;
    uint32_t extLen = 1;

    // Configure a single custom extension
    CustomExtMethods exts = {0};
    CustomExtMethod meth = {0};
    meth.extType = extType;
    meth.parseCb = NULL;  // No callback
    exts.meths = &meth;
    exts.methsCount = 1;
    ctx->config.tlsConfig.customExts = &exts;

    // Call the interface under test
    int32_t ret = ParseCustomExtensions(ctx, buf + bufOffset, extType, extLen, context, NULL, 0);
    ctx->config.tlsConfig.customExts = NULL;
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    // Note: Current implementation doesn't update bufOffset without parse_cb, adjust expectation if needed

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_PACK_CUSTOM_EXTENSIONS_MULTIPLE_API_TC001
 * @title Test the multiple extensions packing function of the PackCustomExtensions interface
 * @precon None
 * @brief
 * 1. Initialize the TLS context and configure two custom extensions. Expected result 1.
 * 2. Call the PackCustomExtensions interface and verify the packing result. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, packing length is 0 (no data without callbacks).
 @ */
/* BEGIN_CASE */
void SDV_TLS_PACK_CUSTOM_EXTENSIONS_MULTIPLE_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint32_t context = 1;
    uint32_t methsCount = 1;

    // Configure multiple custom extensions
    CustomExtMethods exts = {0};
    CustomExtMethod meths[2] = {{0}, {0}};
    meths[0].extType = CUSTOM_EXTENTIONS_TYPE_1;
    meths[0].context = context;
    meths[0].addCb = NULL;  // No callback
    meths[0].freeCb = NULL;
    meths[1].extType = CUSTOM_EXTENTIONS_TYPE_2;
    meths[1].context = context;
    meths[1].addCb = NULL;  // No callback
    meths[1].freeCb = NULL;
    exts.meths = meths;
    exts.methsCount = methsCount;
    ctx->config.tlsConfig.customExts = &exts;

    uint32_t bufOffset = 0;
    uint8_t *buffAddr = &buf[0];
    PackPacket pkt = {.buf = &buffAddr, .bufLen = &bufLen, .bufOffset = &bufOffset};
    // Call the interface under test
    int32_t ret = PackCustomExtensions(ctx, &pkt, context, NULL, 0);
    ctx->config.tlsConfig.customExts = NULL;
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 0);             // No data packed without add_cb

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_PACK_CUSTOM_EXTENSIONS_EMPTY_API_TC001
 * @title Test the behavior of the PackCustomExtensions interface when there are no extensions
 * @precon None
 * @brief
 * 1. Initialize the TLS context without configuring any custom extensions. Expected result 1.
 * 2. Call the PackCustomExtensions interface and verify the packing result. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, packing length is 0.
 @ */
/* BEGIN_CASE */
void SDV_TLS_PACK_CUSTOM_EXTENSIONS_EMPTY_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint32_t context = 1;

    ctx->config.tlsConfig.customExts = NULL;  // No extensions

    uint32_t bufOffset = 0;
    uint8_t *buffAddr = &buf[0];
    PackPacket pkt = {.buf = &buffAddr, .bufLen = &bufLen, .bufOffset = &bufOffset};
    // Call the interface under test
    int32_t ret = PackCustomExtensions(ctx, &pkt, context, NULL, 0);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 0);             // Verify the packing length is 0

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_PACK_CUSTOM_EXTENSIONS_CALLBACK_API_TC001
 * @title Test the PackCustomExtensions interface with callbacks
 * @precon None
 * @brief
 * 1. Initialize the TLS context and configure a single custom extension with add_cb and free_cb. Expected result 1.
 * 2. Call the PackCustomExtensions interface and verify the packing result. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, packing length is 3 (ext_type + data), buffer content is correct.
 @ */
/* BEGIN_CASE */
void SDV_TLS_PACK_CUSTOM_EXTENSIONS_CALLBACK_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint16_t extType = CUSTOM_EXTENTIONS_TYPE_1;
    uint32_t context = 1;
    uint32_t dataLen = 1;

    // Configure a single custom extension with callbacks
    CustomExtMethods exts = {0};
    CustomExtMethod meth = {0};
    meth.extType = extType;
    meth.context = context;
    meth.addCb = SimpleAddCb;
    meth.freeCb = SimpleFreeCb;
    exts.meths = &meth;
    exts.methsCount = 1;
    ctx->config.tlsConfig.customExts = &exts;

    uint32_t bufOffset = 0;
    uint8_t *buffAddr = &buf[0];
    PackPacket pkt = {.buf = &buffAddr, .bufLen = &bufLen, .bufOffset = &bufOffset};
    // Call the interface under test
    int32_t ret = PackCustomExtensions(ctx, &pkt, context, NULL, 0);
    ctx->config.tlsConfig.customExts = NULL;
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    len += bufOffset;
    ASSERT_EQ(len, sizeof(uint16_t) + sizeof(uint16_t) + dataLen);  // ext_type (2 byte) + len (2 byte) + data (1 byte)
    // Verify the extension type
    uint16_t packedType = BSL_ByteToUint16(buf);
    ASSERT_EQ(packedType, extType);
    uint16_t packedLen = BSL_ByteToUint16(&buf[sizeof(uint16_t)]);
    ASSERT_EQ(packedLen, 1);  // Verify the len
    ASSERT_EQ(buf[len - 1], 0xAA);  // Verify the data

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_PARSE_CUSTOM_EXTENSIONS_CALLBACK_API_TC001
 * @title Test the ParseCustomExtensions interface with parse_cb
 * @precon None
 * @brief
 * 1. Initialize the TLS context and configure a single custom extension with parse_cb. Expected result 1.
 * 2. Prepare a buffer containing a single extension and call the ParseCustomExtensions interface. Expected result 2.
 * @expect
 * 1. Initialization successful.
 * 2. Returns HITLS_SUCCESS, buffer offset is updated correctly.
 @ */
/* BEGIN_CASE */
void SDV_TLS_PARSE_CUSTOM_EXTENSIONS_CALLBACK_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);
    HITLS_Ctx *ctx = HITLS_New(tlsConfig);
    ASSERT_NE(ctx, NULL);
    uint8_t buf[1024] = {0xAA};  // ext_type=1 (big-endian), len=1, data=0xAA
    uint32_t bufOffset = 0;
    uint16_t extType = CUSTOM_EXTENTIONS_TYPE_1;
    uint32_t context = 1;
    uint32_t extLen = 1;
    // Configure a single custom extension with parse callback
    CustomExtMethods exts = {0};
    CustomExtMethod meth = {0};
    meth.extType = extType;
    meth.context = context;
    meth.parseCb = SimpleParseCb;
    exts.meths = &meth;
    exts.methsCount = 1;
    ctx->config.tlsConfig.customExts = &exts;

    // Call the interface under test
    int32_t ret = ParseCustomExtensions(ctx, buf + bufOffset, extType, extLen, context, NULL, 0);
    ctx->config.tlsConfig.customExts = NULL;
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    HITLS_Free(ctx);
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_SSLCTX_ADD_CUSTOM_EXTENSION_API_TC002
 * @title Test the custom extension addition functionality of the HITLS_AddCustomExtension function
 * @precon None
 * @brief
 * 1. Initialize the TLS context and add a valid custom extension, verify if the addition is successful.
 * Expected result 1.
 * 2. Attempt to add a duplicate custom extension, verify if the function rejects the duplicate addition.
 * Expected result 2.
 * 3. Call the function with invalid parameters (add_cb is NULL, free_cb is not NULL), verify if the function correctly
 * handles the error. Expected result 3.
 * @expect
 * 1. Returns HITLS_SUCCESS, the custom extension is correctly added to the context.
 * 2. Returns 0, the number of extensions does not increase.
 * 3. Returns 0, the number of extensions does not increase.
 @ */
/* BEGIN_CASE */
void SDV_HITLS_ADD_CUSTOM_EXTENSION_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework
    HITLS_Config *tlsConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_NE(tlsConfig, NULL);

    uint16_t extType = CUSTOM_EXTENTIONS_TYPE_1;
    uint16_t invalidExtType = CUSTOM_EXTENTIONS_TYPE_2;
    uint32_t context = 1;
    HITLS_AddCustomExtCallback addCb = SimpleAddCb;
    HITLS_FreeCustomExtCallback freeCb = SimpleFreeCb;
    void *addArg = NULL;
    HITLS_ParseCustomExtCallback parseCb = SimpleParseCb;
    void *parseArg = NULL;

    // Test normal case: Add a custom extension
    HITLS_CustomExtParams params = {
        .extType = extType,
        .context = context,
        .addCb = addCb,
        .freeCb = freeCb,
        .addArg = addArg,
        .parseCb = parseCb,
        .parseArg = parseArg
    };
    uint32_t ret = HITLS_CFG_AddCustomExtension(tlsConfig, &params);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(tlsConfig->customExts->methsCount, 1);  // Verify the number of extensions is 1
    CustomExtMethod *meth = &tlsConfig->customExts->meths[0];
    ASSERT_EQ(meth->extType, extType);  // Verify the extension type
    ASSERT_EQ(meth->context, context);    // Verify the context
    ASSERT_EQ(meth->addCb, addCb);      // Verify add_cb
    ASSERT_EQ(meth->freeCb, freeCb);    // Verify free_cb
    ASSERT_EQ(meth->addArg, addArg);    // Verify add_arg
    ASSERT_EQ(meth->parseCb, parseCb);  // Verify parse_cb
    ASSERT_EQ(meth->parseArg, parseArg); // Verify parse_arg

    // Test boundary case: Attempt to add a duplicate extension
    HITLS_CustomExtParams duplicateParams = {
        .extType = extType,
        .context = context,
        .addCb = addCb,
        .freeCb = freeCb,
        .addArg = addArg,
        .parseCb = parseCb,
        .parseArg = parseArg
    };
    ret = HITLS_CFG_AddCustomExtension(tlsConfig, &duplicateParams);
    ASSERT_EQ(ret, HITLS_CONFIG_DUP_CUSTOM_EXT);  // Verify the return value is failure
    ASSERT_EQ(tlsConfig->customExts->methsCount, 1);  // Verify the number of extensions does not increase

    // Test invalid parameters: add_cb is NULL, free_cb is not NULL
    HITLS_CustomExtParams invalidParams = {
        .extType = invalidExtType,
        .context = context,
        .addCb = NULL,
        .freeCb = freeCb,
        .addArg = addArg,
        .parseCb = parseCb,
        .parseArg = parseArg
    };
    ret = HITLS_CFG_AddCustomExtension(tlsConfig, &invalidParams);
    ASSERT_EQ(ret, HITLS_INVALID_INPUT);  // Verify the return value is failure
    ASSERT_EQ(tlsConfig->customExts->methsCount, 1);  // Verify the number of extensions does not increase

EXIT:
    HITLS_CFG_FreeConfig(tlsConfig);
    return;
}
/* END_CASE */

typedef struct {
    uint32_t parsedContext[10];
    uint32_t parsedContextCount;
    uint32_t addedContext[10];
    uint32_t addedContextCount;
    uint32_t alertContext;
    uint32_t alert;
    bool addEmptyExt;
    bool parseEmptyExt;
    bool passExt;
} CustomExtensionArg;

int CustomExtensionAddCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, uint8_t **out, uint32_t *outLen,
    HITLS_CERT_X509 *cert, uint32_t certId, uint32_t *alert, void *addArg)
{
    (void)ctx;
    (void)extType;
    (void)cert;
    (void)certId;
    (void)alert;

    CustomExtensionArg *arg = (CustomExtensionArg *)addArg;
    arg->addedContext[arg->addedContextCount++] = context;

    if ((arg->alertContext & context) != 0) {
        *alert = arg->alert;
        return -1;
    }

    if (arg->passExt) {
        *out = NULL;
        *outLen = 0;
        return HITLS_ADD_CUSTOM_EXTENSION_RET_PASS;
    }

    if (arg->addEmptyExt) {
        *out = NULL;
        *outLen = 0;
        return HITLS_ADD_CUSTOM_EXTENSION_RET_PACK;
    }

    *out = malloc(1);
    if (*out == NULL) {
        return -1;
    }
    *outLen = 1;
    (*out)[0] = 0xAA;

    return HITLS_ADD_CUSTOM_EXTENSION_RET_PACK;
}

// Simple free_cb function, frees the allocated data
void CustomExtensionFreeCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, uint8_t *out, void *addArg)
{
    (void)ctx;
    (void)extType;
    (void)context;
    (void)addArg;
    BSL_SAL_Free(out);
}

// Simple parse_cb function, reads the length and data, checks the data
int CustomExtensionParseCb(const struct TlsCtx *ctx, uint16_t extType, uint32_t context, const uint8_t **in, uint32_t *inLen,
    HITLS_CERT_X509 *cert, uint32_t certId, uint32_t *alert, void *parseArg)
{
    (void)ctx;
    (void)extType;
    (void)context;
    (void)cert;
    (void)certId;
    (void)alert;
    CustomExtensionArg *arg = (CustomExtensionArg *)parseArg;
    arg->parsedContext[arg->parsedContextCount++] = context;
    if ((arg->alertContext & context) != 0) {
        *alert = arg->alert;
        return -1;
    }

    if (arg->parseEmptyExt) {
        if (*inLen > 0) {
            return -1;
        }
        return 0;
    }

    if (arg->passExt) {
        return -1;
    }

    if (*inLen != 1 || (*in)[0] != 0xAA) {
        return -1;
    }

    return 0;
}



/**
 * @test  SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC001
 * @title Basic Functionality Test for Custom Extensions
 */
/* BEGIN_CASE */
void SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetClientVerifySupport(serverConfig, true);
    CustomExtensionArg serverArg = {0};
    CustomExtensionArg clientArg = {0};
    HITLS_CustomExtParams params = {
        .extType = CUSTOM_EXTENTIONS_TYPE_2,
        .context = HITLS_EX_TYPE_CLIENT_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO | HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS | HITLS_EX_TYPE_TLS1_3_CERTIFICATE | HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST | HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET,
        .addCb = CustomExtensionAddCb,
        .freeCb = CustomExtensionFreeCb,
        .addArg = &clientArg,
        .parseCb = CustomExtensionParseCb,
        .parseArg = &clientArg
    };
    HITLS_CFG_AddCustomExtension(clientConfig, &params);
    params.addArg = &serverArg;
    params.parseArg = &serverArg;
    HITLS_CFG_AddCustomExtension(serverConfig, &params);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(clientArg.addedContextCount, 3);
    ASSERT_EQ(clientArg.parsedContextCount, 7);
    ASSERT_EQ(clientArg.addedContext[0], HITLS_EX_TYPE_CLIENT_HELLO);
    ASSERT_EQ(clientArg.addedContext[1], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(clientArg.addedContext[2], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(clientArg.parsedContext[0], HITLS_EX_TYPE_TLS1_2_SERVER_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO | HITLS_EX_TYPE_HELLO_RETRY_REQUEST);
    ASSERT_EQ(clientArg.parsedContext[1], HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(clientArg.parsedContext[2], HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST);
    ASSERT_EQ(clientArg.parsedContext[3], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(clientArg.parsedContext[4], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(clientArg.parsedContext[5], HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET);
    ASSERT_EQ(clientArg.parsedContext[6], HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET);

    ASSERT_EQ(serverArg.addedContextCount, 7);
    ASSERT_EQ(serverArg.parsedContextCount, 3);
    ASSERT_EQ(serverArg.parsedContext[0], HITLS_EX_TYPE_CLIENT_HELLO);
    ASSERT_EQ(serverArg.parsedContext[1], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(serverArg.parsedContext[2], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);

    ASSERT_EQ(serverArg.addedContext[0], HITLS_EX_TYPE_TLS1_3_SERVER_HELLO);
    ASSERT_EQ(serverArg.addedContext[1], HITLS_EX_TYPE_ENCRYPTED_EXTENSIONS);
    ASSERT_EQ(serverArg.addedContext[2], HITLS_EX_TYPE_TLS1_3_CERTIFICATE_REQUEST);
    ASSERT_EQ(serverArg.addedContext[3], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(serverArg.addedContext[4], HITLS_EX_TYPE_TLS1_3_CERTIFICATE);
    ASSERT_EQ(serverArg.addedContext[5], HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET);
    ASSERT_EQ(serverArg.addedContext[5], HITLS_EX_TYPE_TLS1_3_NEW_SESSION_TICKET);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC002
 * @title Alert Scenario Test for Custom Extensions
 */
/* BEGIN_CASE */
void SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC002()
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    CustomExtensionArg serverArg = {0};
    CustomExtensionArg clientArg = {0};
    clientArg.alert = ALERT_ILLEGAL_PARAMETER;
    clientArg.alertContext = HITLS_EX_TYPE_TLS1_3_SERVER_HELLO;

    HITLS_CustomExtParams params = {
        .extType = CUSTOM_EXTENTIONS_TYPE_2,
        .context = HITLS_EX_TYPE_CLIENT_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO,
        .addCb = CustomExtensionAddCb,
        .freeCb = CustomExtensionFreeCb,
        .addArg = &clientArg,
        .parseCb = CustomExtensionParseCb,
        .parseArg = &clientArg
    };
    HITLS_CFG_AddCustomExtension(clientConfig, &params);
    params.addArg = &serverArg;
    params.parseArg = &serverArg;
    HITLS_CFG_AddCustomExtension(serverConfig, &params);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), -1);
    ALERT_Info info = {0};
    ALERT_GetInfo(client->ssl, &info);
    ASSERT_EQ(info.flag, ALERT_FLAG_SEND);
    ASSERT_EQ(info.level, ALERT_LEVEL_FATAL);
    ASSERT_EQ(info.description, ALERT_ILLEGAL_PARAMETER);

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC003
 * @title Empty Extension Capability Test
 */
/* BEGIN_CASE */
void SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC003()
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    CustomExtensionArg serverArg = {0};
    CustomExtensionArg clientArg = {0};
    clientArg.addEmptyExt = true;
    clientArg.parseEmptyExt = false;

    serverArg.addEmptyExt = false;
    serverArg.parseEmptyExt = true;

    HITLS_CustomExtParams params = {
        .extType = CUSTOM_EXTENTIONS_TYPE_2,
        .context = HITLS_EX_TYPE_CLIENT_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO,
        .addCb = CustomExtensionAddCb,
        .freeCb = CustomExtensionFreeCb,
        .addArg = &clientArg,
        .parseCb = CustomExtensionParseCb,
        .parseArg = &clientArg
    };
    HITLS_CFG_AddCustomExtension(clientConfig, &params);
    params.addArg = &serverArg;
    params.parseArg = &serverArg;
    HITLS_CFG_AddCustomExtension(serverConfig, &params);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), 0);

    ASSERT_EQ(clientArg.addedContextCount, 1);
    ASSERT_EQ(clientArg.parsedContextCount, 1);
    ASSERT_EQ(clientArg.addedContext[0], HITLS_EX_TYPE_CLIENT_HELLO);
    ASSERT_EQ(clientArg.parsedContext[0], HITLS_EX_TYPE_TLS1_2_SERVER_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO | HITLS_EX_TYPE_HELLO_RETRY_REQUEST);

    ASSERT_EQ(serverArg.addedContextCount, 1);
    ASSERT_EQ(serverArg.parsedContextCount, 1);
    ASSERT_EQ(serverArg.addedContext[0], HITLS_EX_TYPE_TLS1_3_SERVER_HELLO);
    ASSERT_EQ(serverArg.parsedContext[0], HITLS_EX_TYPE_CLIENT_HELLO);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test  SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC004
 * @title Pass Extension Capability Test
 */
/* BEGIN_CASE */
void SDV_HITLS_CUSTOM_EXTENSION_FUNCTION_TC004()
{
    FRAME_Init();  // Initialize the test framework

    HITLS_Config *clientConfig = HITLS_CFG_NewTLS13Config();
    HITLS_Config *serverConfig = HITLS_CFG_NewTLS13Config();
    CustomExtensionArg serverArg = {0};
    CustomExtensionArg clientArg = {0};
    clientArg.passExt = true;

    serverArg.passExt = true;

    HITLS_CustomExtParams params = {
        .extType = CUSTOM_EXTENTIONS_TYPE_2,
        .context = HITLS_EX_TYPE_CLIENT_HELLO | HITLS_EX_TYPE_TLS1_3_SERVER_HELLO,
        .addCb = CustomExtensionAddCb,
        .freeCb = CustomExtensionFreeCb,
        .addArg = &clientArg,
        .parseCb = CustomExtensionParseCb,
        .parseArg = &clientArg
    };
    HITLS_CFG_AddCustomExtension(clientConfig, &params);
    params.addArg = &serverArg;
    params.parseArg = &serverArg;
    HITLS_CFG_AddCustomExtension(serverConfig, &params);

    FRAME_LinkObj *client = FRAME_CreateLink(clientConfig, BSL_UIO_TCP);
    FRAME_LinkObj *server = FRAME_CreateLink(serverConfig, BSL_UIO_TCP);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), 0);

    ASSERT_EQ(clientArg.addedContextCount, 1);
    ASSERT_EQ(clientArg.parsedContextCount, 0);

    ASSERT_EQ(serverArg.addedContextCount, 1);
    ASSERT_EQ(serverArg.parsedContextCount, 0);

    ASSERT_TRUE(TestIsErrStackEmpty());


EXIT:
    HITLS_CFG_FreeConfig(clientConfig);
    HITLS_CFG_FreeConfig(serverConfig);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */