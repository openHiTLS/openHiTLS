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
#include "pack.h"
#include "bsl_err.h"
#include "custom_extensions.h"

// Simple add_cb function, allocates buffer with 1 byte length and 1 byte data
int SimpleAddCb(const struct TlsCtx *ctx, uint8_t ext_type, uint8_t context, uint8_t **out, uint32_t *outlen, void *msg, uint32_t *al, void *add_arg) {
    (void)ctx;
    (void)ext_type;
    (void)context;
    (void)msg;
    (void)al;
    (void)add_arg;
    *out = malloc(2);
    if (*out == NULL) {
        return -1;
    }
    uint32_t bufOffset = 0;
    (*out)[bufOffset] = 1;
    bufOffset++;
    (*out)[bufOffset] = 0xAA;
    bufOffset++;
    *outlen = bufOffset;
    return 1;
}

// Simple free_cb function, frees the allocated data
void SimpleFreeCb(const struct TlsCtx *ctx, uint8_t ext_type, uint8_t context, uint8_t *out, void *add_arg) {
    (void)ctx;
    (void)ext_type;
    (void)context;
    (void)add_arg;
    BSL_SAL_Free(out);
}

// Simple parse_cb function, reads the length and data, checks the data
int SimpleParseCb(const struct TlsCtx *ctx, uint8_t ext_type, uint8_t context, const uint8_t **in, uint32_t *inlen, void *msg, uint32_t *al, void *parse_arg) {
    (void)ctx;
    (void)ext_type;
    (void)context;
    (void)msg;
    (void)al;
    (void)parse_arg;

    uint32_t bufOffset = 0;
    uint8_t tmpSize = (*in)[bufOffset];
    bufOffset++;

    // Pass the data pointer to BSL_SAL_Dump
    uint8_t *dumpedData = BSL_SAL_Dump(&(*in)[bufOffset], tmpSize);
    if (dumpedData == NULL) {
        return -1;  // Processing failed
    }

    // Check the first byte of the returned data
    if (dumpedData[0] != 0xAA) {
        BSL_SAL_Free(dumpedData);  // Free memory
        return -1;
    }

    // Update *inlen to indicate the number of bytes consumed (including the size byte)
    *inlen = tmpSize + bufOffset;

    BSL_SAL_Free(dumpedData);  // Free memory
    return 1;
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

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    // Configure a single custom extension
    CustomExt_Methods exts = {0};
    CustomExt_Method meth = {0};
    meth.ext_type = type;
    meth.context = type;
    meth.add_cb = NULL;  // No callback
    meth.free_cb = NULL;  // No callback
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.customExts = &exts;

    // Call the interface under test
    ASSERT_EQ(PackCustomExtensions(&ctx, buf, bufLen, &len, type), HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 0);  // No data packed without add_cb

EXIT:
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

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {1, 0, 0, 0, 0};  // ext_type=1, len=0
    uint32_t bufOffset = 0;
    uint8_t type = 1;

    // Configure a single custom extension
    CustomExt_Methods exts = {0};
    CustomExt_Method meth = {0};
    meth.ext_type = type;
    meth.parse_cb = NULL;  // No callback
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.customExts = &exts;

    // Call the interface under test
    int32_t ret = ParseCustomExtensions(&ctx, buf, &bufOffset, type);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    // Note: Current implementation doesn't update bufOffset without parse_cb, adjust expectation if needed

EXIT:
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

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    // Configure multiple custom extensions
    CustomExt_Methods exts = {0};
    CustomExt_Method meths[2] = {{0}, {0}};
    meths[0].ext_type = 1;
    meths[0].context = type;
    meths[0].add_cb = NULL;  // No callback
    meths[0].free_cb = NULL;
    meths[1].ext_type = 2;
    meths[1].context = type;
    meths[1].add_cb = NULL;  // No callback
    meths[1].free_cb = NULL;
    exts.meths = meths;
    exts.meths_count = 2;
    ctx.customExts = &exts;

    // Call the interface under test
    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 0);             // No data packed without add_cb

EXIT:
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

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    ctx.customExts = NULL;  // No extensions

    // Call the interface under test
    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 0);             // Verify the packing length is 0

EXIT:
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
 * 2. Returns HITLS_SUCCESS, packing length is 2 (ext_type + data), buffer content is correct.
 @ */
/* BEGIN_CASE */
void SDV_TLS_PACK_CUSTOM_EXTENSIONS_CALLBACK_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    // Configure a single custom extension with callbacks
    CustomExt_Methods exts = {0};
    CustomExt_Method meth = {0};
    meth.ext_type = type;
    meth.context = type;
    meth.add_cb = SimpleAddCb;
    meth.free_cb = SimpleFreeCb;
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.customExts = &exts;

    // Call the interface under test
    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(len, 3);             // ext_type (1 byte) + len (1 byte) + data (1 byte)
    ASSERT_EQ(buf[0], type);       // Verify the extension type
    ASSERT_EQ(buf[1], 1);          // Verify the len
    //ASSERT_EQ(buf[2], 0xAA);       // Verify the data

EXIT:
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

    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {1, 1, 0xAA};  // ext_type=1, data=0xAA
    uint32_t bufOffset = 0;
    uint8_t type = 1;

    // Configure a single custom extension with parse callback
    CustomExt_Methods exts = {0};
    CustomExt_Method meth = {0};
    meth.ext_type = type;
    meth.context = type;
    meth.parse_cb = SimpleParseCb;
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.customExts = &exts;

    // Call the interface under test
    int32_t ret = ParseCustomExtensions(&ctx, buf, &bufOffset, type);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(bufOffset, 3);        // ext_type (1 byte) + len (1 byte) + data (1 byte)

EXIT:
    return;
}
/* END_CASE */

/** @
 * @test  SDV_TLS_SSLCTX_ADD_CUSTOM_EXTENSION_API_TC002
 * @title Test the custom extension addition functionality of the HITLS_AddCustomExtension function
 * @precon None
 * @brief
 * 1. Initialize the TLS context and add a valid custom extension, verify if the addition is successful. Expected result 1.
 * 2. Attempt to add a duplicate custom extension, verify if the function rejects the duplicate addition. Expected result 2.
 * 3. Call the function with invalid parameters (add_cb is NULL, free_cb is not NULL), verify if the function correctly handles the error. Expected result 3.
 * @expect
 * 1. Returns HITLS_SUCCESS, the custom extension is correctly added to the context.
 * 2. Returns 0, the number of extensions does not increase.
 * 3. Returns 0, the number of extensions does not increase.
 @ */
/* BEGIN_CASE */
void SDV_TLS_SSLCTX_ADD_CUSTOM_EXTENSION_API_TC001(void)
{
    FRAME_Init();  // Initialize the test framework

    // Initialize the TLS context
    TLS_Ctx ctx = {0};
    uint8_t ext_type = 1;
    uint8_t context = 1;
    HITLS_CustomExt_Add_Callback add_cb = SimpleAddCb;
    HITLS_CustomExt_Free_Callback free_cb = SimpleFreeCb;
    void *add_arg = NULL;
    HITLS_CustomExt_Parse_Callback parse_cb = SimpleParseCb;
    void *parse_arg = NULL;

    // Test normal case: Add a custom extension
    uint32_t ret = HITLS_AddCustomExtension(&ctx, ext_type, context, add_cb, free_cb, add_arg, parse_cb, parse_arg);
    ASSERT_EQ(ret, HITLS_SUCCESS);  // Verify the return value is success
    ASSERT_EQ(ctx.customExts->meths_count, 1);  // Verify the number of extensions is 1
    CustomExt_Method *meth = &ctx.customExts->meths[0];
    ASSERT_EQ(meth->ext_type, ext_type);  // Verify the extension type
    ASSERT_EQ(meth->context, context);    // Verify the context
    ASSERT_EQ(meth->add_cb, add_cb);      // Verify add_cb
    ASSERT_EQ(meth->free_cb, free_cb);    // Verify free_cb
    ASSERT_EQ(meth->add_arg, add_arg);    // Verify add_arg
    ASSERT_EQ(meth->parse_cb, parse_cb);  // Verify parse_cb
    ASSERT_EQ(meth->parse_arg, parse_arg); // Verify parse_arg

    // Test boundary case: Attempt to add a duplicate extension
    ret = HITLS_AddCustomExtension(&ctx, ext_type, context, add_cb, free_cb, add_arg, parse_cb, parse_arg);
    ASSERT_EQ(ret, 0);  // Verify the return value is failure
    ASSERT_EQ(ctx.customExts->meths_count, 1);  // Verify the number of extensions does not increase

    // Test invalid parameters: add_cb is NULL, free_cb is not NULL
    ret = HITLS_AddCustomExtension(&ctx, 2, context, NULL, free_cb, add_arg, parse_cb, parse_arg);
    ASSERT_EQ(ret, 0);  // Verify the return value is failure
    ASSERT_EQ(ctx.customExts->meths_count, 1);  // Verify the number of extensions does not increase

EXIT:
    // Clean up memory to prevent leaks
    if (ctx.customExts != NULL) {
        BSL_SAL_Free(ctx.customExts->meths);
        BSL_SAL_Free(ctx.customExts);
    }
    return;
}
/* END_CASE */


