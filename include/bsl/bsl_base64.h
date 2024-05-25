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

#ifndef BSL_BASE64_H
#define BSL_BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_BASE64_CTX_BUF_LENGTH 80
#define HITLS_BASE64_CTX_LENGTH 48
/* Input length (len) divided by 3, rounded up, multiplied by 4, then add the number of newline characters,and
   add the length of the context buffer */
#define HITLS_BASE64_ENCODE_LENGTH(len) \
    ((((len) + 2) / 3 * 4) + ((len) / HITLS_BASE64_CTX_LENGTH + 1) * 2 + HITLS_BASE64_CTX_BUF_LENGTH)
#define HITLS_BASE64_DECODE_LENGTH(len) (((len) + 3) / 4 * 3 + HITLS_BASE64_CTX_BUF_LENGTH)

/*
 * When writing, it makes all the data written on one line without a newline character at the end;
 * When reading, it expects all data to be on one line (regardless of whether there is a trailing newline character)
 */
#define BSL_BASE64_FLAGS_NO_NEWLINE  0x01

typedef struct BASE64_ControlBlock BSL_Base64Ctx;

/**
 * @ingroup bsl_base64
 * @brief Encode the specified buffer into the base64 format.
 * @par Description: The function converts the DER code to base64 format,
 *     In the case of the encoding is successful, The user needs to release the dstBuf memory after the dstBuf is
 * used up. The user needs to allocate space dstBuf in advance. dstBufLen indicates the length of the allocate space.
 * @attention None
 * @param srcBuf         [IN] Passed buff buffer.
 * @param srcBufLen      [IN] Input buff buffer length.
 * @param dstBuf        [OUT] Output buff buffer.
 * @param dstBufLen     [OUT] Number of encoded bytes excluding the terminator (a multiple of 4)
 * @return Error code
 */
int32_t BSL_BASE64_Encode(const uint8_t *srcBuf, const uint32_t srcBufLen, char *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Decode the specified buffer into the DER format.
 * @par Description: This function converts the specified base64 format into the DER format, In the case of the
 * decoding is successful, the user needs to release the dstBuf memory after the dstBuf is used up.
 * @attention None
 * @param srcBuf         [IN] Passed buff buffer.
 * @param srcBufLen      [IN] Input buff buffer length.
 * @param dstBufLen     [OUT] Encoding length obtained after decoding.
 * @param dstBuf        [OUT] Encoding string obtained after decoding.
 * @retval when success , return BSL_SUCCESS; Otherwise, return error code
 */
int32_t BSL_BASE64_Decode(const char *srcBuf, const uint32_t srcBufLen, uint8_t *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Generate Stream Encoding Context.
 * @par Description: generate BSL_Base64Ctx.
 * @param ctx            [IN] Base64 context
 * @retval               void
 */
BSL_Base64Ctx *BSL_BASE64_CtxNew(void);

/**
 * @ingroup bsl_base64
 * @brief Release the stream encoding context.
 * @par  Description: release BSL_Base64Ctx.
 * @param ctx            [IN] Base64 context
 * @retval               void
 */
void BSL_BASE64_CtxFree(BSL_Base64Ctx *ctx);

/**
 * @ingroup bsl_base64
 * @brief Clear stream encoding context.
 * @par Description: clear BSL_Base64Ctx.
 * @param ctx            [IN] Base64 context
 * @retval               void
 */
void BSL_BASE64_CtxClear(BSL_Base64Ctx *ctx);

/**
 * @ingroup bsl_base64
 * @brief Initialize stream encoding.
 * @par Description: initialize the context.
 * @param ctx            [IN] Base64 context
 * @retval In the case of success, return BSL_SUCCESS; Otherwise, returned error code.
 */
int32_t BSL_BASE64_EncodeInit(BSL_Base64Ctx *ctx);

/**
 * @ingroup bsl_base64
 * @brief Encodes a specified buffer into the Base64 format.
 * @par Description: If the length of the data to be encoded is less than one line or one block,
 * the data is stored in encData of the context for the next input by user. Until one block is
 * satisfied or we encountered the last line.
 * @param srcBuf         [IN] Passed buff buffer.
 * @param srcBufLen      [IN] Input buff buffer length.
 * @param dstBuf        [OUT] String obtained after encoding.
 * @param dstBufLen     [OUT] Length obtained after encoding.
 * @retval In the case of success, return BSL_SUCCESS. Otherwise, returned error code.
 */
int32_t BSL_BASE64_EncodeUpdate(BSL_Base64Ctx *ctx, const uint8_t *srcBuf, uint32_t srcBufLen,
    char *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Encode the specified buffer into the Base64 format.
 * @par Description: Encode the remaining characters stored in the context buffer.
 * @param dstBufLen     [OUT] Length obtained after encoding.
 * @param dstBuf        [OUT] String obtained after encoding.
 * @retval In the case of success, return BSL_SUCCESS. Otherwise, returned error code.
 */
int32_t BSL_BASE64_EncodeFinal(BSL_Base64Ctx *ctx, char *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Initialize stream decoding.
 * @par Description: Initialize the context.
 * @param ctx            [IN] Base64 context
 * @retval In the case of success, return BSL_SUCCESS. Otherwise, returned error code.
 */
int32_t BSL_BASE64_DecodeInit(BSL_Base64Ctx *ctx);

/**
 * @ingroup bsl_base64
 * @brief Decode the specified buffer into the DER format.
 * @par Description: Block decoding is performed for each full block,
 *                   Otherwise, the padding is less one block are placed in the context for decodeFinal processing.
 * @param srcBuf         [IN] Passed buff buffer.
 * @param srcBufLen      [IN] Input buff buffer length.
 * @param dstBuf        [OUT] String obtained after decoding.
 * @param dstBufLen     [OUT] Length obtained after decoding.
 * @retval In the case of success, return BSL_SUCCESS; Otherwise, returned error code.
 */
int32_t BSL_BASE64_DecodeUpdate(BSL_Base64Ctx *ctx, const char *srcBuf, const uint32_t srcBufLen,
    uint8_t *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Decode the specified buffer into the DER format.
 * @par Description: Decode the remaining characters stored in the context buffer.
 * @param dstBufLen     [OUT] Length obtained after decoding.
 * @param dstBuf        [OUT] String obtained after decoding.
 * @retval In the case of success, return BSL_SUCCESS. Otherwise, returned error code.
 */
int32_t BSL_BASE64_DecodeFinal(BSL_Base64Ctx *ctx, uint8_t *dstBuf, uint32_t *dstBufLen);

/**
 * @ingroup bsl_base64
 * @brief Set the flag
 * @par Description: sets the context flags
 * @param ctx        [IN] Input context.
 * @param flags      [IN] Flags to be set.
 * @retval In the case of success, return BSL_SUCCESS; Otherwise, returned error code.
 */
int32_t BSL_BASE64_SetFlags(BSL_Base64Ctx *ctx, uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif
