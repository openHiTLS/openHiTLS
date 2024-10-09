/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_BASE64_INTERNAL_H
#define BSL_BASE64_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_BASE64

#include "bsl_base64.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BASE64_ControlBlock {
    /* size of the unencoded block in the current buffer */
    uint32_t num;
    /*
     * Size of the block for internal encoding and decoding.
     * The size of the coding block is set to 48, and the size of the decoding block is set to 64.
     */
    uint32_t length;
    /* see BSL_BASE64_FLAGS*, for example: BSL_BASE64_FLAGS_NO_NEWLINE, means process without '\n' */
    uint32_t flags;
    uint32_t paddingCnt;
    /* codec buffer */
    uint8_t buf[HITLS_BASE64_CTX_BUF_LENGTH];
};

#define BASE64_ENCODE_BYTES 3 // encode 3 bytes at a time
#define BASE64_DECODE_BYTES 4 // decode 4 bytes at a time
#define BASE64_BLOCK_SIZE  1024
#define BASE64_PAD_MAX 2
#define BASE64_DECODE_BLOCKSIZE 64
#define BASE64_CTX_BUF_SIZE HITLS_BASE64_ENCODE_LENGTH(BASE64_BLOCK_SIZE) + 10
#define BSL_BASE64_ENC_ENOUGH_LEN(len) (((len) + 2) / 3 * 4 + 1)
#define BSL_BASE64_DEC_ENOUGH_LEN(len) (((len) + 3) / 4 * 3)

/**
 * @ingroup bsl_base64
 * @brief Obtain the remaining context buf and determine whether to invoke final().
 * @par Description: Obtains the remaining length "num" of the context buf.
 * @param ctx        [IN] Input context.
 * @param num        [OUT] Obtain the remaining length of the buf.
 * @retval If it is success, BSL_SUCCESS is returned. Otherwise, a failure error code is returned.
 */
int32_t BSL_Base64GetNum(BSL_Base64Ctx *ctx, uint32_t *num);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_BSL_BASE64 */
#endif /* conditional include */