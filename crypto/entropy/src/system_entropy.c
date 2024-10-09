/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENTROPY

#include <stdint.h>

#include "entropy.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"

#ifdef ENTROPY_USE_DEVRANDOM
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

int32_t ENTROPY_GetRandom(uint8_t *data, uint32_t len)
{
#ifdef ENTROPY_USE_DEVRANDOM
    int32_t fd = open("/dev/random", O_RDONLY);
    if (fd == -1) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    uint32_t remain = len;
    int32_t count = 0;
    uint8_t *ptr = data;
    do {
        count = (int32_t)read(fd, ptr, remain);
        if (count == -1 && errno == EINTR) {
            continue;
        } else if (count == -1) {
            break;
        }
        remain -= (uint32_t)count;
        ptr += (uint32_t)count;
    } while (remain > 0);
    close(fd);
    if (remain > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    return CRYPT_SUCCESS;
#else
    (void)data;
    (void)len;
    BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
    return CRYPT_DRBG_FAIL_GET_ENTROPY;
#endif
}
#endif /* HITLS_CRYPTO_ENTROPY */
