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
