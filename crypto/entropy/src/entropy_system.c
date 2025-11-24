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
#include <unistd.h>
#ifdef HITLS_CRYPTO_ENTROPY_DEVRANDOM
#include <fcntl.h>
#include <errno.h>
#endif
#ifdef HITLS_CRYPTO_ENTROPY_GETENTROPY
#include <sys/syscall.h>
#endif
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "entropy_seed_pool.h"


uint32_t ENTROPY_SysEntropyGet(void *ctx, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;

#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY) || defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
    uint32_t res = 0;
#if defined(HITLS_CRYPTO_ENTROPY_GETENTROPY)
    extern int getentropy (void *__buffer, size_t __length) __attribute__((weak));
    if (getentropy != NULL) {
        if (getentropy(buf, bufLen) == 0) {
            return bufLen;
        }
    }
#if defined(__NR_getrandom)
    return (uint32_t)syscall(__NR_getrandom, buf, bufLen, 0);
#endif
#endif

#if defined(HITLS_CRYPTO_ENTROPY_DEVRANDOM)
    int32_t fd = open("/dev/random", O_RDONLY);
    if (fd == -1) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
        return 0;
    }
    uint32_t left = bufLen;
    uint8_t *tmp = buf;
    do {
        int32_t count = (int32_t)read(fd, tmp, left);
        if (count == -1 && errno == EINTR) {
            continue;
        } else if (count == -1) {
            break;
        }
        left -= (uint32_t)count;
        tmp += (uint32_t)count;
    } while (left > 0);
    close(fd);
    if (left > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
    }
    res = bufLen - left;
#endif
    return res;
#else
    (void)buf;
    (void)bufLen;
    BSL_ERR_PUSH_ERROR(CRYPT_DRBG_FAIL_GET_ENTROPY);
    return 0;
#endif
}

#endif
