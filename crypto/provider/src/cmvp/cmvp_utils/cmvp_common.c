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
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_SM) || defined(HITLS_CRYPTO_CMVP_FIPS)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <syslog.h>
#include <stdarg.h>
#include "securec.h"
#include "crypt_cmvp.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_cmvp_selftest.h"
#include "cmvp_integrity_hmac.h"
#include "cmvp_common.h"

#define BSL_PARAM_MAX_NUMBER 1000

uint8_t *CMVP_StringsToBins(const char *in, uint32_t *outLen)
{
    if (in == NULL) {
        return NULL;
    }
    uint32_t inLen = (uint32_t)strlen(in);
    uint8_t *out = NULL;
    if (inLen == 0) {
        return NULL;
    }
    // The length of a hexadecimal string must be a multiple of 2.
    if (inLen % 2 != 0) {
        return NULL;
    }
    // Length of the hexadecimal string / 2 = Length of the byte stream
    inLen = inLen / 2;
    out = BSL_SAL_Malloc(inLen);
    if (out == NULL) {
        return NULL;
    }
    *outLen = inLen;

    // A group of 2 bytes
    for (uint32_t i = 0; i < 2 * inLen; i += 2) {
        // Formula for converting hex to int: (Hex% 32 + 9)% 25 = int, hexadecimal, 16: high 4 bits.
        out[i / 2] = ((uint8_t)in[i] % 32 + 9) % 25 * 16 + ((uint8_t)in[i + 1] % 32 + 9) % 25;
    }
    return out;
}

void CMVP_WriteSyslog(const char *ident, int32_t priority, const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    openlog(ident, LOG_PID | LOG_ODELAY, LOG_USER);
    vsyslog(priority, format, vargs);
    closelog();
    va_end(vargs);
}

char *CMVP_ReadFile(const char *path, const char *mode, uint32_t *bufLen)
{
    int64_t len;
    int64_t readLen;
    FILE *fp = NULL;
    char *buf = NULL;

    fp = fopen(path, mode);
    if (fp == NULL) {
        return false;
    }
    GOTO_ERR_IF_TRUE(fseek(fp, 0, SEEK_END) != 0, CRYPT_CMVP_COMMON_ERR);
    len = ftell(fp);
    GOTO_ERR_IF_TRUE(len == -1, CRYPT_CMVP_COMMON_ERR);
    buf = BSL_SAL_Malloc((uint32_t)len + 1);
    GOTO_ERR_IF_TRUE(buf == NULL, CRYPT_MEM_ALLOC_FAIL);
    buf[len] = '\0';
    GOTO_ERR_IF_TRUE(fseek(fp, 0, SEEK_SET) != 0, CRYPT_CMVP_COMMON_ERR);
    readLen = (int64_t)fread(buf, sizeof(uint8_t), (uint64_t)len, fp);
    GOTO_ERR_IF_TRUE(readLen != len && feof(fp) == 0, CRYPT_CMVP_COMMON_ERR);
    *bufLen = (uint32_t)readLen;
    (void)fclose(fp);
    return buf;
ERR:
    BSL_SAL_Free(buf);
    (void)fclose(fp);
    return NULL;
}

static char *CMVP_GetLibPath(void *func)
{
    Dl_info info;
    char *path = NULL;

    GOTO_ERR_IF_TRUE(dladdr(func, &info) == 0, CRYPT_CMVP_COMMON_ERR);
    path = BSL_SAL_Malloc((uint32_t)strlen(info.dli_fname) + 1);
    GOTO_ERR_IF_TRUE(path == NULL, CRYPT_MEM_ALLOC_FAIL);
    (void)memcpy_s(path, strlen(info.dli_fname), info.dli_fname, strlen(info.dli_fname));
    path[strlen(info.dli_fname)] = '\0';
    return path;
ERR:
    BSL_SAL_Free(path);
    return NULL;
}

int32_t CMVP_CheckIntegrity(void *libCtx, const char *attrName, CRYPT_MAC_AlgId macId)
{
    int32_t ret = CRYPT_CMVP_ERR_INTEGRITY;
    char *libCryptoPath = NULL;
    char *libBslPath = NULL;

    if (CRYPT_CMVP_SelftestProviderMac(libCtx, attrName, macId) != true) {
        return CRYPT_CMVP_ERR_ALGO_SELFTEST;
    }
    libCryptoPath = CMVP_GetLibPath(CMVP_IntegrityHmac);
    GOTO_ERR_IF_TRUE(libCryptoPath == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CMVP_IntegrityHmac(libCtx, attrName, libCryptoPath, macId) == false, CRYPT_CMVP_ERR_INTEGRITY);

    libBslPath = CMVP_GetLibPath(BSL_SAL_Malloc);
    GOTO_ERR_IF_TRUE(libBslPath == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(CMVP_IntegrityHmac(libCtx, attrName, libBslPath, macId) == false, CRYPT_CMVP_ERR_INTEGRITY);

    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(libCryptoPath);
    BSL_SAL_Free(libBslPath);
    return ret;
}

static int32_t CopyParam(BSL_Param *param, int32_t *selfTestFlag, BSL_Param **newParam)
{
    int32_t index = 0;
    if (param != NULL) {
        while (param[index].key != 0 && index < BSL_PARAM_MAX_NUMBER) {
            index++;
        }
        if (index >= BSL_PARAM_MAX_NUMBER) {
            BSL_ERR_PUSH_ERROR(CRYPT_CMVP_COMMON_ERR);
            return CRYPT_CMVP_COMMON_ERR;
        }
    }
    int32_t count = index + 2;
    BSL_Param *tmpParam = (BSL_Param *)BSL_SAL_Calloc(count, sizeof(BSL_Param));
    if (tmpParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (param != NULL) {
        (void)memcpy_s(tmpParam, count * sizeof(BSL_Param), param, index * sizeof(BSL_Param));
    }
    int32_t ret = BSL_PARAM_InitValue(&tmpParam[index], CRYPT_PARAM_CMVP_INTERNAL_LIBCTX_FLAG, BSL_PARAM_TYPE_INT32,
        selfTestFlag, sizeof(int32_t));
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(tmpParam);
        return ret;
    }
    *newParam = tmpParam;
    return CRYPT_SUCCESS;
}

int32_t CMVP_CreateInternalLibCtx(BSL_Param *param, CRYPT_EAL_LibCtx **libCtx, void *func)
{
    int32_t selfTestFlag = 1;
    int32_t ret = CRYPT_SUCCESS;
    char *libPath = NULL;
    BSL_Param *newParam = NULL;
    CRYPT_EAL_LibCtx *ctx = NULL;

    do {
        ret = CopyParam(param, &selfTestFlag, &newParam);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        ctx = CRYPT_EAL_LibCtxNew();
        if (ctx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            ret = CRYPT_MEM_ALLOC_FAIL;
            break;
        }

        libPath = CMVP_GetLibPath(func);
        if (libPath == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_CMVP_COMMON_ERR);
            ret = CRYPT_CMVP_COMMON_ERR;
            break;
        }

        ret = CRYPT_EAL_ProviderLoad(ctx, 0, libPath, newParam, NULL);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        *libCtx = ctx;
    } while (0);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_LibCtxFree(ctx);
    }
    BSL_SAL_Free(libPath);
    BSL_SAL_Free(newParam);
    return ret;
}

bool CMVP_CheckIsInternalLibCtx(BSL_Param *param)
{
    if (param == NULL) {
        return false;
    }
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_CMVP_INTERNAL_LIBCTX_FLAG);
    if (temp != NULL && temp->valueType == BSL_PARAM_TYPE_INT32) {
        return true;
    }
    return false;
}
#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_SM || HITLS_CRYPTO_CMVP_FIPS */