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

// Source code for the test .so file

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CRYPT_EAL_FUNCEND_ID  0
#define CRYPT_EAL_FUNC_END     {CRYPT_EAL_FUNCEND_ID, NULL}
#define CRYPT_EAL_ALGINFO_END  {CRYPT_EAL_FUNCEND_ID, NULL, NULL}

#define CRYPT_EAL_PROVCB_FREE     1
#define CRYPT_EAL_PROVCB_QUERY    2
#define CRYPT_EAL_PROVCB_CTRL     3

typedef struct {
    int32_t id;
    void *func;
} CRYPT_EAL_Func;


typedef struct {
    int32_t algId; // implemented algorithm id, such as aes128cbc, rsa sign
    const CRYPT_EAL_Func *implFunc; // implemented algorithm callback
    const char *attr; // implemented algorithm attribute
} CRYPT_EAL_AlgInfo;

typedef struct EAL_ProviderMgrCtx CRYPT_EAL_ProvMgrCtx;

void CRYPT_EAL_ProvFreeCb(void *provCtx)
{
    return;
}

int32_t CRYPT_EAL_ProvQueryCb(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos)
{
    return 0;
}

int32_t CRYPT_EAL_ProvCtrlCb(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    return 0;
}

static CRYPT_EAL_Func g_outFuncs[] = {
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_ProvFreeCb},
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_ProvQueryCb},
    {CRYPT_EAL_PROVCB_CTRL, CRYPT_EAL_ProvCtrlCb},
    CRYPT_EAL_FUNC_END
};
