/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
    int32_t type;
    void *param;
    uint32_t paramLen;
} CRYPT_Param;

typedef struct {
    int32_t algId; // implemented algorithm id, such as aes128cbc, rsa sign
    const CRYPT_EAL_Func *implFunc; // implemented algorithm callback
    const char *attr; // implemented algorithm attribute
} CRYPT_EAL_AlgInfo;

typedef struct EalProviderMgrCtx CRYPT_EAL_ProvMgrCtx;

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

int32_t CRYPT_EAL_ProviderInitcb(CRYPT_EAL_ProvMgrCtx *mgrCtx,
    CRYPT_Param *param, CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    *outFuncs = g_outFuncs;
    return 0;
}
