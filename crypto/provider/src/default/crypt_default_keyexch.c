/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#include "crypt_eal_implprovider.h"
#include "crypt_curve25519.h"
#include "crypt_dh.h"
#include "crypt_ecdh.h"
#include "crypt_sm2.h"

typedef struct {
    void *pkeyCtx;
    int32_t algId;
    int32_t index;
} CRYPT_EAL_DefPkeyCtx;

const CRYPT_EAL_Func defExchX25519[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_CURVE25519_ComputeSharedKey},
    {CRYPT_EAL_IMPLPKEYEXCH_CTRL, CRYPT_CURVE25519_Ctrl},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defExchDh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_DH_ComputeShareKey},
    {CRYPT_EAL_IMPLPKEYEXCH_CTRL, CRYPT_DH_Ctrl},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defExchEcdh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_ECDH_ComputeShareKey},
    {CRYPT_EAL_IMPLPKEYEXCH_CTRL, CRYPT_ECDH_Ctrl},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defExchSm2[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_SM2_KapComputeKey},
    {CRYPT_EAL_IMPLPKEYEXCH_CTRL, CRYPT_SM2_Ctrl},
    CRYPT_EAL_FUNC_END
};