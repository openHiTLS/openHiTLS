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
#ifdef HITLS_CRYPTO_PROVIDER

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

const CRYPT_EAL_Func g_defExchX25519[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_CURVE25519_ComputeSharedKey},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defExchDh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_DH_ComputeShareKey},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defExchEcdh[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_ECDH_ComputeShareKey},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defExchSm2[] = {
    {CRYPT_EAL_IMPLPKEYEXCH_EXCH, CRYPT_SM2_KapComputeKey},
    CRYPT_EAL_FUNC_END
};

#endif /* HITLS_CRYPTO_PROVIDER */