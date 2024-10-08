/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#include "crypt_eal_implprovider.h"
#include "crypt_dsa.h"
#include "crypt_curve25519.h"
#include "crypt_rsa.h"
#include "crypt_dh.h"
#include "crypt_ecdsa.h"
#include "crypt_ecdh.h"
#include "crypt_sm2.h"
#include "crypt_errno.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "crypt_eal_pkey.h"

typedef struct {
    void *pkeyCtx;
    int32_t algId;
    int32_t index;
} CRYPT_EAL_DefPkeyCtx;

const CRYPT_EAL_Func defAsymCipherRsa[] = {
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, CRYPT_RSA_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, CRYPT_RSA_Decrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_CTRL, CRYPT_RSA_Ctrl},
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func defAsymCipherSm2[] = {
    {CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT, CRYPT_SM2_Encrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT, CRYPT_SM2_Decrypt},
    {CRYPT_EAL_IMPLPKEYCIPHER_CTRL, CRYPT_SM2_Ctrl},
    CRYPT_EAL_FUNC_END
};