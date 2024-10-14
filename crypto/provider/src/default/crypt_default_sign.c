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
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_sm2.h"
#include "crypt_curve25519.h"

const CRYPT_EAL_Func defSignDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_DSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_DSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_DSA_VerifyData},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_DSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignEd25519[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_CURVE25519_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_CURVE25519_VerifyData},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_CURVE25519_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignRsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_RSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_RSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_RSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_RSA_VerifyData},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_RSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_ECDSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_ECDSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_ECDSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_ECDSA_VerifyData},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_ECDSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignSm2[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_SM2_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_SM2_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_SM2_Ctrl},
    CRYPT_EAL_FUNC_END,
};
