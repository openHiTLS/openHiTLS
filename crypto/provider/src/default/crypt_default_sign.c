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
#include "crypt_bn.h"

const CRYPT_EAL_Func defSignDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_DSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_DSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignEd25519[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_CURVE25519_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_CURVE25519_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_CURVE25519_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignX25519[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_CURVE25519_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_CURVE25519_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_CURVE25519_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignRsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_RSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_RSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_RSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_ECDSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_ECDSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_ECDSA_Ctrl},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func defSignSm2[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_SM2_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_SM2_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_CTRL, CRYPT_SM2_Ctrl},
    CRYPT_EAL_FUNC_END,
};
