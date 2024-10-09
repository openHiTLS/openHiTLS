/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "securec.h"
#include "bsl_sal.h"
#include "crypt_sm4.h"

void CRYPT_SM4_XTS_Clean(CRYPT_SM4_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_CleanseData((void *)(ctx), sizeof(CRYPT_SM4_Ctx) * 2); // cipher context has 2 method contexts in xts mode
}
#endif /* HITLS_CRYPTO_SM4 */
