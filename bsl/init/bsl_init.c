/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_BSL_INIT

#include "bsl_err.h"
#include "bsl_errno.h"

int32_t BSL_GLOBAL_Init(void)
{
    return BSL_ERR_Init();
}

int32_t BSL_GLOBAL_DeInit(void)
{
    BSL_ERR_DeInit();
    return BSL_SUCCESS;
}

#endif /* HITLS_BSL_INIT */
