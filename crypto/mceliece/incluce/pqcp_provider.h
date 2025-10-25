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

#ifndef PQCP_PROVIDER_H
#define PQCP_PROVIDER_H

#include "crypt_eal_provider.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm IDs */
#define CRYPT_PKEY_SCLOUDPLUS 0x88000001
#define CRYPT_PKEY_FRODOKEM 0x88000002
#define CRYPT_PKEY_MCELIECE 0x88000003

/* Provider initialization function */
int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx,
                              BSL_Param *param,
                              CRYPT_EAL_Func *capFuncs,
                              CRYPT_EAL_Func **outFuncs,
                              void **provCtx);

#ifdef __cplusplus
}
#endif

#endif /* PQCP_PROVIDER_H */ 