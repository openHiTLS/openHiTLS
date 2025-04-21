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

#ifndef CRYPT_HYBRID_KEM_LOCAL_H
#define CRYPT_HYBRID_KEM_LOCAL_H

#include "crypt_local_types.h"
#include "sal_atomic.h"

struct HybridKemCtx {
    void *pkeyCtx;     // CRYPT_CURVE25519_Ctx or CRYPT_ECDH_Ctx
    void *kemCtx;      // CRYPT_ML_KEM_Ctx
    const EAL_PkeyMethod *pKeyMethod;
    const EAL_PkeyMethod *kemMethod;
    BSL_SAL_RefCount references;
    void *libCtx;
};

#endif