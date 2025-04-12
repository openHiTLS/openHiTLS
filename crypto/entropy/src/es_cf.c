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
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)
#include <stdint.h>
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "es_cf.h"

ES_CfMethod *ES_CFGetMethod(uint32_t algId, void *md)
{
    switch (algId) {
        case CRYPT_MD_SM3:
        case CRYPT_MD_SHA256:
        case CRYPT_MD_SHA224:
        case CRYPT_MD_SHA384:
        case CRYPT_MD_SHA512:
            return ES_CFGetDfMethod((EAL_MdMethod *)md);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_ENTROPY_ECF_ALG_ERROR);
            return NULL;
    }
}

#endif