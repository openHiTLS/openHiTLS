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

#ifndef MCELIECE_SHAKE_H
#define MCELIECE_SHAKE_H

#include "crypt_eal_md.h"
#include "pqcp_err.h"
#include "bsl_errno.h"
#include "mceliece_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// High-level SHAKE256 function
int32_t CMShake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

int32_t CMMdFunc(const CRYPT_MD_AlgId id, const uint8_t *input1, const uint32_t inLen1, const uint8_t *input2,
    const uint32_t inLen2, uint8_t *output, uint32_t *outLen);

// McEliece-specific hash functions
void McEliecePrg(const uint8_t *seed, uint8_t *output, size_t output_len);

#ifdef __cplusplus
}
#endif

#endif  // MCELIECE_SHAKE_H
