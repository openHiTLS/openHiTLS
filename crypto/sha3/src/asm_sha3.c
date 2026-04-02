/*
 *
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
#ifdef HITLS_CRYPTO_SHA3

#include "asm_sha3.h"
#include <stddef.h>
#include <string.h>
#include "crypt_sha3.h"

void Shake256x2(uint8_t *dgst0, uint8_t *dgst1, size_t dgstLen, const uint8_t *in0, const uint8_t *in1, size_t inlen)
{
    Keccakx2State state;
    size_t nblocks;
    
    /* Absorb phase */
    Keccakx2Absorb(state, CRYPT_SHAKE256_BLOCKSIZE, in0, in1, inlen, 0x1F);

    /* Squeeze full blocks */
    nblocks = dgstLen / CRYPT_SHAKE256_BLOCKSIZE;
    if (nblocks > 0) {
        Keccakx2Squeeze(dgst0, dgst1, nblocks, CRYPT_SHAKE256_BLOCKSIZE, state);
        dgst0 += nblocks * CRYPT_SHAKE256_BLOCKSIZE;
        dgst1 += nblocks * CRYPT_SHAKE256_BLOCKSIZE;
        dgstLen -= nblocks * CRYPT_SHAKE256_BLOCKSIZE;
    }
    
    /* Squeeze remaining bytes */
    if (dgstLen > 0) {
        uint8_t tmp0[CRYPT_SHAKE256_BLOCKSIZE];
        uint8_t tmp1[CRYPT_SHAKE256_BLOCKSIZE];
        Keccakx2Squeeze(tmp0, tmp1, 1, CRYPT_SHAKE256_BLOCKSIZE, state);
        memcpy(dgst0, tmp0, dgstLen);
        memcpy(dgst1, tmp1, dgstLen);
    }
}

#endif // HITLS_CRYPTO_SHA3