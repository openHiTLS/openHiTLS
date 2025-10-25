/*
Reference FIPS202 SHAKE256 implementation for McEliece
Based on the official Keccak Team implementation

Implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
hereby denoted as "the implementer".

For more information, feedback or questions, please refer to our website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "mceliece_shake.h"
#include "securec.h"

int32_t CMShake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    uint32_t len = (uint32_t)outlen;
    return CMMdFunc(CRYPT_MD_SHAKE256, input, inlen, NULL, 0, output, &len);
}

int32_t CMMdFunc(const CRYPT_MD_AlgId id, const uint8_t *input1, const uint32_t inLen1, const uint8_t *input2,
    const uint32_t inLen2, uint8_t *output, uint32_t *outLen)
{
    CRYPT_EAL_MdCTX *MdCtx = CRYPT_EAL_MdNewCtx(id);
    if (MdCtx == NULL) {
        return BSL_MALLOC_FAIL;
    }
    int32_t ret = CRYPT_EAL_MdInit(MdCtx);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(MdCtx, input1, inLen1);
    if (ret != PQCP_SUCCESS) {
        goto EXIT;
    }
    if (input2 != NULL) {
        ret = CRYPT_EAL_MdUpdate(MdCtx, input2, inLen2);
        if (ret != PQCP_SUCCESS) {
            goto EXIT;
        }
    }
    ret = CRYPT_EAL_MdFinal(MdCtx, output, outLen);
EXIT:
    CRYPT_EAL_MdFreeCtx(MdCtx);
    return ret;
}

// McEliece PRG using SHAKE256
void McEliecePrg(const uint8_t *seed, uint8_t *output, size_t output_len)
{
    uint8_t temp_seed[33];
    temp_seed[0] = 64;
    memcpy_s(temp_seed + 1, MCELIECE_L_BYTES, seed, MCELIECE_L_BYTES);
    CMShake256(output, output_len, temp_seed, 33);
}
