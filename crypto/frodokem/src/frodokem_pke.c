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
#ifdef HITLS_CRYPTO_FRODOKEM
#include <stdlib.h>
#include <string.h>
#include "frodo_local.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"

static void FrodoCommonSampleNFromR(uint16_t *samples, const size_t n, const uint16_t *cdfTable, const size_t cdfLen,
                                    const uint8_t *rBytes)
{
    for (size_t i = 0; i < n; i++) {
        uint16_t r = (uint16_t)rBytes[2 * i] | ((uint16_t)rBytes[2 * i + 1] << 8);

        uint16_t prnd = r >> 1;
        uint16_t sign = r & 1;

        uint16_t t = 0;
        for (size_t j = 0; j < cdfLen - 1; j++) {
            t += (uint16_t)(cdfTable[j] - prnd) >> 15;
        }
        samples[i] = ((uint16_t)(-sign) ^ t) + sign;
    }
}

int32_t FrodoPkeKeygenSeeded(const FrodoKemParams *params, uint8_t *pk, uint16_t *matrixSTranspose,
                             const uint8_t *seedA, const uint8_t *seedSE)
{
    const uint16_t n = params->n;
    const uint16_t nBar = params->nBar;
    const size_t count = (size_t)n * nBar;
    const size_t bytesOne = 2 * count;
    const size_t bytesBoth = 2 * bytesOne;

    uint8_t *rAll = (uint8_t *)BSL_SAL_Malloc(bytesBoth);
    if (rAll == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    // sample (r_0, r_1, ..., r_{2*n*nBar-1}) = SHAKE(0x5F || seedSE)
    int32_t ret = FrodoExpandShakeDs(rAll, bytesBoth, 0x5F, seedSE, params->lenSeedSE, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(rAll);
        return ret;
    }
    // S^T = Sample(r_0, r_1, ..., r_{n*nBar-1})
    FrodoCommonSampleNFromR(matrixSTranspose, count, params->cdfTable, params->cdfLen, rAll);

    uint16_t *B = (uint16_t *)BSL_SAL_Malloc(bytesOne);
    if (B == NULL) {
        BSL_SAL_FREE(rAll);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // E = Sample(r_{n*nBar}, r_{n*nBar+1}, ..., r_{2*n*nBar-1}) where E is stored in varible B temporarily
    FrodoCommonSampleNFromR(B, count, params->cdfTable, params->cdfLen, rAll + bytesOne);

    BSL_SAL_FREE(rAll);

    // step 1: A = GenerateA(seedA)
    // step2: B += A*S, output B = A*S + E
    ret = FrodoCommonMulAddAsPlusEPortable(B, matrixSTranspose, seedA, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(B);
        return ret;
    }

    for (int32_t i = 0; i < params->lenSeedA; i++) {
        pk[i] = seedA[i];
    }
    FrodoCommonPack(pk + params->lenSeedA, params->pkSize - params->lenSeedA, B, count, params->logq);
    BSL_SAL_FREE(B);
    return CRYPT_SUCCESS;
}

int32_t FrodoPkeEncrypt(const FrodoKemParams *params, const uint8_t *pk, const uint8_t *mu, const uint8_t *seedSEp,
                        uint8_t *ct)
{
    const uint16_t n = params->n;
    const uint16_t nBar = params->nBar;
    const uint16_t qMask = (uint16_t)((1u << params->logq) - 1u);

    const uint8_t *pkSeedA = pk;
    const uint8_t *pkB = pk + params->lenSeedA;
    const size_t lenC1 = ((size_t)n * nBar * params->logq) / 8;
    const size_t lenC2 = ((size_t)nBar * nBar * params->logq) / 8;
    uint8_t *ctC1 = ct;
    uint8_t *ctC2 = ct + lenC1;

    const size_t cntNNBar = (size_t)n * nBar; // n x nBar matrix
    const size_t cntNBarNBar = (size_t)nBar * nBar; // nBar x nBar matrix
    const size_t bytesS = 2 * cntNNBar;
    const size_t bytesE = 2 * cntNNBar;
    const size_t bytesEp = 2 * cntNBarNBar;
    // Ep denotes E', Epp denotes E'', and so on
    uint8_t *r96 = (uint8_t *)BSL_SAL_Malloc(bytesS + bytesE + bytesEp);
    if (r96 == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // r96 = SHAKE(0x96 || seedSEp) = (rS, rE, rE')
    int32_t ret = FrodoExpandShakeDs(r96, bytesS + bytesE + bytesEp, 0x96, seedSEp, params->lenSeedSE, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(r96);
        return ret;
    }
    uint8_t *rS = r96;
    uint8_t *rE = r96 + bytesS;
    uint8_t *rEp = r96 + bytesS + bytesE;
    // Memory layout:
    // |<-      S^T       -   >|<-      E'             >|<-      E''       ->|<-      B        -  >|<-      U          ->|<-      V        ->|<-      M        ->|
    // |<-      n x nBar     ->|<-      n x nBar     ->|<-   nBar x nBar   ->|<-     n x nBar    ->|<-     n x nBar    ->|<-  nBar x nBar ->|<-  nBar x nBar   ->|
    uint16_t *matrixBuf = (uint16_t *)BSL_SAL_Malloc((4 * cntNNBar + 3 * cntNBarNBar) * sizeof(uint16_t));
    if (matrixBuf == NULL) {
        BSL_SAL_FREE(r96);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    uint16_t *STp = matrixBuf;
    uint16_t *Eprime = STp + cntNNBar;
    uint16_t *Epp = Eprime + cntNNBar;
    uint16_t *B = Epp + cntNBarNBar;
    uint16_t *U = B + cntNNBar;
    uint16_t *V = U + cntNNBar;
    uint16_t *M = V + cntNBarNBar;

    FrodoCommonSampleNFromR(STp, cntNNBar, params->cdfTable, params->cdfLen, rS);
    FrodoCommonSampleNFromR(Eprime, cntNNBar, params->cdfTable, params->cdfLen, rE);
    FrodoCommonSampleNFromR(Epp, cntNBarNBar, params->cdfTable, params->cdfLen, rEp);

    BSL_SAL_FREE(r96);
    ret = FrodoCommonMulAddSaPlusEPortable(U, STp, Eprime, pkSeedA, params);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(matrixBuf);
        return ret;
    }
    FrodoCommonUnpack(B, (size_t)n * nBar, pkB, params->pkSize - params->lenSeedA, params->logq);

    FrodoCommonMulAddSbPlusEPortable(V, STp, B, Epp, params);

    FrodoCommonKeyEncode(M, (const uint16_t *)mu, params);
    for (size_t t = 0; t < cntNBarNBar; t++) {
        V[t] = (uint16_t)((V[t] + M[t]) & qMask);
    }

    FrodoCommonPack(ctC1, lenC1, U, (size_t)nBar * n, params->logq);
    FrodoCommonPack(ctC2, lenC2, V, (size_t)nBar * nBar, params->logq);
    BSL_SAL_FREE(matrixBuf);
    return CRYPT_SUCCESS;
}

int32_t FrodoPkeDecrypt(const FrodoKemParams *params, const uint8_t *pkeSk, const uint8_t *ct, uint8_t *mu)
{
    const uint8_t *ctC1 = ct;
    const uint8_t *ctC2 = ct + (params->n * params->nBar * params->logq) / 8;

    const size_t cntNNBar = (size_t)params->n * params->nBar; // n x nBar matrix
    const size_t cntNBarNBar = (size_t)params->nBar * params->nBar; // nBar x nBar matrix
    uint16_t *matrixBuf = BSL_SAL_Malloc((cntNNBar + 2 * cntNBarNBar) * sizeof(uint16_t));
    if (matrixBuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Memory layout:
    // |<-      B'       -   >|<-      C        -    >|<-      M        ->|
    // |<-     n x nBar    ->|<-    nBar x nBar   ->|<-  nBar x nBar   ->|
    uint16_t *Bp = matrixBuf;
    uint16_t *C = Bp + cntNNBar;
    uint16_t *M = C + cntNBarNBar;

    const uint16_t *S = (const uint16_t *)pkeSk;

    FrodoCommonUnpack(Bp, params->nBar * params->n, ctC1, (params->n * params->nBar * params->logq) / 8, params->logq);
    FrodoCommonUnpack(C, params->nBar * params->nBar, ctC2, (params->nBar * params->nBar * params->logq) / 8,
                      params->logq);

    FrodoCommonMulBsUsingSt(M, Bp, S, params);
    FrodoCommonSub(M, C, M, params);

    FrodoCommonKeyDecode((uint16_t *)mu, M, params);
    BSL_SAL_FREE(matrixBuf);

    return CRYPT_SUCCESS;
}
#endif
