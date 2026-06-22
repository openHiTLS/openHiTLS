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
#ifdef HITLS_CRYPTO_LMS

#include <string.h>
#include "bsl_sal.h"
#include "lms_address.h"
#include "lms_local.h"

/**
 * @ingroup lms_address
 * @brief Build OTS iteration buffer (I || q || k || j || prev)
 */
void LmsAdrs_BuildOtsIterInput(uint8_t *buffer, const uint8_t *I, uint32_t q, uint32_t k, uint32_t j,
                               const uint8_t *prev, uint32_t n)
{
    /* Copy tree identifier I (16 bytes) */
    memcpy(buffer + LMS_ITER_I_OFFSET, I, LMS_I_LEN);

    /* Write leaf index q (4 bytes, big-endian) */
    BSL_Uint32ToByte(q, buffer + LMS_ITER_Q_OFFSET);

    /* Write chain index k (2 bytes, big-endian) */
    BSL_Uint16ToByte((uint16_t)k, buffer + LMS_ITER_K_OFFSET);

    /* Write iteration index j (1 byte) */
    buffer[LMS_ITER_J_OFFSET] = (uint8_t)j;

    /* Copy previous hash value (n bytes) */
    memcpy(buffer + LMS_ITER_PREV_OFFSET, prev, n);
}

/**
 * @ingroup lms_address
 * @brief Build leaf node buffer (I || r || D || pk)
 */
void LmsAdrs_BuildLeafInput(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *pk, uint32_t n)
{
    /* Copy tree identifier I (16 bytes) */
    memcpy(buffer + LMS_LEAF_I_OFFSET, I, LMS_I_LEN);

    /* Write node index r (4 bytes, big-endian) */
    BSL_Uint32ToByte(r, buffer + LMS_LEAF_R_OFFSET);

    /* Write domain separation value D = LMS_D_LEAF (2 bytes) */
    LmsSetD(buffer + LMS_LEAF_D_OFFSET, LMS_D_LEAF);

    /* Copy OTS public key (n bytes) */
    memcpy(buffer + LMS_LEAF_PK_OFFSET, pk, n);
}

/**
 * @ingroup lms_address
 * @brief Build internal node buffer (I || r || D || left || right)
 */
void LmsAdrs_BuildInternalInput(uint8_t *buffer, const uint8_t *I, uint32_t r, const uint8_t *left,
                                const uint8_t *right, uint32_t n)
{
    /* Copy tree identifier I (16 bytes) */
    memcpy(buffer + LMS_INTR_I_OFFSET, I, LMS_I_LEN);

    /* Write node index r (4 bytes, big-endian) */
    BSL_Uint32ToByte(r, buffer + LMS_INTR_R_OFFSET);

    /* Write domain separation value D = LMS_D_INTR (2 bytes) */
    LmsSetD(buffer + LMS_INTR_D_OFFSET, LMS_D_INTR);

    /* Copy left child hash (n bytes) */
    memcpy(buffer + LMS_INTR_LEFT_OFFSET, left, n);

    /* Copy right child hash (n bytes) */
    memcpy(buffer + LMS_INTR_RIGHT_OFFSET(n), right, n);
}

/**
 * @ingroup lms_address
 * @brief Build message hash buffer (I || q || D || C)
 */
void LmsAdrs_BuildMsgInput(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *C, uint32_t n)
{
    /* Copy tree identifier I (16 bytes) */
    memcpy(buffer + LMS_MESG_I_OFFSET, I, LMS_I_LEN);

    /* Write leaf index q (4 bytes, big-endian) */
    BSL_Uint32ToByte(q, buffer + LMS_MESG_Q_OFFSET);

    /* Write domain separation value D = LMS_D_MESG (2 bytes) */
    LmsSetD(buffer + LMS_MESG_D_OFFSET, LMS_D_MESG);

    /* Copy randomizer C (n bytes) */
    memcpy(buffer + LMS_MESG_C_OFFSET, C, n);
}

/**
 * @ingroup lms_address
 * @brief Build OTS public key buffer (I || q || D || chains)
 */
void LmsAdrs_BuildOtsPubKeyInput(uint8_t *buffer, const uint8_t *I, uint32_t q, const uint8_t *chains, uint32_t p,
                                 uint32_t n)
{
    /* Copy tree identifier I (16 bytes) */
    memcpy(buffer + LMS_PBLC_I_OFFSET, I, LMS_I_LEN);

    /* Write leaf index q (4 bytes, big-endian) */
    BSL_Uint32ToByte(q, buffer + LMS_PBLC_Q_OFFSET);

    /* Write domain separation value D = LMS_D_PBLC (2 bytes) */
    LmsSetD(buffer + LMS_PBLC_D_OFFSET, LMS_D_PBLC);

    /* Copy all chain values (p * n bytes) */
    memcpy(buffer + LMS_PBLC_PREFIX_LEN, chains, p * n);
}

/* Global address operations table */
static const LmsFamilyAdrsOps g_lmsAdrsOps = {
    .buildOtsIterInput = LmsAdrs_BuildOtsIterInput,
    .buildLeafInput = LmsAdrs_BuildLeafInput,
    .buildInternalInput = LmsAdrs_BuildInternalInput,
    .buildMsgInput = LmsAdrs_BuildMsgInput,
    .buildOtsPubKeyInput = LmsAdrs_BuildOtsPubKeyInput,
};

/**
 * @ingroup lms_address
 * @brief Initialize LMS address operations
 */
const LmsFamilyAdrsOps *LmsAdrsOps_Init(void)
{
    return &g_lmsAdrsOps;
}

#endif /* HITLS_CRYPTO_LMS */
