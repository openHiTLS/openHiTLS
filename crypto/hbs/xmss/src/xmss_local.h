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

#ifndef XMSS_LOCAL_H
#define XMSS_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT)

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "hbs_wots.h"
#include "hbs_tree.h"
#include "xmss_params.h"
#include "xmss_address.h"
#include "xmss_bds.h"

#ifdef __cplusplus
extern "C" {
#endif

/* XMSS_MAX_SEED_SIZE is defined in xmss_params.h, included above. */

/*
 * XMSS Context
 *
 * This structure contains all state needed for XMSS operations.
 * It is designed to be independent of SLH-DSA.
 */
typedef struct CryptXmssCtx {
    const XmssParams *params; // XMSS parameters (pointer to global param table)

    bool isXmssmt; // true = XMSS^MT (d > 1), false = XMSS (d == 1), set at creation

    const XmssFamilyHashFuncs *hashFuncs; // Hash function table (pointer to static table)

    XmssFamilyAdrsOps adrsOps; // Generic address operation function pointers

    struct {
        uint8_t seed[XMSS_MAX_SEED_SIZE]; // Private seed (SK.seed)
        uint8_t prf[XMSS_MAX_SEED_SIZE]; // PRF key (SK.prf)
        uint64_t idx; // Next unused leaf index
        uint8_t root[XMSS_MAX_MDSIZE]; // Tree root (PK.root)
        uint8_t pubSeed[XMSS_MAX_SEED_SIZE]; // Public seed (PK.seed)
    } key;

    XmssBdsCtx bds;

    bool hasPrivateKey; // Whether key.seed/prf/idx contain usable private signing state.

    /* Library context */
    void *libCtx;
} CryptXmssCtx;

/*
 * Initialize XMSS context
 *
 * @param ctx     XMSS context to initialize
 * @param params  XMSS parameters
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t CRYPT_XMSS_InitInternal(CryptXmssCtx *ctx, const XmssParams *params);

/*
 * Generate XMSS key pair
 *
 * @param ctx  XMSS context (will be populated with generated keys)
 *
 * @return CRYPT_SUCCESS on success
 */
int32_t CRYPT_XMSS_KeyGenInternal(CryptXmssCtx *ctx);

/*
 * Sign a message using XMSS
 *
 * @param ctx      XMSS context
 * @param msg      Message to sign (n bytes)
 * @param msgLen   Length of message (must be n)
 * @param sig      Output signature buffer
 * @param sigLen   Input: buffer size, Output: actual signature length
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_XMSS_ERR_KEY_EXPIRED if all signatures used
 */
int32_t CRYPT_XMSS_SignInternal(CryptXmssCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig, uint32_t *sigLen);

/*
 * Verify an XMSS signature (internal)
 *
 * @param ctx      XMSS context
 * @param msg      Message to verify (n bytes)
 * @param msgLen   Length of message (must be n)
 * @param sig      Signature to verify
 * @param sigLen   Length of signature
 *
 * @return CRYPT_SUCCESS on success
 *         CRYPT_XMSS_ERR_VERIFY_FAIL on verification failure
 */
int32_t CRYPT_XMSS_VerifyInternal(const CryptXmssCtx *ctx, const uint8_t *msg, uint32_t msgLen, const uint8_t *sig,
                                  uint32_t sigLen);

/*
 * Initialize HbsTreeCtx from an XMSS context.
 *
 * Used by xmss_core.c to populate a unified HBS tree context before
 * calling HbsTree_* / HbsHyperTree_* in hbs_tree.c.
 *
 * @param treeCtx [out] Tree context to initialize
 * @param ctx     [in]  XMSS context
 */
void HbsTreeCtx_InitFromXmss(HbsTreeCtx *treeCtx, const CryptXmssCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* defined(HITLS_CRYPTO_XMSS) || defined(HITLS_CRYPTO_XMSSMT) */
#endif /* XMSS_LOCAL_H */
