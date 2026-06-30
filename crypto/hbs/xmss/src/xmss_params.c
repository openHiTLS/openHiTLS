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
#ifdef HITLS_CRYPTO_XMSS

#include <string.h>
#include "xmss_params.h"
#include "crypt_utils.h"

/*
 * XMSS Parameter Table (RFC 8391 + RFC 9802)
 *
 * This static table contains XMSS parameter sets with their corresponding
 * XDR OIDs for X.509 certificate support.
 *
 * Array Format: {algId, n, h, wotsW, wotsLen, pkBytes, sigBytes, {xdrAlgId}, mdId, paddingLen}
 *
 * Notes:
 * - wotsW is always 16 for all XMSS variants (RFC 8391 Section 5.3).
 * - pkBytes = 2 * n + 4 (OID + root + seed)
 * - sigBytes = 4 + n + (wotsLen + h) * n  (idx + r + WOTS+ sig + auth)
 * - xdrAlgId is the 4-byte XMSS XDR OID from RFC 8391 Appendix B.
 * - mdId and paddingLen are used by generic hash function implementation.
 */
static const XmssParams g_xmssParams[] = {
    /* XMSS with SHA2-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHA2_10_256, 32, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x01}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSS_SHA2_16_256, 32, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x02}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSS_SHA2_20_256, 32, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x03}, CRYPT_MD_SHA256, 32},

    /* XMSS with SHA2-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSS_SHA2_10_512, 64, 10, 16, 131, 132, 9092, {0x0, 0x0, 0x0, 0x04}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSS_SHA2_16_512, 64, 16, 16, 131, 132, 9476, {0x0, 0x0, 0x0, 0x05}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSS_SHA2_20_512, 64, 20, 16, 131, 132, 9732, {0x0, 0x0, 0x0, 0x06}, CRYPT_MD_SHA512, 64},

    /* XMSS with SHAKE128 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHAKE_10_256, 32, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x07}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSS_SHAKE_16_256, 32, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x08}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSS_SHAKE_20_256, 32, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x09}, CRYPT_MD_SHAKE128, 32},

    /* XMSS with SHAKE256-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSS_SHAKE_10_512, 64, 10, 16, 131, 132, 9092, {0x0, 0x0, 0x0, 0x0a}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSS_SHAKE_16_512, 64, 16, 16, 131, 132, 9476, {0x0, 0x0, 0x0, 0x0b}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSS_SHAKE_20_512, 64, 20, 16, 131, 132, 9732, {0x0, 0x0, 0x0, 0x0c}, CRYPT_MD_SHAKE256, 64},

    /* XMSS with SHA2-192 (n=24) - paddingLen = 4 (special case for 192-bit) */
    {CRYPT_XMSS_SHA2_10_192, 24, 10, 16, 51, 52, 1492, {0x0, 0x0, 0x0, 0x0d}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSS_SHA2_16_192, 24, 16, 16, 51, 52, 1636, {0x0, 0x0, 0x0, 0x0e}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSS_SHA2_20_192, 24, 20, 16, 51, 52, 1732, {0x0, 0x0, 0x0, 0x0f}, CRYPT_MD_SHA256, 4},

    /* XMSS with SHAKE256-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHAKE256_10_256, 32, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x10}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSS_SHAKE256_16_256, 32, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x11}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSS_SHAKE256_20_256, 32, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x12}, CRYPT_MD_SHAKE256, 32},

    /* XMSS with SHAKE256-192 (n=24) - paddingLen = 4 */
    {CRYPT_XMSS_SHAKE256_10_192, 24, 10, 16, 51, 52, 1492, {0x0, 0x0, 0x0, 0x13}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSS_SHAKE256_16_192, 24, 16, 16, 51, 52, 1636, {0x0, 0x0, 0x0, 0x14}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSS_SHAKE256_20_192, 24, 20, 16, 51, 52, 1732, {0x0, 0x0, 0x0, 0x15}, CRYPT_MD_SHAKE256, 4},

};

const XmssParams *XmssParams_FindByAlgId(CRYPT_PKEY_ParaId algId)
{
    for (uint32_t i = 0; i < sizeof(g_xmssParams) / sizeof(g_xmssParams[0]); i++) {
        if (g_xmssParams[i].algId == algId) {
            return &g_xmssParams[i];
        }
    }
    /* Algorithm ID not found in parameter table */
    return NULL;
}

const XmssParams *XmssParams_FindByXdrId(uint32_t xdrId)
{
    /* Convert xdrId to 4-byte array for comparison (big-endian) */
    uint8_t xdrIdBytes[HASH_SIGN_XDR_ALG_TYPE_LEN] = {0};
    PUT_UINT32_BE(xdrId, xdrIdBytes, 0);

    /* Linear search through parameter table to find matching XDR OID */
    for (uint32_t i = 0; i < sizeof(g_xmssParams) / sizeof(g_xmssParams[0]); i++) {
        if (memcmp(g_xmssParams[i].xdrAlgId, xdrIdBytes, HASH_SIGN_XDR_ALG_TYPE_LEN) == 0) {
            /* Found matching parameter set - return pointer to global table */
            return &g_xmssParams[i];
        }
    }
    /* No match found - invalid XDR ID */
    return NULL;
}

#endif /* HITLS_CRYPTO_XMSS */
