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
#include "bsl_sal.h"
#include "crypt_utils.h"

/*
 * XMSS Parameter Table (RFC 8391 + RFC 9802)
 *
 * This static table contains all XMSS and XMSSMT parameter sets with their
 * corresponding XDR OIDs for X.509 certificate support.
 *
 * Array Format: {algId, n, h, d, hp, wotsW, wotsLen, pkBytes, sigBytes, {xdrAlgId}, mdId, paddingLen}
 *
 * Notes:
 * - wotsW is always 16 for all XMSS variants (RFC 8391 Section 5.3)
 * - pkBytes = 2 * n + 4 (OID + root + seed)
 * - For XMSS (d=1): sigBytes = 4 + n + (wotsLen + h) * n  (idx + r + WOTS+ sig + auth)
 * - For XMSSMT (d>1): sigBytes = ((h + 7) / 8) + n + d * (wotsLen + hp) * n
 * - xdrAlgId is the 4-byte XDR OID from RFC 8391 Table 1
 * - mdId and paddingLen are used by generic hash function implementation
 */
static const XmssParams g_xmssParams[] = {
    /* XMSS with SHA2-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHA2_10_256, 32, 10, 1, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x01}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSS_SHA2_16_256, 32, 16, 1, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x02}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSS_SHA2_20_256, 32, 20, 1, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x03}, CRYPT_MD_SHA256, 32},

    /* XMSS with SHA2-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSS_SHA2_10_512, 64, 10, 1, 10, 16, 131, 132, 9092, {0x0, 0x0, 0x0, 0x04}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSS_SHA2_16_512, 64, 16, 1, 16, 16, 131, 132, 9476, {0x0, 0x0, 0x0, 0x05}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSS_SHA2_20_512, 64, 20, 1, 20, 16, 131, 132, 9732, {0x0, 0x0, 0x0, 0x06}, CRYPT_MD_SHA512, 64},

    /* XMSS with SHAKE128 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHAKE_10_256, 32, 10, 1, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x07}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSS_SHAKE_16_256, 32, 16, 1, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x08}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSS_SHAKE_20_256, 32, 20, 1, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x09}, CRYPT_MD_SHAKE128, 32},

    /* XMSS with SHAKE256-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSS_SHAKE_10_512, 64, 10, 1, 10, 16, 131, 132, 9092, {0x0, 0x0, 0x0, 0x0a}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSS_SHAKE_16_512, 64, 16, 1, 16, 16, 131, 132, 9476, {0x0, 0x0, 0x0, 0x0b}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSS_SHAKE_20_512, 64, 20, 1, 20, 16, 131, 132, 9732, {0x0, 0x0, 0x0, 0x0c}, CRYPT_MD_SHAKE256, 64},

    /* XMSS with SHA2-192 (n=24) - paddingLen = 4 (special case for 192-bit) */
    {CRYPT_XMSS_SHA2_10_192, 24, 10, 1, 10, 16, 51, 52, 1492, {0x0, 0x0, 0x0, 0x0d}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSS_SHA2_16_192, 24, 16, 1, 16, 16, 51, 52, 1636, {0x0, 0x0, 0x0, 0x0e}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSS_SHA2_20_192, 24, 20, 1, 20, 16, 51, 52, 1732, {0x0, 0x0, 0x0, 0x0f}, CRYPT_MD_SHA256, 4},

    /* XMSS with SHAKE256-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSS_SHAKE256_10_256, 32, 10, 1, 10, 16, 67, 68, 2500, {0x0, 0x0, 0x0, 0x10}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSS_SHAKE256_16_256, 32, 16, 1, 16, 16, 67, 68, 2692, {0x0, 0x0, 0x0, 0x11}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSS_SHAKE256_20_256, 32, 20, 1, 20, 16, 67, 68, 2820, {0x0, 0x0, 0x0, 0x12}, CRYPT_MD_SHAKE256, 32},

    /* XMSS with SHAKE256-192 (n=24) - paddingLen = 4 */
    {CRYPT_XMSS_SHAKE256_10_192, 24, 10, 1, 10, 16, 51, 52, 1492, {0x0, 0x0, 0x0, 0x13}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSS_SHAKE256_16_192, 24, 16, 1, 16, 16, 51, 52, 1636, {0x0, 0x0, 0x0, 0x14}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSS_SHAKE256_20_192, 24, 20, 1, 20, 16, 51, 52, 1732, {0x0, 0x0, 0x0, 0x15}, CRYPT_MD_SHAKE256, 4},

    /* XMSSMT with SHA2-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSSMT_SHA2_20_2_256, 32, 20, 2, 10, 16, 67, 68, 4963, {0x0, 0x0, 0x0, 0x01}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_20_4_256, 32, 20, 4, 5, 16, 67, 68, 9251, {0x0, 0x0, 0x0, 0x02}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_40_2_256, 32, 40, 2, 20, 16, 67, 68, 5605, {0x0, 0x0, 0x0, 0x03}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_40_4_256, 32, 40, 4, 10, 16, 67, 68, 9893, {0x0, 0x0, 0x0, 0x04}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_40_8_256, 32, 40, 8, 5, 16, 67, 68, 18469, {0x0, 0x0, 0x0, 0x05}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_60_3_256, 32, 60, 3, 20, 16, 67, 68, 8392, {0x0, 0x0, 0x0, 0x06}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_60_6_256, 32, 60, 6, 10, 16, 67, 68, 14824, {0x0, 0x0, 0x0, 0x07}, CRYPT_MD_SHA256, 32},
    {CRYPT_XMSSMT_SHA2_60_12_256, 32, 60, 12, 5, 16, 67, 68, 27688, {0x0, 0x0, 0x0, 0x08}, CRYPT_MD_SHA256, 32},

    /* XMSSMT with SHA2-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSSMT_SHA2_20_2_512, 64, 20, 2, 10, 16, 131, 132, 18115, {0x0, 0x0, 0x0, 0x09}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_20_4_512, 64, 20, 4, 5, 16, 131, 132, 34883, {0x0, 0x0, 0x0, 0x0a}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_40_2_512, 64, 40, 2, 20, 16, 131, 132, 19397, {0x0, 0x0, 0x0, 0x0b}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_40_4_512, 64, 40, 4, 10, 16, 131, 132, 36165, {0x0, 0x0, 0x0, 0x0c}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_40_8_512, 64, 40, 8, 5, 16, 131, 132, 69701, {0x0, 0x0, 0x0, 0x0d}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_60_3_512, 64, 60, 3, 20, 16, 131, 132, 29064, {0x0, 0x0, 0x0, 0x0e}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_60_6_512, 64, 60, 6, 10, 16, 131, 132, 54216, {0x0, 0x0, 0x0, 0x0f}, CRYPT_MD_SHA512, 64},
    {CRYPT_XMSSMT_SHA2_60_12_512, 64, 60, 12, 5, 16, 131, 132, 104520, {0x0, 0x0, 0x0, 0x10}, CRYPT_MD_SHA512, 64},

    /* XMSSMT with SHAKE128 (n=32) - paddingLen = 32 */
    {CRYPT_XMSSMT_SHAKE_20_2_256, 32, 20, 2, 10, 16, 67, 68, 4963, {0x0, 0x0, 0x0, 0x11}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_20_4_256, 32, 20, 4, 5, 16, 67, 68, 9251, {0x0, 0x0, 0x0, 0x12}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_40_2_256, 32, 40, 2, 20, 16, 67, 68, 5605, {0x0, 0x0, 0x0, 0x13}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_40_4_256, 32, 40, 4, 10, 16, 67, 68, 9893, {0x0, 0x0, 0x0, 0x14}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_40_8_256, 32, 40, 8, 5, 16, 67, 68, 18469, {0x0, 0x0, 0x0, 0x15}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_60_3_256, 32, 60, 3, 20, 16, 67, 68, 8392, {0x0, 0x0, 0x0, 0x16}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_60_6_256, 32, 60, 6, 10, 16, 67, 68, 14824, {0x0, 0x0, 0x0, 0x17}, CRYPT_MD_SHAKE128, 32},
    {CRYPT_XMSSMT_SHAKE_60_12_256, 32, 60, 12, 5, 16, 67, 68, 27688, {0x0, 0x0, 0x0, 0x18}, CRYPT_MD_SHAKE128, 32},

    /* XMSSMT with SHAKE256-512 (n=64) - paddingLen = 64 */
    {CRYPT_XMSSMT_SHAKE_20_2_512, 64, 20, 2, 10, 16, 131, 132, 18115, {0x0, 0x0, 0x0, 0x19}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_20_4_512, 64, 20, 4, 5, 16, 131, 132, 34883, {0x0, 0x0, 0x0, 0x1a}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_40_2_512, 64, 40, 2, 20, 16, 131, 132, 19397, {0x0, 0x0, 0x0, 0x1b}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_40_4_512, 64, 40, 4, 10, 16, 131, 132, 36165, {0x0, 0x0, 0x0, 0x1c}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_40_8_512, 64, 40, 8, 5, 16, 131, 132, 69701, {0x0, 0x0, 0x0, 0x1d}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_60_3_512, 64, 60, 3, 20, 16, 131, 132, 29064, {0x0, 0x0, 0x0, 0x1e}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_60_6_512, 64, 60, 6, 10, 16, 131, 132, 54216, {0x0, 0x0, 0x0, 0x1f}, CRYPT_MD_SHAKE256, 64},
    {CRYPT_XMSSMT_SHAKE_60_12_512, 64, 60, 12, 5, 16, 131, 132, 104520, {0x0, 0x0, 0x0, 0x20}, CRYPT_MD_SHAKE256, 64},

    /* XMSSMT with SHA2-192 (n=24) - paddingLen = 4 */
    {CRYPT_XMSSMT_SHA2_20_2_192, 24, 20, 2, 10, 16, 51, 52, 2955, {0x0, 0x0, 0x0, 0x21}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_20_4_192, 24, 20, 4, 5, 16, 51, 52, 5403, {0x0, 0x0, 0x0, 0x22}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_40_2_192, 24, 40, 2, 20, 16, 51, 52, 3437, {0x0, 0x0, 0x0, 0x23}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_40_4_192, 24, 40, 4, 10, 16, 51, 52, 5885, {0x0, 0x0, 0x0, 0x24}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_40_8_192, 24, 40, 8, 5, 16, 51, 52, 10781, {0x0, 0x0, 0x0, 0x25}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_60_3_192, 24, 60, 3, 20, 16, 51, 52, 5144, {0x0, 0x0, 0x0, 0x26}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_60_6_192, 24, 60, 6, 10, 16, 51, 52, 8816, {0x0, 0x0, 0x0, 0x27}, CRYPT_MD_SHA256, 4},
    {CRYPT_XMSSMT_SHA2_60_12_192, 24, 60, 12, 5, 16, 51, 52, 16160, {0x0, 0x0, 0x0, 0x28}, CRYPT_MD_SHA256, 4},

    /* XMSSMT with SHAKE256-256 (n=32) - paddingLen = 32 */
    {CRYPT_XMSSMT_SHAKE256_20_2_256, 32, 20, 2, 10, 16, 67, 68, 4963, {0x0, 0x0, 0x0, 0x29}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_20_4_256, 32, 20, 4, 5, 16, 67, 68, 9251, {0x0, 0x0, 0x0, 0x2a}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_40_2_256, 32, 40, 2, 20, 16, 67, 68, 5605, {0x0, 0x0, 0x0, 0x2b}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_40_4_256, 32, 40, 4, 10, 16, 67, 68, 9893, {0x0, 0x0, 0x0, 0x2c}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_40_8_256, 32, 40, 8, 5, 16, 67, 68, 18469, {0x0, 0x0, 0x0, 0x2d}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_60_3_256, 32, 60, 3, 20, 16, 67, 68, 8392, {0x0, 0x0, 0x0, 0x2e}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_60_6_256, 32, 60, 6, 10, 16, 67, 68, 14824, {0x0, 0x0, 0x0, 0x2f}, CRYPT_MD_SHAKE256, 32},
    {CRYPT_XMSSMT_SHAKE256_60_12_256, 32, 60, 12, 5, 16, 67, 68, 27688, {0x0, 0x0, 0x0, 0x30}, CRYPT_MD_SHAKE256, 32},

    /* XMSSMT with SHAKE256-192 (n=24) - paddingLen = 4 */
    {CRYPT_XMSSMT_SHAKE256_20_2_192, 24, 20, 2, 10, 16, 51, 52, 2955, {0x0, 0x0, 0x0, 0x31}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_20_4_192, 24, 20, 4, 5, 16, 51, 52, 5403, {0x0, 0x0, 0x0, 0x32}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_40_2_192, 24, 40, 2, 20, 16, 51, 52, 3437, {0x0, 0x0, 0x0, 0x33}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_40_4_192, 24, 40, 4, 10, 16, 51, 52, 5885, {0x0, 0x0, 0x0, 0x34}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_40_8_192, 24, 40, 8, 5, 16, 51, 52, 10781, {0x0, 0x0, 0x0, 0x35}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_60_3_192, 24, 60, 3, 20, 16, 51, 52, 5144, {0x0, 0x0, 0x0, 0x36}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_60_6_192, 24, 60, 6, 10, 16, 51, 52, 8816, {0x0, 0x0, 0x0, 0x37}, CRYPT_MD_SHAKE256, 4},
    {CRYPT_XMSSMT_SHAKE256_60_12_192, 24, 60, 12, 5, 16, 51, 52, 16160, {0x0, 0x0, 0x0, 0x38}, CRYPT_MD_SHAKE256, 4},
};

const XmssParams *FindXmssPara(CRYPT_PKEY_ParaId algId)
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
#endif // HITLS_CRYPTO_XMSS
