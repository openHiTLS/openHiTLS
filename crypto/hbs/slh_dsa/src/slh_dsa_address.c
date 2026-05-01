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

/*
 * slh_dsa_address.c - SLH-DSA address operations
 *
 * UC (uncompressed) and C (compressed) address function tables.
 * Moved from slh_dsa.c per HBS refactoring design §2.3.3.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stdint.h>
#include <string.h>
#include "crypt_utils.h"
#include "slh_dsa_local.h"

/* -------------------------------------------------------------------------
 * Uncompressed (UC) address operations — 32-byte address format
 * ------------------------------------------------------------------------- */

static void UCAdrsSetLayerAddr(void *adrs, uint32_t layer)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(layer, sa->uc.layerAddr, 0);
}

static void UCAdrsSetTreeAddr(void *adrs, uint64_t tree)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT64_BE(tree, sa->uc.treeAddr, 4);
}

static void UCAdrsSetType(void *adrs, uint32_t type)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(type, sa->uc.type, 0);
    memset(sa->uc.padding, 0, sizeof(sa->uc.padding));
}

static void UCAdrsSetKeyPairAddr(void *adrs, uint32_t keyPair)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(keyPair, sa->uc.padding, 0);
}

static void UCAdrsSetChainAddr(void *adrs, uint32_t chain)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(chain, sa->uc.padding, 4);
}

static void UCAdrsSetTreeHeight(void *adrs, uint32_t height)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(height, sa->uc.padding, 4);
}

static void UCAdrsSetHashAddr(void *adrs, uint32_t hash)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(hash, sa->uc.padding, 8);
}

static void UCAdrsSetTreeIndex(void *adrs, uint32_t index)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(index, sa->uc.padding, 8);
}

static uint32_t UCAdrsGetTreeHeight(const void *adrs)
{
    const SlhDsaAdrs *sa = (const SlhDsaAdrs *)adrs;
    return GET_UINT32_BE(sa->uc.padding, 0);
}

static uint32_t UCAdrsGetTreeIndex(const void *adrs)
{
    const SlhDsaAdrs *sa = (const SlhDsaAdrs *)adrs;
    return GET_UINT32_BE(sa->uc.padding, 8);
}

static void UCAdrsCopyKeyPairAddr(void *adrs, const void *adrs2)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    const SlhDsaAdrs *sa2 = (const SlhDsaAdrs *)adrs2;
    memcpy(sa->uc.padding, sa2->uc.padding, 4);
}

static uint32_t UCAdrsGetAdrsLen(void)
{
    return SLH_DSA_ADRS_LEN;
}

/* -------------------------------------------------------------------------
 * Compressed (C) address operations — 22-byte address format
 * ------------------------------------------------------------------------- */

static void CAdrsSetLayerAddr(void *adrs, uint32_t layer)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    sa->c.layerAddr = (uint8_t)layer;
}

static void CAdrsSetTreeAddr(void *adrs, uint64_t tree)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT64_BE(tree, sa->c.treeAddr, 0);
}

static void CAdrsSetType(void *adrs, uint32_t type)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    sa->c.type = (uint8_t)type;
    memset(sa->c.padding, 0, sizeof(sa->c.padding));
}

static void CAdrsSetKeyPairAddr(void *adrs, uint32_t keyPair)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(keyPair, sa->c.padding, 0);
}

static void CAdrsSetChainAddr(void *adrs, uint32_t chain)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(chain, sa->c.padding, 4);
}

static void CAdrsSetTreeHeight(void *adrs, uint32_t height)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(height, sa->c.padding, 4);
}

static void CAdrsSetHashAddr(void *adrs, uint32_t hash)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(hash, sa->c.padding, 8);
}

static void CAdrsSetTreeIndex(void *adrs, uint32_t index)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    PUT_UINT32_BE(index, sa->c.padding, 8);
}

static uint32_t CAdrsGetTreeHeight(const void *adrs)
{
    const SlhDsaAdrs *sa = (const SlhDsaAdrs *)adrs;
    return GET_UINT32_BE(sa->c.padding, 0);
}

static uint32_t CAdrsGetTreeIndex(const void *adrs)
{
    const SlhDsaAdrs *sa = (const SlhDsaAdrs *)adrs;
    return GET_UINT32_BE(sa->c.padding, 8);
}

static void CAdrsCopyKeyPairAddr(void *adrs, const void *adrs2)
{
    SlhDsaAdrs *sa = (SlhDsaAdrs *)adrs;
    const SlhDsaAdrs *sa2 = (const SlhDsaAdrs *)adrs2;
    memcpy(sa->c.padding, sa2->c.padding, 4);
}

static uint32_t CAdrsGetAdrsLen(void)
{
    return SLH_DSA_ADRS_COMPRESSED_LEN;
}

/* -------------------------------------------------------------------------
 * Global address operation tables (index 0 = UC, index 1 = C)
 * Used by SlhDsaSetAlgId in slh_dsa_core.c via SlhDsaGetAdrsOps()
 * ------------------------------------------------------------------------- */

static XmssFamilyAdrsOps g_adrsOps[2] = {{
                                             .setLayerAddr = UCAdrsSetLayerAddr,
                                             .setTreeAddr = UCAdrsSetTreeAddr,
                                             .setType = UCAdrsSetType,
                                             .setKeyPairAddr = UCAdrsSetKeyPairAddr,
                                             .setChainAddr = UCAdrsSetChainAddr,
                                             .setTreeHeight = UCAdrsSetTreeHeight,
                                             .setHashAddr = UCAdrsSetHashAddr,
                                             .setTreeIndex = UCAdrsSetTreeIndex,
                                             .getTreeHeight = UCAdrsGetTreeHeight,
                                             .getTreeIndex = UCAdrsGetTreeIndex,
                                             .copyKeyPairAddr = UCAdrsCopyKeyPairAddr,
                                             .getAdrsLen = UCAdrsGetAdrsLen,
                                         },
                                         {
                                             .setLayerAddr = CAdrsSetLayerAddr,
                                             .setTreeAddr = CAdrsSetTreeAddr,
                                             .setType = CAdrsSetType,
                                             .setKeyPairAddr = CAdrsSetKeyPairAddr,
                                             .setChainAddr = CAdrsSetChainAddr,
                                             .setTreeHeight = CAdrsSetTreeHeight,
                                             .setHashAddr = CAdrsSetHashAddr,
                                             .setTreeIndex = CAdrsSetTreeIndex,
                                             .getTreeHeight = CAdrsGetTreeHeight,
                                             .getTreeIndex = CAdrsGetTreeIndex,
                                             .copyKeyPairAddr = CAdrsCopyKeyPairAddr,
                                             .getAdrsLen = CAdrsGetAdrsLen,
                                         }};

const XmssFamilyAdrsOps *SlhDsaGetAdrsOps(bool isCompressed)
{
    return isCompressed ? &g_adrsOps[1] : &g_adrsOps[0];
}

#endif /* HITLS_CRYPTO_SLH_DSA */
