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

#include "securec.h"
#include "crypt_utils.h"
#include "xmss_address.h"
#include "xmss_local.h"
#define XMSS_ADRS_LEN                   32
#define XMSS_TYPE_SPECIFIC_FIELD_OFFSET 16
#define XMSS_TYPE_SPECIFIC_FIELD_LEN    16

static void XmssAdrs_SetLayerAddr(void *adrs, uint32_t layer)
{
    PUT_UINT32_BE(layer, ((XmssAdrs *)adrs)->fields.layerAddr, 0);
}

static void XmssAdrs_SetTreeAddr(void *adrs, uint64_t tree)
{
    PUT_UINT64_BE(tree, ((XmssAdrs *)adrs)->fields.treeAddr, 0);
}

// RFC 8391 specifies that when the adrs type changes, the type-specific fields should be reset to zero.
static void XmssAdrs_SetType(void *adrs, uint32_t type)
{
    PUT_UINT32_BE(type, ((XmssAdrs *)adrs)->fields.type, 0);
    (void)memset_s(((XmssAdrs *)adrs)->bytes + XMSS_TYPE_SPECIFIC_FIELD_OFFSET, XMSS_TYPE_SPECIFIC_FIELD_LEN, 0,
                   XMSS_TYPE_SPECIFIC_FIELD_LEN);
}

static void XmssAdrs_SetKeyPairAddr(void *adrs, uint32_t keyPair)
{
    PUT_UINT32_BE(keyPair, ((XmssAdrs *)adrs)->fields.keyPairAddr, 0);
}

static void XmssAdrs_SetChainAddr(void *adrs, uint32_t chain)
{
    PUT_UINT32_BE(chain, ((XmssAdrs *)adrs)->fields.chainAddr, 0);
}

static void XmssAdrs_SetHashAddr(void *adrs, uint32_t hash)
{
    PUT_UINT32_BE(hash, ((XmssAdrs *)adrs)->fields.hashAddr, 0);
}

static void XmssAdrs_SetTreeHeight(void *adrs, uint32_t height)
{
    /* For tree hash address (type=2), tree height goes to bytes 20-23 (chainAddr field) */
    PUT_UINT32_BE(height, ((XmssAdrs *)adrs)->fields.chainAddr, 0);
}

static void XmssAdrs_SetTreeIndex(void *adrs, uint32_t index)
{
    /* For tree hash address (type=2), tree index goes to bytes 24-27 (hashAddr field) */
    PUT_UINT32_BE(index, ((XmssAdrs *)adrs)->fields.hashAddr, 0);
}

static uint32_t XmssAdrs_GetTreeHeight(const void *adrs)
{
    /* For tree hash address (type=2), tree height is in bytes 20-23 (chainAddr field) */
    return GET_UINT32_BE(((const XmssAdrs *)adrs)->fields.chainAddr, 0);
}

static uint32_t XmssAdrs_GetTreeIndex(const void *adrs)
{
    /* For tree hash address (type=2), tree index is in bytes 24-27 (hashAddr field) */
    return GET_UINT32_BE(((const XmssAdrs *)adrs)->fields.hashAddr, 0);
}

static void XmssAdrs_CopyKeyPairAddr(void *dest, const void *src)
{
    (void)memcpy_s(((XmssAdrs *)dest)->fields.keyPairAddr, sizeof(((XmssAdrs *)dest)->fields.keyPairAddr),
                   ((const XmssAdrs *)src)->fields.keyPairAddr, sizeof(((const XmssAdrs *)src)->fields.keyPairAddr));
}

static uint32_t XmssAdrs_GetAdrsLen(void)
{
    return XMSS_ADRS_LEN;
}

void XmssAdrs_SetKeyAndMask(void *adrs, uint32_t index)
{
    PUT_UINT32_BE(index, ((XmssAdrs *)adrs)->fields.keyAndMask, 0);
}

int32_t XmssAdrsOps_Init(CryptAdrsOps *ops)
{
    if (ops == NULL) {
        return CRYPT_NULL_INPUT;
    }
    ops->setLayerAddr = XmssAdrs_SetLayerAddr;
    ops->setTreeAddr = XmssAdrs_SetTreeAddr;
    ops->setType = XmssAdrs_SetType;
    ops->setKeyPairAddr = XmssAdrs_SetKeyPairAddr;
    ops->setChainAddr = XmssAdrs_SetChainAddr;
    ops->setTreeHeight = XmssAdrs_SetTreeHeight;
    ops->setHashAddr = XmssAdrs_SetHashAddr;
    ops->setTreeIndex = XmssAdrs_SetTreeIndex;
    ops->getTreeHeight = XmssAdrs_GetTreeHeight;
    ops->getTreeIndex = XmssAdrs_GetTreeIndex;
    ops->copyKeyPairAddr = XmssAdrs_CopyKeyPairAddr;
    ops->getAdrsLen = XmssAdrs_GetAdrsLen;
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_XMSS
