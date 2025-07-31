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

#ifndef HITLS_PKI_UTILS_H
#define HITLS_PKI_UTILS_H

#include "bsl_uio.h"
#include "hitls_pki_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_Ext HITLS_X509_Ext;

typedef struct _HITLS_X509_Attrs HITLS_X509_Attrs;

/**
 * @ingroup hitls_pki_utils
 * @brief Generic function to print data.
 * @attention
 * Thread safe     : Not thread-safe function.
 * Blocking risk   : No blocking.
 * Time consuming  : Not time-consuming.
 *
 * @param cmd     [IN] HITLS_PKI_PrintCmd
 * @param val     [IN] The data to be printed.
 * @param valLen  [In] The length of the data to be printed.
 * @param uio     [In] Pointer to the BSL_UIO structure.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         error codes see the hitls_pki_errno.h
 */
int32_t HITLS_PKI_PrintCtrl(int32_t cmd, void *val, uint32_t valLen, BSL_UIO *uio);

/**
 * @ingroup pki
 * @brief Generic function to set/get an extension.
 *
 * @param ext    [IN] extensions
 * @param cmd    [IN] HITLS_X509_EXT_SET_XXX
 *        cmd                               data type
 *        HITLS_X509_EXT_GET|SET_KUSAGE         HITLS_X509_ExtKeyUsage
 *        HITLS_X509_EXT_GET|SET_BCONS          HITLS_X509_ExtBCons
 *        HITLS_X509_EXT_GET|SET_AKI            HITLS_X509_ExtAki
 *        HITLS_X509_EXT_GET|SET_SKI            HITLS_X509_ExtSki
 *        HITLS_X509_EXT_GET|SET_SAN            HITLS_X509_ExtSan
 *        HITLS_X509_EXT_GET|SET_EXKUSAGE       HITLS_X509_ExtExKeyUsage
 *        HITLS_X509_EXT_CHECK_SKI              bool
 * @param val    [IN/OUT] input and output value
 * @param valLen [In] value length
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, uint32_t valLen);

/**
 * @ingroup pki
 * @brief Allocate a extension.
 *
 * @retval HITLS_X509_Ext *
 */
HITLS_X509_Ext *HITLS_X509_ExtNew(int32_t type);

/**
 * @ingroup pki
 * @brief Unallocate a extension.
 *
 * @param ext [IN] The extension.
 */
void HITLS_X509_ExtFree(HITLS_X509_Ext *ext);

/**
 * @ingroup pki
 * @brief clear the HITLS_X509_ExtAki structure.
 * @par Description: This interface needs to be called to clean up memory when obtaining AKI extensions from
 *  certificates, CRLs, or CSRs using the macro HITLS_X509_EXT_GET_AKI.
 *
 * @param aki [IN] The HITLS_X509_ExtAki aki
 */
void HITLS_X509_ClearAuthorityKeyId(HITLS_X509_ExtAki *aki);

/**
 * @ingroup pki
 * @brief Free a general name.
 *
 * @param data [IN] The general name.
 */
void HITLS_X509_FreeGeneralName(HITLS_X509_GeneralName *data);

/**
 * @ingroup pki
 * @brief New a list of distinguish name, the item is HITLS_X509_NameNode.
 * @attention You need to HITLS_X509_DnListFree to free list, after the end of use
 *
 * @retval #BslList *, success.
 *         error return NULL.
 */
BslList *HITLS_X509_DnListNew(void);

/**
 * @ingroup pki
 * @brief New a list of distinguish name, the list .
 *
 * @param list [IN] The name list
 * @retval  void
 */
void HITLS_X509_DnListFree(BslList *dnList);

/**
 * @ingroup pki
 * @brief Add a distinguish name array to list.
 *
 * @param list [IN] The name list
 * @param dnNames   [IN] dnName array
 * @param size   [IN] The count of dnName array
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_AddDnName(BslList *list, HITLS_X509_DN *dnNames, uint32_t size);

/**
 * @ingroup pki
 * @brief Generic function to process attribute function
 *
 * @param attributes [IN] The attribute list
 * @param cmd [IN] HITLS_X509_AttrCmd
 * @param val                                               data type
 *        HITLS_X509_ATTR_XX_REQUESTED_EXTENSIONS         HITLS_X509_Ext
 * @param valLen  The length of value.
 * @retval #HITLS_PKI_SUCCESS, success.
 *         Error codes can be found in hitls_pki_errno.h
 */
int32_t HITLS_X509_AttrCtrl(HITLS_X509_Attrs *attributes, HITLS_X509_AttrCmd cmd, void *val, uint32_t valLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_UTILS_H
