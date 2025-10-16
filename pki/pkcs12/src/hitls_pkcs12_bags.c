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
#ifdef HITLS_PKI_PKCS12
#include "bsl_sal.h"
#include "securec.h"
#include "hitls_pki_errno.h"
#include "hitls_x509_local.h"
#include "hitls_cms_local.h"
#include "bsl_obj_internal.h"
#include "bsl_err_internal.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pkcs12_local.h"

int32_t BagGetAttr(HITLS_PKCS12_Bag *bag, uint32_t valType, BSL_Buffer *attrValue)
{
    if (bag == NULL || attrValue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (valType != BSL_CID_LOCALKEYID && valType != BSL_CID_FRIENDLYNAME) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES);
        return HITLS_PKCS12_ERR_INVALID_SAFEBAG_ATTRIBUTES;
    }
    if (bag->attributes == NULL || bag->attributes->list == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES);
        return HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES;
    }
    BSL_ASN1_List *list = bag->attributes->list;
    HITLS_PKCS12_SafeBagAttr *node = BSL_LIST_GET_FIRST(list);
    while (node != NULL) {
        if (node->attrId == valType) {
            if (attrValue->data == NULL || attrValue->dataLen < node->attrValue.dataLen) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_BUFFLEN_NOT_ENOUGH);
                return HITLS_PKCS12_ERR_BUFFLEN_NOT_ENOUGH;
            }
            (void)memcpy_s(attrValue->data, attrValue->dataLen, node->attrValue.data, node->attrValue.dataLen);
            attrValue->dataLen = node->attrValue.dataLen;
            return HITLS_PKI_SUCCESS;
        }
        node = BSL_LIST_GET_NEXT(list);
    }
    BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES);
    return HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES;
}

static int32_t GetKeyBagValue(HITLS_PKCS12_Bag *bag, void **value)
{
    if (value == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (*value != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (bag->value.key == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_BAG_NO_KEY);
        return HITLS_PKCS12_ERR_BAG_NO_KEY;
    }
    int32_t ret = CRYPT_EAL_PkeyUpRef(bag->value.key);
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *((CRYPT_EAL_PkeyCtx **)value) = bag->value.key;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetCertBagValue(HITLS_PKCS12_Bag *bag, void **value)
{
    if (value == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    if (*value != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    if (bag->value.cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_BAG_NO_CERT);
        return HITLS_PKCS12_ERR_BAG_NO_CERT;
    }
    int32_t ref;
    if (bag->type != BSL_CID_X509CERTIFICATE) { // now only support x509 certificate.
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
        return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
    int32_t ret = HITLS_X509_CertCtrl(bag->value.cert, HITLS_X509_REF_UP, &ref, sizeof(int32_t));
    if (ret != HITLS_PKI_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *((HITLS_X509_Cert **)value) = bag->value.cert;
    return HITLS_PKI_SUCCESS;
}

static int32_t GetSecretBagValue(HITLS_PKCS12_Bag *bag, void *value)
{
    if (value == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    BSL_Buffer *tmp = (BSL_Buffer *)value;
    if (bag->value.secret.data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_BAG_NO_SECRET);
        return HITLS_PKCS12_ERR_BAG_NO_SECRET;
    }
    if (tmp->data == NULL || tmp->dataLen < bag->value.secret.dataLen) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_BUFFLEN_NOT_ENOUGH);
        return HITLS_PKCS12_ERR_BUFFLEN_NOT_ENOUGH;
    }
    (void)memcpy_s(tmp->data, tmp->dataLen, bag->value.secret.data, bag->value.secret.dataLen);
    tmp->dataLen = bag->value.secret.dataLen;
    return HITLS_PKI_SUCCESS;
}

int32_t BagGetValue(HITLS_PKCS12_Bag *bag, void *val)
{
    if (bag == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (bag->id) {
        case BSL_CID_KEYBAG:
        case BSL_CID_PKCS8SHROUDEDKEYBAG:
            return GetKeyBagValue(bag, val);
        case BSL_CID_CERTBAG:
            return GetCertBagValue(bag, val);
        case BSL_CID_SECRETBAG:
            return GetSecretBagValue(bag, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
}

int32_t HITLS_PKCS12_BagRefUp(HITLS_PKCS12_Bag *bag)
{
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    int val = 0;
    return BSL_SAL_AtomicUpReferences(&(bag->references), &val);
}

int32_t HITLS_PKCS12_BagCtrl(HITLS_PKCS12_Bag *bag, int32_t cmd, void *val, uint32_t valType)
{
    if (bag == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
        return HITLS_PKCS12_ERR_NULL_POINTER;
    }
    switch (cmd) {
#ifdef HITLS_PKI_PKCS12_GEN
        case HITLS_PKCS12_BAG_ADD_ATTR:
            return HITLS_PKCS12_BagAddAttr(bag, valType, val);
#endif
        case HITLS_PKCS12_BAG_GET_ATTR:
            return BagGetAttr(bag, valType, val);
        case HITLS_PKCS12_BAG_GET_ID:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
                return HITLS_PKCS12_ERR_NULL_POINTER;
            }
            if (valType != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
                return HITLS_PKCS12_ERR_INVALID_PARAM;
            }
            *((uint32_t *)val) = bag->id;
            return HITLS_PKI_SUCCESS;
        case HITLS_PKCS12_BAG_GET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_NULL_POINTER);
                return HITLS_PKCS12_ERR_NULL_POINTER;
            }
            if (valType != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
                return HITLS_PKCS12_ERR_INVALID_PARAM;
            }
            *((uint32_t *)val) = bag->type;
            return HITLS_PKI_SUCCESS;
        case HITLS_PKCS12_BAG_GET_VALUE:
            return BagGetValue(bag, val);
        default:
            BSL_ERR_PUSH_ERROR(HITLS_PKCS12_ERR_INVALID_PARAM);
            return HITLS_PKCS12_ERR_INVALID_PARAM;
    }
}

#endif // HITLS_PKI_PKCS12
