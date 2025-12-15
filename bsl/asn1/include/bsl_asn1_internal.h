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

#ifndef BSL_ASN1_INTERNAL_H
#define BSL_ASN1_INTERNAL_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bsl_list.h"
#include "bsl_uio.h"
#include "bsl_asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_ASN1_MAX_TEMPLATE_DEPTH 6

#define BSL_ASN1_UTCTIME_LEN 13         // YYMMDDHHMMSSZ
#define BSL_ASN1_GENERALIZEDTIME_LEN 15 // YYYYMMDDHHMMSSZ

typedef enum {
    BSL_ASN1_TYPE_GET_ANY_TAG = 0,
    BSL_ASN1_TYPE_CHECK_CHOICE_TAG = 1
} BSL_ASN1_CALLBACK_TYPE;

/**
 * @ingroup bsl_asn1
 * @brief Obtain the length of V or LV in an ASN1 TLV structure.
 *
 * @param encode [IN/OUT] Data to be decoded. Update the offset after decoding.
 * @param encLen [IN/OUT] The length of the data to be decoded.
 * @param completeLen [IN] True: Get the length of L+V; False: Get the length of V.
 * @param len [OUT] Output.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeLen(uint8_t **encode, uint32_t *encLen, bool completeLen, uint32_t *len);

/**
 * @ingroup bsl_asn1
 * @brief Decoding of primitive type data.
 *
 * @param asn [IN] The data to be decoded.
 * @param decodeData [OUT] Decoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodePrimitiveItem(BSL_ASN1_Buffer *asn, void *decodeData);

/**
 * @ingroup bsl_asn1
 * @brief Decode one asn1 item.
 *
 * @param encode [IN/OUT] Data to be decoded. Update the offset after decoding.
 * @param encLen [IN/OUT] The length of the data to be decoded.
 * @param asnItem [OUT] Output.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_DecodeItem(uint8_t **encode, uint32_t *encLen, BSL_ASN1_Buffer *asnItem);

/**
 * @ingroup bsl_asn1
 * @brief Obtain the length of an ASN1 TLV structure.
 *
 * @param data [IN] Data to be decoded. Update the offset after decoding.
 * @param dataLen [OUT] Decoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_GetCompleteLen(uint8_t *data, uint32_t *dataLen);

/**
 * @ingroup bsl_asn1
 * @brief Encode the smaller positive integer.
 *
 * @param tag [IN] BSL_ASN1_TAG_INTEGER or BSL_ASN1_TAG_ENUMERATED
 * @param limb [IN] Positive integer.
 * @param asn [OUT] Encoding result.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_EncodeLimb(uint8_t tag, uint64_t limb, BSL_ASN1_Buffer *asn);

/**
 * @ingroup bsl_asn1
 * @brief Calculate the total encoding length for a ASN.1 type through the content length.
 *
 * @param contentLen [IN] The length of the content to be encoded.
 * @param encodeLen [OUT] The total number of bytes needed for DER encoding.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_GetEncodeLen(uint32_t contentLen, uint32_t *encodeLen);

/**
 * @ingroup bsl_asn1
 * @brief Convert ASN.1 string content encoded in various ASN.1 string forms to UTF-8 encoded octets.
 *
 * @param in     [IN]  Input ASN.1 buffer.
 * @param out    [OUT] Output ASN.1 buffer receiving the UTF-8 encoded octets.
 * @retval  BSL_SUCCESS, success.
 *          Other error codes see the bsl_errno.h.
 */
int32_t BSL_ASN1_ToUtf8String(const BSL_ASN1_Buffer *in, BSL_ASN1_Buffer *out);


#ifdef __cplusplus
}
#endif

#endif // BSL_ASN1_INTERNAL_H
