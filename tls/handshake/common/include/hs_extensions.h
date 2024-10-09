/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HS_EXTERNSIONS_H
#define HS_EXTERNSIONS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HS_EX_HEADER_LEN 4u

/* Handshake Extension message type */
#define HS_EX_TYPE_SERVER_NAME 0u
#define HS_EX_TYPE_TRUSTED_CA_KEYS 3u
#define HS_EX_TYPE_STATUS_REQUEST 5u
#define HS_EX_TYPE_SUPPORTED_GROUPS 10u
#define HS_EX_TYPE_POINT_FORMATS 11u
#define HS_EX_TYPE_SIGNATURE_ALGORITHMS 13u
#define HS_EX_TYPE_APP_LAYER_PROTOCOLS 16u
#define HS_EX_TYPE_STATUS_REQUEST_V2 17u
#define HS_EX_TYPE_ENCRYPT_THEN_MAC 22u
#define HS_EX_TYPE_EXTENDED_MASTER_SECRET 23u
#define HS_EX_TYPE_SESSION_TICKET 35u
#define HS_EX_TYPE_PRE_SHARED_KEY 41u
#define HS_EX_TYPE_EARLY_DATA 42u
#define HS_EX_TYPE_SUPPORTED_VERSIONS 43u
#define HS_EX_TYPE_COOKIE 44u
#define HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES 45u
#define HS_EX_TYPE_TRUSTED_CA_LIST 47u
#define HS_EX_TYPE_OID_FILTERS 48u
#define HS_EX_TYPE_POST_HS_AUTH 49u
#define HS_EX_TYPE_SIGNATURE_ALGORITHMS_CERT 50u
#define HS_EX_TYPE_KEY_SHARE 51u
#define HS_EX_TYPE_RENEGOTIATION_INFO 0xFF01u
#define HS_EX_TYPE_END 0xFFFFu

#ifdef __cplusplus
}
#endif /* end __cplusplus */

#endif /* end HS_EXTERNSIONS_H */
