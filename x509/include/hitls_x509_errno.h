/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_X509_ERRNO_H
#define HITLS_X509_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HITLS_X509_SUCCESS,
    HITLS_X509_ERR_VFY_CERT_NOT_BEFORE = 0x04000001,
    HITLS_X509_ERR_VFY_CERT_NOT_AFTER,
    HITLS_X509_ERR_VFY_KU_NO_CERTSIGN,
    HITLS_X509_ERR_INVALID_PARAM,

    HITLS_X509_ERR_INVALID_EXT,
    HITLS_X509_ERR_NOT_SUPPORT_FORMAT,
    HITLS_X509_ERR_ALG_OID,
    HITLS_X509_ERR_PARSE_PARAM,
    HITLS_X509_ERR_NAME_OID,
    HITLS_X509_ERR_PARSE_STR,
    HITLS_X509_ERR_INVALID_KEYUSAGE,
    HITLS_X509_ERR_CHECK_TAG,
    HITLS_X509_ERR_GET_ANY_TAG,
    HITLS_X509_ERR_CHECK_SECBITS,
    HITLS_X509_ERR_PROCESS_CRITICALEXT,
    HITLS_X509_ERR_NO_EXTCRLSIGN,
    HITLS_X509_ERR_CERT_REVOKED,
    HITLS_X509_ERR_GET_HASHID,
    HITLS_X509_ERR_TIME_EXPIRED,
    HITLS_X509_ERR_TIME_FUTURE,
} HITLS_X509_ERRNO;

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_ERRNO_H