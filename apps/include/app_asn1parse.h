/* Copyright (c) 2025，Shandong University — School of Cyber Science and Technology
* Contributor: Mingzhang Sun
 * Instructor:  Weijia Wang
*/
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

#ifndef APP_ASN1PARSE_H
#define APP_ASN1PARSE_H
#include <stdint.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public entry used by g_cmdFunc[] in app_function.c
 * Signature matches other HITLS command entry functions.
 */
int HITLS_Asn1Main(int argc, char **argv);

/* helper for unit tests: parse a buffer */
int AppAsn1ParseBuffer(const uint8_t *buf, size_t bufLen, int showIndent, int showValue);

/* helper: extract node TLV bytes at offset (allocated buffer, caller must free with BSL_SAL_FREE()) */
int AppAsn1GetNodeBytes(const uint8_t *buf, size_t bufLen, size_t offset, uint8_t **outBuf, size_t *outLen);

/* compute header length for a TLV starting at buf[0] */
int AppAsn1ComputeHeaderLenOfTlv(const uint8_t *tlv, size_t tlvLen, size_t *hdrLen);

#ifdef __cplusplus
}
#endif

#endif /* APP_ASN1PARSE_H */