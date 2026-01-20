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
/* BEGIN_HEADER */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_pem_internal.h"

/* END_HEADER */

/* BEGIN_CASE */
void SDV_BSL_PEM_ISPEM_FUNC_TC001(char *data, int expflag)
{
    char *encode = data;
    uint32_t encodeLen = strlen(data);
    bool isPem = BSL_PEM_IsPemFormat(encode, encodeLen);
    ASSERT_TRUE(isPem == (bool)expflag);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_ISPEM_FUNC_TC002(void)
{
    char *aa = "aaaaaaaa";
    ASSERT_TRUE(BSL_PEM_IsPemFormat(NULL, 0) == false);
    ASSERT_TRUE(BSL_PEM_IsPemFormat(aa, strlen(aa)) == false);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC001(char *encode, char *head, char *tail, int expRes)
{
    BSL_PEM_Symbol sym = {head, tail};
    char *pemdata = encode;
    uint32_t len = strlen(encode);
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    TestMemInit();
    ASSERT_EQ(BSL_PEM_DecodePemToAsn1(&pemdata, &len, &sym, &asn1Encode, &asn1Len), expRes);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC002(void)
{
    BSL_PEM_Symbol sym = {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR};
    char *pemdata = "-----BEGIN EC PRIVATE KEY-----\n"
                    "MHcCAQEEIAadtjyegBKXLH9xvNDvH24j7cn3PsaNSXSMIVmvJZM7oAoGCCqGSM49\n"
                    "AwEHoUQDQgAEPFKNDGyE7HES1hPd8mXydX4QunGvk37ISPOhXJStzxTt8sWdcEtV\n"
                    "gaXhArNx9Dz8pKIhoGcviy8xML3wPICv9Q==\n"
                    "-----END EC PRIVATE KEY-----\n"
                    "-----BEGIN EC PRIVATE KEY-----\n"
                    "MHcCAQEEIAadtjyegBKXLH9xvNDvH24j7cn3PsaNSXSMIVmvJZM7oAoGCCqGSM49\n"
                    "AwEHoUQDQgAEPFKNDGyE7HES1hPd8mXydX4QunGvk37ISPOhXJStzxTt8sWdcEtV\n"
                    "gaXhArNx9Dz8pKIhoGcviy8xML3wPICv9Q==\n"
                    "-----END EC PRIVATE KEY-----\n";
    int32_t len = strlen(pemdata);
    char *next = pemdata;
    uint32_t nextLen = len;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    TestMemInit();
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_SUCCESS);
    BSL_SAL_Free(asn1Encode);
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_PARSE_FUNC_TC003(void)
{
    BSL_PEM_Symbol sym = {BSL_PEM_EC_PRI_KEY_BEGIN_STR, BSL_PEM_EC_PRI_KEY_END_STR};
    char *pemdata = "-----BEGIN EC PRIVATE KEY-----END EC PRIVATE KEY------------------END-----\n";
    int32_t len = strlen(pemdata);
    char *next = pemdata;
    uint32_t nextLen = len;
    uint8_t *asn1Encode = NULL;
    uint32_t asn1Len;
    ASSERT_TRUE(BSL_PEM_DecodePemToAsn1(&next, &nextLen, &sym, &asn1Encode, &asn1Len) == BSL_PEM_SYMBOL_NOT_FOUND);
EXIT:
    BSL_SAL_Free(asn1Encode);
    return;
}
/* END_CASE */
