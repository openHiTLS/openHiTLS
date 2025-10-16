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

#include "bsl_sal.h"
#include "bsl_params.h"
#include "bsl_err.h"
#include "bsl_list.h"
#include "crypt_eal_cipher.h"
/* END_HEADER */


/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_MAKER_New_API_TC001()
{
    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_TRUE(maker != NULL);
EXIT:
    if (maker) {
        BSL_PARAM_MAKER_Free(maker);
    }
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_MAKER_Push_Value_API_TC001()
{
    int32_t val = 1;
    bool valBool = true;
    int32_t *valPtr = &val;
    int32_t key = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_TRUE(maker != NULL);

    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(NULL, key, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UINT32, NULL, sizeof(val)), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_FUNC_PTR, valPtr, sizeof(valPtr)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_CTX_PTR, valPtr, sizeof(valPtr)), BSL_SUCCESS);
    valPtr = NULL;
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
EXIT:
    if (maker) {
        BSL_PARAM_MAKER_Free(maker);
    }
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_MAKER_ToParam_API_TC001()
{
    int32_t val = 1;
    uint8_t u8 = 10;
    uint16_t u16 = 20;
    uint32_t u32 = 100;
    bool valBool = true;
    int32_t key = 1;
    int32_t index = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &u32, sizeof(u32)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_INT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT8, &u8, sizeof(u8)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT16, &u16, sizeof(u16)), BSL_SUCCESS);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    ASSERT_TRUE(params != NULL);

    BSL_Param *temp = NULL;
    key = 1;
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_EQ(*((uint32_t *)temp->value), u32);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((bool *)temp->value), valBool);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((int32_t *)temp->value), val);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint8_t *)temp->value), u8);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint16_t *)temp->value), u16);
EXIT:
    if (maker) {
        BSL_PARAM_MAKER_Free(maker);
    }
    if (params) {
        BSL_PARAM_Free(params);
    }
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_MAKER_ToParam_API_TC002()
{
    char str[] = "aaa";
    uint32_t u32 = 100;
    uint32_t *ptr = &u32;
    unsigned char OCTETS[1];
    OCTETS[0] = 'a';
    int32_t key = 1;
    int32_t index = 1;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC);

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UTF8_STR, &str, sizeof(str)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_CTX_PTR, ctx, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32_PTR, ptr, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_OCTETS, &OCTETS, sizeof(OCTETS)), BSL_SUCCESS);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    BSL_Param *temp = NULL;

    key = 1;
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_TRUE(memcmp((char *)temp->value, str, sizeof(str)) == 0);

    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_TRUE(memcmp((CRYPT_EAL_CipherCtx *)temp->value, ctx, 0) == 0);

    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint32_t *)temp->value), u32);

    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_TRUE(memcmp((unsigned char *)temp->value, &OCTETS, sizeof(OCTETS)) == 0);

    BSL_PARAM_Free(params);
    params = NULL;
    key = 1;
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UTF8_STR, &str, sizeof(str) - 2), BSL_SUCCESS);
    params = BSL_PARAM_MAKER_ToParam(maker);

    temp = BSL_PARAM_FindParam(params, key);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_TRUE(memcmp((char *)temp->value, str, sizeof(str) - 2) == 0);
    ASSERT_TRUE(memcmp((char *)temp->value, str, sizeof(str)) == 0);

EXIT:
    if (maker) {
        BSL_PARAM_MAKER_Free(maker);
    }
    if (params) {
        BSL_PARAM_Free(params);
    }
    if (ctx) {
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
    return;
}
/* END_CASE */