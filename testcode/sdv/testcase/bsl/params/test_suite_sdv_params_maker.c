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
    TestErrClear();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_FUNC_PTR, valPtr, sizeof(valPtr)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_CTX_PTR, valPtr, sizeof(valPtr)), BSL_SUCCESS);
    valPtr = NULL;
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());
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
    ASSERT_TRUE(TestIsErrStackEmpty());

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

/* @
* @test  SDV_HITLS_PARAM_001
* @spec  -
* @title  Accessing numeric data types normally in MAKER
* @precon  nan
* @brief
1.Call BSL_PARAM_MAKER_New to create a MAKER.
2.Call BSL_PARAM_MAKER_PushValue to store a bool type value into the MAKER.
3.Call BSL_PARAM_MAKER_PushValue to store an int32_t type value into the MAKER.
4.Call BSL_PARAM_MAKER_PushValue to store a uint8_t type value into the MAKER.
5.Call BSL_PARAM_MAKER_PushValue to store a uint16_t type value into the MAKER.
6.Call BSL_PARAM_MAKER_PushValue to store a uint32_t type value into the MAKER.
7.Call BSL_PARAM_MAKER_PushValue to store a string type value into the MAKER.
8.Call BSL_PARAM_MAKER_PushValue to store a pointer type value into the MAKER.
9.Call BSL_PARAM_MAKER_ToParam to convert the MAKER into a Param structure.
10.Compare the converted Param value with the input to ensure they are consistent.
11.Call BSL_PARAM_Free and BSL_PARAM_MAKER_Free to release the Param and MAKER.
* @expect
1.MAKER creation successful.
2.Data input successful.
3.Data input successful.
4.Data input successful.
5.Data input successful.
6.Data input successful.
7.Data input successful.
8.Data input successful.
9.Conversion successful.
10.Consistent with the input data.
11.Release successful.
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_PARAM_001()
{
    bool valBool = false;
    int32_t int32 = -1;
    uint8_t u8 = 10;
    uint16_t u16 = 20;
    uint32_t u32 = 100;
    char str[] = "aaa";
    uint32_t *ptr = &u32;
    int32_t key = 1;
    int32_t index = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_INT32, &int32, sizeof(int32)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT8, &u8, sizeof(u8)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT16, &u16, sizeof(u16)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &u32, sizeof(u32)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UTF8_STR, &str, sizeof(str)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32_PTR, ptr, 0), BSL_SUCCESS);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    ASSERT_TRUE(params != NULL);

    BSL_Param *temp = NULL;
    key = 1;
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_EQ(*((bool *)temp->value), valBool);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((int32_t *)temp->value), int32);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint8_t *)temp->value), u8);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint16_t *)temp->value), u16);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint32_t *)temp->value), u32);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_TRUE(memcmp((char *)temp->value, str, sizeof(str)) == 0);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint32_t *)temp->value), u32);
    ASSERT_TRUE(TestIsErrStackEmpty());
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

/* @
* @test  SDV_HITLS_PARAM_002
* @spec  -
* @title  Accessing numeric data types normally in MAKER
* @precon  nan
* @brief
1.Create a MAKER
2.Call BSL_PARAM_MAKER_PushValue to store an int32_t type value (-1) into the MAKER, with the Type parameter set to uint32_t
3.Convert the MAKER into a Param structure
4.Compare the converted Param value with the input to check for consistency
* @expect
1.MAKER creation successful
2.Data input successful
3.Conversion successful
4.1
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_PARAM_002()
{
    int32_t int32 = 65535;
    int32_t val_32 = -1;
    uint8_t val_8 = 255;
    bool valBool = true;
    int32_t key = 1;
    int32_t index = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();

    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &int32, sizeof(int32)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT8, &val_8, sizeof(val_8)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &val_32, sizeof(val_32)), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &val_8, sizeof(val_8)), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key++, BSL_PARAM_TYPE_UINT32, &val_8, sizeof(uint16_t)), BSL_INVALID_ARG);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    ASSERT_TRUE(params != NULL);

    BSL_Param *temp = NULL;
    key = 1;
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_EQ(*((uint32_t *)temp->value), int32);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint8_t *)temp->value), 255);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((bool *)temp->value), true);
    temp = BSL_PARAM_FindParam(params, key++);
    ASSERT_EQ(temp->value, (&params[index++])->value);
    ASSERT_EQ(*((uint32_t *)temp->value), 0xffffffff);

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

/* @
* @test  SDV_HITLS_PARAM_003
* @spec  -
* @title  Storing data into MAKER, len is smaller than the actual value.
* @precon  nan
* @brief
1.Create a MAKER
2.Call BSL_PARAM_MAKER_PushValue to store a string type value ("hello world") into the MAKER, with len set to 5
3.Convert the MAKER into a Param structure
4.Output the value of the converted Param
* @expect
1.MAKER creation successful
2.Data input successful
3.Conversion successful
4.Value is "hello"
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_PARAM_003()
{
    char str[] = "hello world";

    int32_t key = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
 
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UTF8_STR, &str, sizeof("hello")), BSL_SUCCESS);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    ASSERT_TRUE(params != NULL);

    BSL_Param *temp = NULL;
    temp = BSL_PARAM_FindParam(params, key);
    ASSERT_EQ(temp->value, params->value);
    ASSERT_TRUE(memcmp((char *)temp->value, str, sizeof("hello")) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

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

/* @
* @test  SDV_HITLS_PARAM_004
* @spec  -
* @title  Storing data into MAKER, len is larger than the actual value.
* @precon  nan
* @brief
1.Create a MAKER
2.Call BSL_PARAM_MAKER_PushValue to store a string type value ("hello world") into the MAKER, with len set to 20
* @expect
1.MAKER creation successful
2.Data input successful
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_PARAM_004()
{
    char str[] = "hello world";

    int32_t key = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
 
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_UTF8_STR, &str, sizeof("hello world!!!")), BSL_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    if (maker) {
        BSL_PARAM_MAKER_Free(maker);
    }
    return;
}
/* END_CASE */

/* @
* @test  SDV_HITLS_PARAM_005
* @spec  -
* @title  Store data into MAKER, including duplicate key values.
* @precon  nan
* @brief
1.Create a MAKER
2.Call BSL_PARAM_MAKER_PushValue to store an int32_t type value (0) into the MAKER, with the key value set to 0
3.Call BSL_PARAM_MAKER_PushValue to store an int32_t type value (1) into the MAKER, with the key value set to 0
4.Convert the MAKER into a Param structure
5.After conversion, retrieve the value using the Param index and check if it matches the input
6.After conversion, retrieve the value using BSL_PARAM_FindParam
* @expect
1.MAKER creation successful
2.Data input successful
3.Data input successful
4.Conversion successful
5.Matches the input value
6.The retrieved Param's value is 0
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_HITLS_PARAM_005()
{
    int32_t int32_0 = 0;
    int32_t int32_1 = 1;

    int32_t key = 1;

    BSL_ParamMaker *maker = BSL_PARAM_MAKER_New();
 
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_INT32, &int32_0, sizeof(int32_0)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_MAKER_PushValue(maker, key, BSL_PARAM_TYPE_INT32, &int32_1, sizeof(int32_1)), BSL_SUCCESS);

    BSL_Param *params = BSL_PARAM_MAKER_ToParam(maker);
    ASSERT_TRUE(params != NULL);

    BSL_Param *temp = NULL;
    temp = BSL_PARAM_FindParam(params, key);
    ASSERT_EQ(temp->value, (&params[0])->value);
    ASSERT_EQ(*((int32_t *)temp->value), int32_0);

    ASSERT_EQ(*((int32_t *)(&params[0])->value), int32_0);
    ASSERT_EQ(*((int32_t *)(&params[1])->value), int32_1);
    ASSERT_TRUE(TestIsErrStackEmpty());

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