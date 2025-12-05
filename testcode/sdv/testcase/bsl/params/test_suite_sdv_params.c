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

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_params.h"
#include "bsl_err.h"
#include "bsl_log.h"
/* END_HEADER */


/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_InitValue_API_TC001()
{
    BSL_Param param = {0};
    int32_t val = 1;
    bool valBool = true;
    int32_t *valPtr = &val;
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 0, BSL_PARAM_TYPE_UINT32,
        &val, sizeof(val)), BSL_PARAMS_INVALID_KEY);
    ASSERT_EQ(BSL_PARAM_InitValue(NULL, 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_UINT32, NULL, sizeof(val)), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, 100, &val, sizeof(val)), BSL_PARAMS_INVALID_TYPE);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_CTX_PTR, valPtr, 0), BSL_SUCCESS);
    valPtr = NULL;
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_SetValue_API_TC001()
{
    BSL_Param param = {0};
    int32_t val = 1;
    bool valBool = true;
    int32_t *valPtr = &val;
    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 0, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_PARAMS_INVALID_KEY);
    ASSERT_EQ(BSL_PARAM_SetValue(NULL, 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 2, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_PARAMS_MISMATCH);
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_UINT32, &val, 5), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_UINT32, NULL, sizeof(val)), BSL_INVALID_ARG);
    val = 4;
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_OCTETS_PTR, &val, sizeof(val)), BSL_PARAMS_MISMATCH);
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    int32_t retVal = 0;
    uint32_t retValLen = sizeof(retVal);
    ASSERT_EQ(BSL_PARAM_GetValue(&param, 1, BSL_PARAM_TYPE_UINT32, &retVal, &retValLen), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_GetValue(&param, 0, BSL_PARAM_TYPE_UINT32, &retVal, &retValLen), BSL_PARAMS_INVALID_KEY);
    ASSERT_EQ(BSL_PARAM_GetValue(NULL, 1, BSL_PARAM_TYPE_UINT32, &retVal, &retValLen), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_GetValue(&param, 1, BSL_PARAM_TYPE_OCTETS_PTR, &retVal, &retValLen), BSL_PARAMS_MISMATCH);

    ASSERT_EQ(retVal, val);

    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    valBool = false;
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    uint32_t boolSize = sizeof(valBool);
    ASSERT_EQ(BSL_PARAM_GetValue(&param, 1, BSL_PARAM_TYPE_BOOL, &valBool, &boolSize), BSL_SUCCESS);
    ASSERT_EQ(valBool, false);

    ASSERT_EQ(BSL_PARAM_InitValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
    *valPtr = 0;
    ASSERT_EQ(BSL_PARAM_SetValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_GetPtrValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, (void **)&valPtr, NULL), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_GetPtrValue(&param, 0, BSL_PARAM_TYPE_FUNC_PTR, (void **)&valPtr, NULL), BSL_PARAMS_INVALID_KEY);
    ASSERT_EQ(BSL_PARAM_GetPtrValue(NULL, 1, BSL_PARAM_TYPE_FUNC_PTR, (void **)&valPtr, NULL), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_GetPtrValue(&param, 1, BSL_PARAM_TYPE_FUNC_PTR, NULL, NULL), BSL_INVALID_ARG);

    ASSERT_EQ(*valPtr, 0);

EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_SetValue_API_TC002()
{
    uint8_t tmp1 = 0;
    uint16_t tmp2 = 0;
    uint32_t tmp3 = 0;
    bool tmp4 = 0;
    uint8_t tmpBuffer1[10] = {0};
    uint32_t tmpBuffer1Len = 10;
    uint8_t ptr[] = {0};

    uint8_t val1 = 1;
    uint16_t val2 = 1;
    uint32_t val3 = 1;
    bool val4 = true;
    uint8_t buffer1[15] = {1};
    uint32_t buffer1Len = 15;

    BSL_Param param[9] = {
        {1, BSL_PARAM_TYPE_UINT8, &tmp1, sizeof(tmp1), sizeof(tmp1)},
        {1, BSL_PARAM_TYPE_UINT16, &tmp2, sizeof(tmp2), sizeof(tmp2)},
        {1, BSL_PARAM_TYPE_UINT32, &tmp3, sizeof(tmp3), sizeof(tmp3)},
        {1, BSL_PARAM_TYPE_OCTETS, tmpBuffer1, tmpBuffer1Len, tmpBuffer1Len},
        {1, BSL_PARAM_TYPE_BOOL, &tmp4, sizeof(tmp4), sizeof(tmp4)},
        {1, BSL_PARAM_TYPE_OCTETS_PTR, NULL, 0, 0},
        {1, BSL_PARAM_TYPE_FUNC_PTR, NULL, 0, 0},
        {1, BSL_PARAM_TYPE_CTX_PTR, NULL, 0, 0},
        BSL_PARAM_END
    };

    ASSERT_EQ(BSL_PARAM_SetValue(&param[0], 1, BSL_PARAM_TYPE_UINT8, &val1, sizeof(val1)), BSL_SUCCESS);
    ASSERT_EQ(val1, tmp1);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[1], 1, BSL_PARAM_TYPE_UINT16, &val2, sizeof(val2)), BSL_SUCCESS);
    ASSERT_EQ(val2, tmp2);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[2], 1, BSL_PARAM_TYPE_UINT32, &val3, sizeof(val3)), BSL_SUCCESS);
    ASSERT_EQ(val3, tmp3);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[3], 1, BSL_PARAM_TYPE_OCTETS, &buffer1, buffer1Len), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[3], 1, BSL_PARAM_TYPE_OCTETS, &buffer1, buffer1Len - 5), BSL_SUCCESS);
    ASSERT_COMPARE("compare value", tmpBuffer1, param[3].useLen, buffer1, buffer1Len - 5);
    tmpBuffer1[0] = 2;
    ASSERT_EQ(BSL_PARAM_SetValue(&param[3], 1, BSL_PARAM_TYPE_OCTETS, &buffer1, buffer1Len - 10), BSL_SUCCESS);
    ASSERT_COMPARE("compare value", tmpBuffer1, param[3].useLen, buffer1, buffer1Len - 10);

    ASSERT_EQ(BSL_PARAM_SetValue(&param[4], 1, BSL_PARAM_TYPE_BOOL, &val4, sizeof(val4)), BSL_SUCCESS);
    ASSERT_EQ(val4, tmp4);

    ASSERT_EQ(BSL_PARAM_SetValue(&param[5], 1, BSL_PARAM_TYPE_OCTETS_PTR, ptr, 8), BSL_SUCCESS);
    ASSERT_EQ(param[5].value, ptr);
    ASSERT_EQ(param[5].useLen, 8);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[6], 1, BSL_PARAM_TYPE_FUNC_PTR, ptr, 8), BSL_SUCCESS);
    ASSERT_EQ(param[6].value, ptr);
    ASSERT_EQ(param[6].useLen, 8);
    ASSERT_EQ(BSL_PARAM_SetValue(&param[7], 1, BSL_PARAM_TYPE_CTX_PTR, ptr, 8), BSL_SUCCESS);
    ASSERT_EQ(param[7].value, ptr);
    ASSERT_EQ(param[7].useLen, 8);
EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_BSL_PARAM_FindParam_API_TC001()
{
    BSL_Param param[6] = {0};
    int32_t val = 1;
    bool valBool = true;
    int32_t *valPtr = &val;

    ASSERT_EQ(BSL_PARAM_InitValue(&param[0], 1, BSL_PARAM_TYPE_UINT32, &val, sizeof(val)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[1], 2, BSL_PARAM_TYPE_BOOL, &valBool, sizeof(valBool)), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[2], 3, BSL_PARAM_TYPE_FUNC_PTR, valPtr, 0), BSL_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&param[3], 4, BSL_PARAM_TYPE_CTX_PTR, valPtr, 0), BSL_SUCCESS);

    BSL_Param *temp = NULL;
    temp = BSL_PARAM_FindParam(param, 1);
    ASSERT_EQ(temp, &param[0]);
    temp = BSL_PARAM_FindParam(param, 2);
    ASSERT_EQ(temp, &param[1]);
    temp = BSL_PARAM_FindParam(param, 5);
    ASSERT_EQ(temp, NULL);

EXIT:
    return;
}
/* END_CASE */
