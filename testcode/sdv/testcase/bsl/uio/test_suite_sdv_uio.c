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
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/ioctl.h>
#include "securec.h"
#include "stub_replace.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#include "sal_atomic.h"
#include "uio_abstraction.h"

/* END_HEADER */

#define MAX_BUF_SIZE 255
#define IP_V4_LEN 4
#define IP_V6_LEN 16

static int32_t g_writeRet;
static uint32_t g_writeLen;
static int32_t STUB_Write(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    (void)uio;
    (void)buf;
    (void)len;

    *writeLen = g_writeLen;
    return g_writeRet;
}

static int32_t g_readRet;
static uint32_t g_readLen;
static int32_t STUB_Read(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    (void)uio;
    (void)buf;
    (void)len;

    *readLen = g_readLen;
    return g_readRet;
}

static int32_t g_ctrlRet1;
static int32_t g_ctrlRet2;
static int32_t g_ctrlRet3;
static BSL_UIO_CtrlParameter g_ctrlCmd1;
static BSL_UIO_CtrlParameter g_ctrlCmd2;
static BSL_UIO_CtrlParameter g_ctrlCmd3;
static uint16_t g_shareKeyId;
static uint16_t g_delShareKeyId;
static uint8_t g_isEmpty;
static int32_t STUB_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *param)
{
    (void)larg;
    (void)uio;
    (void)param;
    if (cmd == BSL_UIO_SCTP_ADD_AUTH_SHARED_KEY) {
        BSL_UIO_SctpAuthKey *key = (BSL_UIO_SctpAuthKey *)param;
        g_shareKeyId = key->shareKeyId;
    }

    if (cmd == BSL_UIO_SCTP_DEL_PRE_AUTH_SHARED_KEY) {
        g_delShareKeyId = *(uint16_t*)param;
    }

    if (cmd == BSL_UIO_SCTP_SND_BUFF_IS_EMPTY) {
        *(uint8_t *)param = g_isEmpty;
    }

    if ((int32_t)g_ctrlCmd1 == cmd) {
        return g_ctrlRet1;
    }

    if ((int32_t)g_ctrlCmd2 == cmd) {
        return g_ctrlRet2;
    }

    if ((int32_t)g_ctrlCmd3 == cmd) {
        return g_ctrlRet3;
    }

    return BSL_UIO_FAIL;
}

const BSL_UIO_Method * GetUioMethodByType(int uioType)
{
    switch (uioType) {
#ifdef HITLS_BSL_UIO_TCP
        case BSL_UIO_TCP:
            return BSL_UIO_TcpMethod();
#endif
#ifdef HITLS_BSL_UIO_UDP
        case BSL_UIO_UDP:
            return BSL_UIO_UdpMethod();
#endif
        case BSL_UIO_BUFFER:
            return BSL_UIO_BufferMethod();
        default:
            return NULL;
    }
}

typedef struct {
    int32_t len;
    uint8_t index;
    uint8_t *buff;
} CustomLowCtx;

static int32_t BslUioCreate(BSL_UIO *uio)
{
    int32_t len = 20;
    int32_t ret;
    CustomLowCtx *lowCtx = BSL_SAL_Calloc(1, sizeof(CustomLowCtx));
    if (lowCtx == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto EXIT;
    }
    lowCtx->buff = BSL_SAL_Malloc(len);
    if (lowCtx->buff == NULL) {
        ret = BSL_MALLOC_FAIL;
        goto EXIT;
    }
    lowCtx->len = len;
    BSL_UIO_SetCtx(uio, (void *)lowCtx);
    BSL_UIO_SetInit(uio, 1);
    return BSL_SUCCESS;
EXIT:
    if(lowCtx != NULL) {
        BSL_SAL_FREE(lowCtx->buff);
        BSL_SAL_FREE(lowCtx);
    }
    return ret;
}

static int32_t BslUioDestroy(BSL_UIO *uio)
{
    CustomLowCtx *lowCtx = BSL_UIO_GetCtx(uio);
    if (lowCtx == NULL) {
        return BSL_INVALID_ARG;
    }
    BSL_SAL_FREE(lowCtx->buff);
    BSL_SAL_FREE(lowCtx);
    BSL_UIO_SetCtx(uio, NULL);
    return BSL_SUCCESS;
}

static int32_t BslUioWrite(BSL_UIO *uio, const void *buf, uint32_t len, uint32_t *writeLen)
{
    CustomLowCtx *lowCtx = BSL_UIO_GetCtx(uio);
    if (lowCtx == NULL) {
        return BSL_INVALID_ARG;
    }
    uint32_t reslen = lowCtx->len - lowCtx->index;
    if (reslen < len) {
        return BSL_INVALID_ARG;
    }
    memcpy_s(lowCtx->buff + lowCtx->index, len, buf, len);
    lowCtx->index += len;
    *writeLen = len;
    return BSL_SUCCESS;
}

static int32_t BslUioRead(BSL_UIO *uio, void *buf, uint32_t len, uint32_t *readLen)
{
    CustomLowCtx *lowCtx = BSL_UIO_GetCtx(uio);
    if (lowCtx == NULL) {
        return BSL_INVALID_ARG;
    }
    if (lowCtx->index == 0) {
        return BSL_INVALID_ARG;
    }

    int copyLen = (lowCtx->index > len) ? len : lowCtx->index;
    (void)memcpy_s(buf, copyLen, lowCtx->buff, copyLen);
    *readLen = copyLen;
    lowCtx->index -= copyLen;
    return BSL_SUCCESS;
}

#define BSL_CUSTOM_UIO_GET_INDEX 0x100

static int32_t BslUioCtrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    (void)larg;
    CustomLowCtx *lowCtx = BSL_UIO_GetCtx(uio);
    if (lowCtx == NULL) {
        return BSL_INVALID_ARG;
    }
    if (cmd == BSL_CUSTOM_UIO_GET_INDEX) {
        *(uint32_t *)parg = lowCtx->index;
        return BSL_SUCCESS;
    }
    return BSL_INVALID_ARG;
}

static int32_t BslUioPuts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    (void) uio;
    (void) buf;
    (void) writeLen;
    return BSL_INVALID_ARG;
}

static int32_t BslUioGets(BSL_UIO *uio, char *buf, uint32_t *readLen)
{
    (void) uio;
    (void) buf;
    (void) readLen;
    return BSL_INVALID_ARG;
}

/**
 * @test  SDV_BSL_UIO_NEW_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1. Construct the tcp/sctp/udp method structure, and invoke BSL_UIO_New.
 *    2. Invoke the BSL_UIO_GetTransportType interface.
 * @expect
 *    1. Expected the uio is not NULL, and transport type is the target type
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_NEW_API_TC001(void)
{
#if defined(HITLS_BSL_UIO_TCP) || defined(HITLS_BSL_UIO_UDP)
    TestMemInit();
    /* Set method to NULL */
    BSL_UIO *uio = BSL_UIO_New(NULL);
    ASSERT_TRUE(uio == NULL);
#ifdef HITLS_BSL_UIO_TCP
    /* Set transportType to tcp and construct the method structure. */
    {
        const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
        BSL_UIO_Method method = {0};
        memcpy(&method, ori, sizeof(method));
        method.uioWrite = STUB_Write;
        method.uioRead = STUB_Read;
        method.uioCtrl = STUB_Ctrl;
        uio = BSL_UIO_New(&method);
        ASSERT_TRUE(uio != NULL && BSL_UIO_GetTransportType(uio) == BSL_UIO_TCP);
        BSL_UIO_Free(uio);
    }
#endif
#ifdef HITLS_BSL_UIO_UDP
    /* Set transportType to udp and construct the method structure. */
    {
        const BSL_UIO_Method *ori = BSL_UIO_UdpMethod();
        BSL_UIO_Method method = {0};
        memcpy(&method, ori, sizeof(method));
        method.uioWrite = STUB_Write;
        method.uioRead = STUB_Read;
        method.uioCtrl = STUB_Ctrl;
        uio = BSL_UIO_New(&method);
        ASSERT_TRUE(uio != NULL && BSL_UIO_GetTransportType(uio) == BSL_UIO_UDP);
        BSL_UIO_Free(uio);
    }
#endif
EXIT:
    return;
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_NEW_API_TC002
 * @title BSL uio and meth parameter test
 * @precon Registering memory-related functions.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_NEW_API_TC002(void)
{
    TestMemInit();

    BSL_UIO *uio = BSL_UIO_New(NULL);
    ASSERT_EQ(uio, NULL);
    BSL_UIO_Method *ori = BSL_UIO_NewMethod();
    ASSERT_NE(ori, NULL);
    int32_t customType = BSL_UIO_EXTEND + 3;

    ASSERT_EQ(BSL_UIO_SetMethodType(ori, customType), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_READ_CB, BslUioRead), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_WRITE_CB, BslUioWrite), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_CTRL_CB, BslUioCtrl), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_CREATE_CB, BslUioCreate), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_DESTROY_CB, BslUioDestroy), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_PUTS_CB, BslUioPuts), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_GETS_CB, BslUioGets), BSL_SUCCESS);

    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_READ_CB, NULL), BSL_NULL_INPUT);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_GETS_CB + 1, BslUioGets), BSL_INVALID_ARG);

    uio = BSL_UIO_New(ori);
    ASSERT_NE(uio, NULL);

    ASSERT_EQ(BSL_UIO_GetTransportType(uio), customType);

    char *test = "test ";
    uint32_t len = 0;
    ASSERT_EQ(BSL_UIO_Gets(uio, test, &len), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_UIO_Puts(uio, test, &len), BSL_INVALID_ARG);

EXIT:
    BSL_UIO_Free(uio);
    BSL_UIO_FreeMethod(ori);
}
/* END_CASE */


/**
 * @test  SDV_BSL_UIO_NEW_API_TC001
 * @title BSL uio and meth functional test
 * @precon Registering memory-related functions.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_NEW_FUNC_TC001(void)
{
    uint8_t test[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    TestMemInit();

    BSL_UIO_Method *ori = BSL_UIO_NewMethod();
    ASSERT_NE(ori, NULL);
    int32_t customType = BSL_UIO_EXTEND + 3;

    ASSERT_EQ(BSL_UIO_SetMethodType(ori, customType), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_READ_CB, BslUioRead), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_WRITE_CB, BslUioWrite), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_CTRL_CB, BslUioCtrl), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_CREATE_CB, BslUioCreate), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_DESTROY_CB, BslUioDestroy), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_PUTS_CB, BslUioPuts), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_SetMethod(ori, BSL_UIO_GETS_CB, BslUioGets), BSL_SUCCESS);
    BSL_UIO *uio = BSL_UIO_New(ori);
    ASSERT_NE(uio, NULL);

    ASSERT_EQ(BSL_UIO_GetTransportType(uio), customType);

    uint32_t len = 0;
    ASSERT_EQ(BSL_UIO_Write(uio, test, 3, &len), BSL_SUCCESS);
    ASSERT_EQ(len, 3);

    ASSERT_EQ(BSL_UIO_Write(uio, &test[3], 7, &len), BSL_SUCCESS);
    ASSERT_EQ(len, 7);

    uint32_t index = 0;
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_CUSTOM_UIO_GET_INDEX, sizeof(index), &index), BSL_SUCCESS);
    ASSERT_EQ(index, 10);

    uint8_t readBuff[20] = {0};
    ASSERT_EQ(BSL_UIO_Read(uio, readBuff, 8, &len), BSL_SUCCESS);
    ASSERT_EQ(len, 8);

    ASSERT_EQ(BSL_UIO_Read(uio, &readBuff[7], 8, &len), BSL_SUCCESS);
    ASSERT_EQ(len, 2);

    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_CUSTOM_UIO_GET_INDEX, sizeof(index), &index), BSL_SUCCESS);
    ASSERT_EQ(index, 0);

EXIT:
    BSL_UIO_Free(uio);
    BSL_UIO_FreeMethod(ori);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_INIT_FUNC_TC001
 * @title  Init status value test: The uio type of the FD can be set.
 * @precon  nan
 * @brief
 *    1.BSL_UIO_New,Expected result 1 is obtained.
 *    2.BSL_UIO_GET_INIT,Expected result 2 is obtained.
 *    3.BSL_UIO_GET_FD,Expected result 3 is obtained.
 *    4.BSL_UIO_SET_FD,Expected result 4 is obtained.
 *    5.BSL_UIO_GET_INIT,Expected result 5 is obtained.
 *    6.BSL_UIO_GET_FD,Expected result 6 is obtained.
 * @expect
 *    1.Expected success
 *    2.The value of init is 0.
 *    3.Expected failure, The error code is BSL_UIO_UNINITIALIZED,fd is - 1.
 *    4.Expected success
 *    5.The value of init is 1.
 *    6.Expected success
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_INIT_FUNC_TC001(int uioType)
{
    BSL_UIO *uio = NULL;
    int32_t fd = 5;
    uint8_t init = 0;
    int32_t getFd = 0;

    const BSL_UIO_Method *ori = NULL;
    switch (uioType) {
        case BSL_UIO_TCP:
        case BSL_UIO_UDP:
            ori = GetUioMethodByType(uioType);
            break;
        default: // The uio of the FD cannot be set.
            ASSERT_TRUE(false);
    }
    ASSERT_TRUE(ori != NULL);

    uio = BSL_UIO_New(ori);
    ASSERT_TRUE(uio != NULL);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_INIT, (int32_t)sizeof(init), &init), BSL_SUCCESS);
    ASSERT_EQ(init, 0);

    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd), BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_INIT, (int32_t)sizeof(init), &init), BSL_SUCCESS);
    ASSERT_EQ(init, 1);

    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, (int32_t)sizeof(fd), &getFd), BSL_SUCCESS);
    ASSERT_EQ(getFd, fd);

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_INIT_FUNC_TC002
 * @title  Init status value test: Test the UIO type whose init is set to 1 during create.
 * @precon  nan
 * @brief
 *    1.Call BSL_UIO_New. Expected result 1 is obtained.
 *    2.Call BSL_UIO_GET_INIT. Expected result 1 is obtained.
 * @expect
 *    1.Success
 *    2.init is 1
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_INIT_FUNC_TC002(int uioType)
{
    BSL_UIO *uio = NULL;
    uint8_t init = 0;

    const BSL_UIO_Method *ori = NULL;
    switch (uioType) {
        case BSL_UIO_BUFFER:
            ori = GetUioMethodByType(uioType);
            break;
        default:
            ASSERT_TRUE(false);
    }
    ASSERT_TRUE(ori != NULL);

    uio = BSL_UIO_New(ori);
    ASSERT_TRUE(uio != NULL);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_INIT, (int32_t)sizeof(init), &init), BSL_SUCCESS);
    ASSERT_EQ(init, 1);

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  UT_BSL_UIO_FREE_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1. Set UIO to null and invoke BSL_UIO_Free. Expected result 1 is obtained.
 * @expect
 *    1. It is expected that the program does not dump code. No memory leakage occurs.
 */
/* BEGIN_CASE */
void UT_BSL_UIO_FREE_API_TC001(void)
{
    /* The test UIO is empty. */
    BSL_UIO_Free(NULL);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_SETUSERDATA_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1.The specified uio is empty, Invoke BSL_UIO_SetUserData,Expected result 1 is obtained.
 *    2.Construct the uio object,  the user data is empty, invoke the BSL_UIO_SetUserData interface.
        Expected result 2 is obtained.
 *    3.Invoke BSL_UIO_SetUserData to specify that data1 is not null, Expected result 3 is obtained.
 *    4.User data2 is not empty, call BSL_UIO_SetUserData again, Expected result 4 is obtained.
 *    5.Releasing a UIO Object, Expected result 5 is obtained.
 * @expect
 *    1.Expected return failure
 *    2.Expected success
 *    3.Expected success
 *    4.Expected success
 *    5.It is expected that the program does not have code dump and no memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_SETUSERDATA_API_TC001(void)
{
    BSL_UIO *uio = NULL;
    void *userData1 = (void *)STUB_Write;
    void *userData2 = (void *)STUB_Read;
    /* The test UIO is empty. */
    int32_t ret = BSL_UIO_SetUserData(NULL, userData1);
    ASSERT_TRUE(ret == BSL_NULL_INPUT);

    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(uio != NULL);

    ret = BSL_UIO_SetUserData(uio, NULL);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_UIO_SetUserData(uio, userData1);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_UIO_SetUserData(uio, userData2);
    ASSERT_TRUE(ret == BSL_SUCCESS);

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_GETUSERDATA_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1.The specified uio is empty., invoke BSL_UIO_GetUserData. Expected result 1 is obtained.
 *    2.Construct the uio object, invoke BSL_UIO_GetUserData. Expected result 2 is obtained.
 *    3.Construct user data, invoke BSL_UIO_SetUserData. Expected result 3 is obtained.
 *    4.Invoke BSL_UIO_GetUserData. Expected result 4 is obtained.
 *    5.Invoke BSL_UIO_Free. Expected result 5 is obtained.
 * @expect
 *    1.Expected return NULL
 *    2.Expected return NULL
 *    3.Expected success
 *    4.The expected return value is the same as the data pointer.
 *    5.It is expected that the program does not have code dump and no memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_GETUSERDATA_API_TC001(void)
{
    BSL_UIO *uio = NULL;
    void *userData = (void *)STUB_Write;
    /* The test UIO is empty. */
    void *data = BSL_UIO_GetUserData(NULL);
    ASSERT_TRUE(data == NULL);

    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(uio != NULL);

    int32_t ret = BSL_UIO_SetUserData(uio, userData);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    data = BSL_UIO_GetUserData(uio);
    ASSERT_TRUE(data == userData);
EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_FLAGS_FUNC_TC001
 * @title  UIO Setting the Status Test
 * @precon  nan
 * @brief
 *    1.BSL_UIO_New. Expected result 1 is obtained.
 *    2.BSL_UIO_SetFlags. Expected result 2 is obtained.
 * @expect
 *    1.Expected success
 *    2.If the flags are invalid, BSL_INVALID_ARG is returned. If the flags are valid, BSL_SUCCESS is returned.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_FLAGS_FUNC_TC001(int uioType)
{
    BSL_UIO *uio = NULL;

    const BSL_UIO_Method *ori = GetUioMethodByType(uioType);
    ASSERT_TRUE(ori != NULL);

    uio = BSL_UIO_New(ori);
    ASSERT_TRUE(uio != NULL);

    // 0000 0001
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_READ), BSL_SUCCESS);
    // 0000 0010
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE), BSL_SUCCESS);
    // 0000 0100
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_IO_SPECIAL), BSL_SUCCESS);
    // 0000 0111
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_RWS), BSL_SUCCESS);
    // 0000 1000
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_SHOULD_RETRY), BSL_SUCCESS);
    // 0001 0000
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_MEM_READ_ONLY), BSL_INVALID_ARG);
    // 0010 0000
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_BASE64_NO_NEWLINE), BSL_SUCCESS);
    // 0100 0000
    ASSERT_EQ(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_BASE64_PEM), BSL_SUCCESS);
    // 0111 1111
    ASSERT_EQ(BSL_UIO_SetFlags(uio, 0b01111111), BSL_INVALID_ARG);
    // 0110 1111
    ASSERT_EQ(BSL_UIO_SetFlags(uio, 0b01101111), BSL_SUCCESS);
    // 1110 1111
    ASSERT_EQ(BSL_UIO_SetFlags(uio, 0b11101111), BSL_INVALID_ARG);

    ASSERT_EQ(BSL_UIO_SetFlags(uio, -1), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_UIO_SetFlags(uio, INT_MAX), BSL_INVALID_ARG);
    ASSERT_EQ(BSL_UIO_SetFlags(uio, 0), BSL_INVALID_ARG);

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_FLAGS_FUNC_TC002
 * @title  UIO flags interface test
 * @precon
* @brief
*    1. uio new. Expected result 1 is obtained.
*    2. Set two flags A and B. Expected result 2 is obtained.
*    3. Detection mark A. Expected result 3 is obtained.
*    4. Clear mark A. Expected result 4 is obtained.
*    5. Detection mark A. Expected result 5 is obtained.
*    6. Detection mark B. Expected result 6 is obtained.
* @expect
*    1. The success is not null.
*    2. Success
*    3. Successful and flag A detected
*    4. Success
*    5. Succeeded and Flag A Not Detected
*    6. Successful and Mark B detected
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_FLAGS_FUNC_TC002(void)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(uio != NULL);

    ASSERT_TRUE(BSL_UIO_SetFlags(uio, BSL_UIO_FLAGS_WRITE | BSL_UIO_FLAGS_SHOULD_RETRY) == BSL_SUCCESS);

    uint32_t out = 0;
    ASSERT_TRUE(BSL_UIO_TestFlags(uio, BSL_UIO_FLAGS_WRITE, &out) == BSL_SUCCESS);
    ASSERT_TRUE(out == BSL_UIO_FLAGS_WRITE);

    ASSERT_TRUE(BSL_UIO_ClearFlags(uio, BSL_UIO_FLAGS_WRITE) == BSL_SUCCESS);

    ASSERT_TRUE(BSL_UIO_TestFlags(uio, BSL_UIO_FLAGS_WRITE, &out) == BSL_SUCCESS);
    ASSERT_TRUE(out == 0);

    ASSERT_TRUE(BSL_UIO_TestFlags(uio, BSL_UIO_FLAGS_SHOULD_RETRY, &out) == BSL_SUCCESS);
    ASSERT_TRUE(out == BSL_UIO_FLAGS_SHOULD_RETRY);
EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_UPREF_API_TC001
 * @title  Input Parameter test
 * @precon  nan
 * @brief
 *    1.The specified uio is empty, invoke UIO_UpRef. Expected result 1 is obtained.
 *    2.Construct the uio object(BSL_UIO_New), invoke UIO_UpRef. Expected result 2 is obtained.
 *    3.BSL_UIO_Free is invoked twice. Expected result 3 is obtained.
 * @expect
 *    1.Expected return failure
 *    2.Expected success
 *    3.It is expected that the program does not have code dump and no memory leakage occurs.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_UPREF_API_TC001(void)
{
#ifndef HITLS_BSL_UIO_SCTP
    SKIP_TEST();
#else
    BSL_UIO *uio = NULL;
    /* The test UIO is empty. */
    int32_t ret = BSL_UIO_UpRef(NULL);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    uio = BSL_UIO_New(BSL_UIO_SctpMethod());
    ASSERT_TRUE(uio != NULL);

    ret = BSL_UIO_UpRef(uio);
    ASSERT_TRUE(ret == BSL_SUCCESS);

EXIT:
    BSL_UIO_Free(uio);
    BSL_UIO_Free(uio);
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_WRITE_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_TcpMethod to create a tcp method. Expected result 1 is obtained.
 *    2. The value of the input parameter UIO is NULL when BSL_UIO_Write is invoked. Expected result 2 is obtained.
 *    3. The value of the input parameter data is NULL when BSL_UIO_Write is invoked. Expected result 2 is obtained.
 *    4. The value of the input parameter data len is 0 when BSL_UIO_Write is invoked. Expected result 2 is obtained.
 *    5. The value of the input parameter write len is NULL when BSL_UIO_Write is invoked. Expected result 2 is obtained.
 * @expect
 *    1. The TCP method is successfully created.
 *    2. Return HITLS_INTERNAL_EXCEPTION
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_WRITE_API_TC001(void)
{
#ifdef HITLS_BSL_UIO_TCP
    BSL_UIO *uio = NULL;
    uint8_t data[MAX_BUF_SIZE] = {0};
    const uint32_t len = 1;
    uint32_t writeLen;

    const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
    BSL_UIO_Method method = {0};
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_Write;
    method.uioRead = STUB_Read;

    /* The test UIO is empty. */
    int32_t ret = BSL_UIO_Write(NULL, data, len, &writeLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);

    /* The test data is null. */
    ret = BSL_UIO_Write(uio, NULL, len, &writeLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    /* Test the case when the write length is 0. */
    ret = BSL_UIO_Write(uio, data, 0, &writeLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    /* Test that writeLen is NULL. */
    ret = BSL_UIO_Write(uio, data, len, NULL);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);
EXIT:
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_READ_API_TC001
 * @title  Input parameter test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_TcpMethod to create a tcp method. Expected result 1 is obtained.
 *    2. The value of the input parameter UIO is NULL when BSL_UIO_Read is invoked. Expected result 2 is obtained.
 *    3. The value of the input parameter data is NULL when BSL_UIO_Read is invoked. Expected result 3 is obtained.
 *    4. The value of the input parameter data len is 0 when BSL_UIO_Read is invoked. Expected result 4 is obtained.
 *    5. The value of the input parameter write len is NULL when BSL_UIO_Read is invoked. Expected result 4 is obtained.
 * @expect
 *    1. The TCP method is successfully created.
 *    2. Return BSL_INTERNAL_EXCEPTION
 *    3. Return BSL_INTERNAL_EXCEPTION
 *    4. Return BSL_INTERNAL_EXCEPTION
 *    5. Return BSL_INTERNAL_EXCEPTION
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_READ_API_TC001(void)
{
#ifdef HITLS_BSL_UIO_TCP
    BSL_UIO *uio = NULL;
    uint8_t data[MAX_BUF_SIZE] = {0};
    const uint32_t len = 1;
    uint32_t readLen;

    const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
    BSL_UIO_Method method = {0};
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_Write;
    method.uioRead = STUB_Read;

    /* The test UIO is empty. */
    int32_t ret = BSL_UIO_Read(NULL, data, len, &readLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);

    /* The test data is null. */
    ret = BSL_UIO_Read(uio, NULL, len, &readLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    /* Test the case when the write length is 0. */
    ret = BSL_UIO_Read(uio, data, 0, &readLen);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);

    /* Test that writeLen is NULL. */
    ret = BSL_UIO_Read(uio, data, len, NULL);
    ASSERT_TRUE(ret == BSL_INTERNAL_EXCEPTION);
EXIT:
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_SET_USERDATA_FREE_TC001
 * @title  Set userData free test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_New to create a tcp uio. Expected result 1 is obtained.
 *    2. Apply for space for userData. Expected result 2 is obtained.
 *    3. Call BSL_UIO_SetUserData to set userData for UIO. Expected result 3 is obtained.
 *    4. Call BSL_UIO_SetUserDataFreeFunc when uio is NULL. Expected result 4 is obtained.
 *    5. Call BSL_UIO_SetUserDataFreeFunc when uio is not null. Expected result 5 is obtained.
 * @expect
 *    1. The TCP UIO is successfully created.
 *    2. The value of userData is not empty.
 *    3. Return BSL_SUCCESS and the userdata of the UIO is not empty.
 *    4. Return BSL_NULL_INPUT
 *    5. Return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_SET_USERDATA_FREE_TC001(void)
{
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(uio != NULL);
    void *userData = BSL_SAL_Malloc(MAX_BUF_SIZE);
    ASSERT_TRUE(userData != NULL);

    int32_t ret = BSL_UIO_SetUserData(uio, userData);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(uio->userData != NULL);

    ret = BSL_UIO_SetUserDataFreeFunc(NULL, BSL_SAL_Free);
    ASSERT_TRUE(ret == BSL_NULL_INPUT);

    ret = BSL_UIO_SetUserDataFreeFunc(uio, BSL_SAL_Free);
    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_GET_METHOD_TC001
 * @title  Get uio method test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_New to create a tcp uio. Expected result 1 is obtained.
 *    2. Call BSL_UIO_TcpMethod to create a tcp method. Call BSL_UIO_GetMethod to obtain the method of TCP_UIO.
 *       Compare the two methods. Expected result 2 is obtained.
 * @expect
 *    1. The TCP UIO is successfully created.
 *    2. The two methods are equal.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_GET_METHOD_TC001(void)
{
#ifdef HITLS_BSL_UIO_TCP
    const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
    BSL_UIO *uio = BSL_UIO_New(ori);
    ASSERT_TRUE(uio != NULL);

    const BSL_UIO_Method *method = BSL_UIO_GetMethod(uio);
    int ret = memcmp(method, ori, sizeof(BSL_UIO_Method));
    ASSERT_TRUE(ret == 0);
EXIT:
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_GET_READANDWRITE_NUM_TC001
 * @title  Get read and written num test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_TcpMethod to create a tcp method. Expected result 1 is obtained.
 *    2. Call BSL_UIO_New to create a tcp uio. Expected result 2 is obtained.
 *    3. Call BSL_UIO_Ctrl and transfer the BSL_UIO_GET_WRITE_NUM parameter to obtain the number of written
 *       bytes. Expected result 3 is obtained.
 *    4. Call BSL_UIO_Ctrl and transfer the BSL_UIO_GET_READ_NUM parameter to obtain the number of read bytes.
 *       Expected result 4 is obtained.
 * @expect
 *    1. The TCP METHOD is successfully created.
 *    2. The TCP UIO is successfully created.
 *    3. The value of writeNum is the same as the number of written bytes.
 *    4. The value of readNum is the same as the number of read bytes.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_GET_READANDWRITE_NUM_TC001(void)
{
#ifdef HITLS_BSL_UIO_TCP
    BSL_UIO *uio = NULL;
    uint8_t data[10] = {'0', '1', '2', '3', '4'};
    uint8_t readBuf[10] = {0};
    const uint32_t dataLen = 5;
    uint32_t writeLen = 0;
    uint32_t readLen = 0;
    int64_t writeNum = 0;
    int64_t readNum = 0;

    const BSL_UIO_Method *ori = BSL_UIO_TcpMethod();
    BSL_UIO_Method method = {0};
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_Write;
    method.uioRead = STUB_Read;

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);
    BSL_UIO_SetInit(uio, 1);

    ASSERT_TRUE(BSL_UIO_Write(uio, data, dataLen, &writeLen) == BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_WRITE_NUM, (int32_t)sizeof(writeNum), &writeNum), BSL_SUCCESS);
    ASSERT_EQ(writeNum, writeLen);

    ASSERT_TRUE(BSL_UIO_Read(uio, readBuf, dataLen, &readLen) == BSL_SUCCESS);
    ASSERT_EQ(BSL_UIO_Ctrl(uio, BSL_UIO_GET_READ_NUM, (int32_t)sizeof(readNum), &readNum), BSL_SUCCESS);
    ASSERT_EQ(readNum, readLen);
EXIT:
    BSL_UIO_Free(uio);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_SET_FD_TC001
 * @title  Set fd test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_New to create a tcp uio. Expected result 1 is obtained.
 *    2. Call BSL_UIO_SetFD to set fd to uio. Call BSL_UIO_Ctrl and transfer the BSL_UIO_GET_FD parameter to obtain
 *       the fd1 of uio. Compare the two fds. Expected result 2 is obtained.
 * @expect
 *    1. The TCP UIO is successfully created.
 *    2. The two fds are equal.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_SET_FD_TC001(void)
{
    char *filename = "fd_test_file.txt";
    int fd = open(filename, O_RDWR | O_CREAT, 0060);
    const char *data = "012345678\nabcdef";
    write(fd, data, strlen(data));
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(uio != NULL);
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);

    BSL_UIO_SetFD(uio, fd);
    int32_t fd1 = -1;
    ASSERT_TRUE(BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, (int32_t)sizeof(fd1), &fd1) == BSL_SUCCESS);
    ASSERT_TRUE(fd == fd1);
EXIT:
    BSL_UIO_Free(uio);
    remove(filename);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_NEXT_TC001
 * @title  Uio next test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_New to create a tcp uio named tcp1. Expected result 1 is obtained.
 *    2. Call BSL_UIO_New to create a tcp uio named tcp2. Expected result 2 is obtained.
 *    3. Append tcp2 to tcp1. Expected result 3 is obtained.
 *    4. Check the next uio of tcp1 and the next uio of tcp2. Expected result 4 is obtained.
 * @expect
 *    1. The tcp1 is successfully created.
 *    2. The tcp2 is successfully created.
 *    3. Return BSL_SUCCESS.
 *    4. The next uio of tcp1 is tcp2 and the next uio of tcp2 is NULL.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_NEXT_TC001(void)
{
    BSL_UIO *tcp1 = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(tcp1 != NULL);
    BSL_UIO *tcp2 = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(tcp2 != NULL);

    ASSERT_TRUE(BSL_UIO_Append(tcp1, tcp2) == BSL_SUCCESS);
    ASSERT_TRUE(BSL_UIO_Next(tcp1) == tcp2);
    ASSERT_TRUE(BSL_UIO_Next(tcp2) == NULL);
EXIT:
    BSL_UIO_Free(tcp1);
    BSL_UIO_Free(tcp2);
}
/* END_CASE */

typedef union {
    struct sockaddr addr;
    struct sockaddr_in6 addrIn6;
    struct sockaddr_in addrIn;
    struct sockaddr_un addrUn;
} UIO_Addr;
/**
 * @test  SDV_BSL_UIO_UDP_API_TC001
 * @title  UDP ctrl test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_UdpMethod to create a UDP method. Expected result 1 is obtained.
 *    2. The input cmd is BSL_UIO_SET_PEER_IP_ADDR when BSL_UIO_Ctrl is invoked. Expected result 2 is obtained.
 *    3. The input cmd is BSL_UIO_GET_PEER_IP_ADDR when BSL_UIO_Ctrl is invoked. Expected result 3 is obtained.
 *    4. The input cmd is BSL_UIO_UDP_SET_CONNECTED when BSL_UIO_Ctrl is invoked. Expected result 3 is obtained.
 * @expect
 *    1. The UDP method is successfully created.
 *    2. Return BSL_SUCCESS
 *    3. Return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_UDP_API_TC001(void)
{
    BSL_UIO *uio = NULL;
    int ret;
    UIO_Addr peerAddr = { 0 };
    uint8_t ipv4[IP_V4_LEN] = {0x11, 0x22, 0x33, 0x44};
    peerAddr.addr.sa_family = AF_INET;
    ASSERT_TRUE(memcpy_s(peerAddr.addr.sa_data, sizeof(UIO_Addr), ipv4, IP_V4_LEN) == EOK);

    const BSL_UIO_Method *ori = BSL_UIO_UdpMethod();
    BSL_UIO_Method method = {0};
    memcpy_s(&method, sizeof(method), ori, sizeof(method));
    method.uioWrite = STUB_Write;
    method.uioRead = STUB_Read;

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_PEER_IP_ADDR, sizeof(peerAddr), &peerAddr);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    UIO_Addr getAddr = { 0 };
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_GET_PEER_IP_ADDR, sizeof(getAddr), &getAddr);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ASSERT_TRUE(memcmp(getAddr.addr.sa_data, ipv4, IP_V4_LEN) == 0);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_UDP_SET_CONNECTED, sizeof(peerAddr.addr), &peerAddr);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_UDP_SET_CONNECTED, 0, NULL);
    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_SCTP_API_TC001
 * @title  SCTP ctrl test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_SctpMethod to create a SCTP method. Expected result 1 is obtained.
 *    2. The input cmd is BSL_UIO_SET_PEER_IP_ADDR when BSL_UIO_Ctrl is invoked. Expected result 2 is obtained.
 *    3. The input cmd is BSL_UIO_GET_PEER_IP_ADDR when BSL_UIO_Ctrl is invoked. Expected result 3 is obtained.
 *    4. The input cmd is BSL_UIO_SCTP_SET_APP_STREAM_ID when BSL_UIO_Ctrl is invoked. Expected result 4 is obtained.
 * @expect
 *    1. The SCTP method is successfully created.
 *    2. Return BSL_SUCCESS
 *    3. Return BSL_SUCCESS
 *    4. Return BSL_SUCCESS
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_SCTP_API_TC001(void)
{
#ifndef HITLS_BSL_UIO_SCTP
    SKIP_TEST();
#else
    BSL_UIO *uio = NULL;
    int ret;
    uint8_t ipAddr[256] = {0};
    BSL_UIO_CtrlGetPeerIpAddrParam param = {ipAddr, sizeof(ipAddr)};
    uint8_t data[IP_ADDR_V4_LEN] = {0};
    uint16_t sendAppStreamId = 1;

    const BSL_UIO_Method *ori = BSL_UIO_SctpMethod();
    BSL_UIO_Method method = {0};
    memcpy(&method, ori, sizeof(method));
    method.uioWrite = STUB_Write;
    method.uioRead = STUB_Read;

    uio = BSL_UIO_New(&method);
    ASSERT_TRUE(uio != NULL);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_PEER_IP_ADDR, sizeof(data), data);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_GET_PEER_IP_ADDR, sizeof(param), &param);
    ASSERT_TRUE(ret == BSL_SUCCESS);

    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SCTP_SET_APP_STREAM_ID, sizeof(uint16_t), &sendAppStreamId);
    ASSERT_TRUE(ret == BSL_SUCCESS);
EXIT:
    BSL_UIO_Free(uio);
#endif
}
/* END_CASE */

/**
 * @test  SDV_BSL_UIO_BUFFER_RESET_TC001
 * @title  Buffer reset test
 * @precon  nan
 * @brief
 *    1. Call BSL_UIO_New to create a buffer uio named buffer. Expected result 1 is obtained.
 *    2. Call BSL_UIO_New to create a tcp uio named tcp. Expected result 2 is obtained.
 *    3. Append tcp to buffer. Expected result 3 is obtained.
 *    4. Write 2048-length data to the buffer uio. Expected result 4 is obtained.
 *    5. Call BSL_UIO_Ctrl and transfer the BSL_UIO_RESET parameter to reset the buffer uio. Expected result 5 is
 *       obtained.
 * @expect
 *    1. The buffer is successfully created.
 *    2. The tcp is successfully created.
 *    3. Return BSL_SUCCESS and the next uio of buffer is tcp.
 *    4. Return BSL_SUCCESS and writeLen is 2048.
 *    5. Return BSL_UIO_FAIL.
 */
/* BEGIN_CASE */
void SDV_BSL_UIO_BUFFER_RESET_TC001(void)
{
    BSL_UIO *buffer = BSL_UIO_New(BSL_UIO_BufferMethod());
    ASSERT_TRUE(buffer != NULL);
    BSL_UIO *tcp = BSL_UIO_New(BSL_UIO_TcpMethod());
    ASSERT_TRUE(tcp != NULL);

    int32_t ret = BSL_UIO_Append(buffer, tcp);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(BSL_UIO_Next(buffer) == tcp);
    ASSERT_TRUE(BSL_UIO_Next(tcp) == NULL);

    uint8_t buf[8192];
    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(buffer, buf, 2048, &writeLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(writeLen == 2048);

    ret = BSL_UIO_Ctrl(buffer, BSL_UIO_RESET, 0, NULL);
    ASSERT_TRUE(ret = BSL_UIO_FAIL);
EXIT:
    BSL_UIO_Free(buffer);
    BSL_UIO_Free(tcp);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_UIO_MEM_BASIC_TC001(void)
{
    TestMemInit();
    
    // Create memory UIO
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_TRUE(uio != NULL);
    
    // Test write operation
    const char testData[] = "Hello World";
    uint32_t writeLen = 0;
    int32_t ret = BSL_UIO_Write(uio, testData, strlen(testData), &writeLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(writeLen == strlen(testData));
    
    // Test read operation
    char readBuf[20] = {0};
    uint32_t readLen = 0;
    ret = BSL_UIO_Read(uio, readBuf, sizeof(readBuf), &readLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(readLen == strlen(testData));
    ASSERT_TRUE(memcmp(readBuf, testData, readLen) == 0);
    
    // Test pending data length
    int64_t pendingLen = 0;
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_PENDING, sizeof(size_t), &pendingLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(pendingLen == 0); // All data has been read

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_UIO_MEM_NEW_BUF_TC001(void)
{
    TestMemInit();
    
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_TRUE(uio != NULL);
    
    // Test MemNewBuf with invalid parameters
    int32_t ret = BSL_UIO_Ctrl(uio, BSL_UIO_MEM_NEW_BUF, -1, NULL);
    ASSERT_TRUE(ret == BSL_NULL_INPUT);
    
    // Test MemNewBuf with valid parameters
    char testBuf[] = "Test Buffer";
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_MEM_NEW_BUF, strlen(testBuf), testBuf);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    
    // Verify buffer is in read-only mode
    uint32_t writeLen = 0;
    ret = BSL_UIO_Write(uio, "data", 4, &writeLen);
    ASSERT_TRUE(ret == BSL_UIO_WRITE_NOT_ALLOWED);
    
    // Test reading from new buffer
    char readBuf[20] = {0};
    uint32_t readLen = 0;
    ret = BSL_UIO_Read(uio, readBuf, sizeof(readBuf), &readLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(readLen == strlen(testBuf));
    ASSERT_TRUE(memcmp(readBuf, testBuf, readLen) == 0);
EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_UIO_MEM_EOF_TC001(void)
{
    TestMemInit();
    
    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_MemMethod());
    ASSERT_TRUE(uio != NULL);
    
    // Test setting EOF behavior
    int32_t eofValue = 1;
    int32_t ret = BSL_UIO_Ctrl(uio, BSL_UIO_MEM_SET_EOF, sizeof(int32_t), &eofValue);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    
    // Verify EOF value
    int32_t readEof = 0;
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_MEM_GET_EOF, sizeof(int32_t), &readEof);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(readEof == eofValue);
    
    // Test read behavior with EOF set
    char readBuf[10];
    uint32_t readLen = 0;
    ret = BSL_UIO_Read(uio, readBuf, sizeof(readBuf), &readLen);
    ASSERT_TRUE(ret == BSL_SUCCESS);
    ASSERT_TRUE(readLen == 0);
    
    // Verify retry flag is set due to EOF
    uint32_t flags = 0;
    BSL_UIO_TestFlags(uio, BSL_UIO_FLAGS_SHOULD_RETRY, &flags);
    ASSERT_TRUE((flags & BSL_UIO_FLAGS_SHOULD_RETRY) != 0);

EXIT:
    BSL_UIO_Free(uio);
}
/* END_CASE */
