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
#include <string.h>
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls.h"
#include "hlt.h"
#include "hs.h"
#include "hs_ctx.h"
#include "session_type.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "simulate_io.h"
#include "record.h"
#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
#include "bsl_async.h"
#endif

/*
 * The simulated link holds a single message, so a second record cannot be sent until the peer takes the
 * first one. That naturally produces HITLS_REC_NORMAL_IO_BUSY in the middle of a multi record write.
 */
#define TEST_REC_LIMIT 100u

static void InitWriteData(uint8_t *buf, uint32_t len, uint8_t seed)
{
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i);
    }
}

/*
 * After a fatal retry check the connection is terminated. Keep reading what was already committed and keep
 * writing until the fatal alert has been processed, so the caller sees HITLS_CM_LINK_FATAL_ALERTED.
 */
static int32_t DrainUntilAlerted(FRAME_LinkObj *server, FRAME_LinkObj *client, const uint8_t *wbuf, uint32_t wlen,
                                 uint8_t *rbuf, uint32_t rbufSize, uint32_t *totalRead)
{
    int32_t ret = HITLS_SUCCESS;
    *totalRead = 0;
    for (uint32_t i = 0; i < 8 && ret != HITLS_CM_LINK_FATAL_ALERTED; i++) {
        uint32_t rd = 0;
        FRAME_TrasferMsgBetweenLink(server, client);
        if (*totalRead < rbufSize &&
            HITLS_Read(client->ssl, rbuf + *totalRead, rbufSize - *totalRead, &rd) == HITLS_SUCCESS) {
            *totalRead += rd;
        }
        uint32_t n = 0;
        ret = HITLS_Write(server->ssl, wbuf, wlen, &n);
    }
    return ret;
}
/* END_HEADER */

/* @
* @test SDV_HiTLS_WriteMode_TC001
* @spec -
* @title Partial write is the default, full write is selected by clearing the mode bit.
* @precon nan
* @brief
* 1. A fresh config must contain HITLS_MODE_ENABLE_PARTIAL_WRITE.
* 2. Clear the bit on both ends, set record_size_limit to 100 and establish a link.
* 3. The server writes 200 bytes: the first record goes out, the second one blocks.
* 4. The server retries with the same parameters after the peer takes the first record.
* @expect
* 1. HITLS_REC_NORMAL_IO_BUSY with writeLen 0 for the first call.
* 2. HITLS_SUCCESS with writeLen 200 for the retry, the client receives all 200 bytes.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC001(void)
{
    HITLS_Config *check_config = NULL;
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    check_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(check_config != NULL);
    uint32_t mode = 0;
    ASSERT_EQ(HITLS_CFG_GetModeSupport(check_config, &mode), HITLS_SUCCESS);
    ASSERT_TRUE((mode & HITLS_MODE_ENABLE_PARTIAL_WRITE) != 0);

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[200] = {0};
    uint8_t rbuf[200] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 1);

    uint32_t outLen = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, TEST_REC_LIMIT);

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, sizeof(wbuf));

    uint32_t readLen2 = 0;
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + readLen, sizeof(rbuf) - readLen, &readLen2), HITLS_SUCCESS);
    ASSERT_EQ(readLen + readLen2, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(check_config);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC002
* @spec -
* @title Full write keeps the progress across several IO busy rounds.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 250 bytes, which needs three records, and retries with the same parameters each
*    time the peer has taken one record.
* @expect
* 1. The first two calls return HITLS_REC_NORMAL_IO_BUSY with writeLen 0.
* 2. The third call returns HITLS_SUCCESS with writeLen 250, the client receives 100+100+50 bytes in order.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC002(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[250] = {0};
    uint8_t rbuf[250] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 2);

    uint32_t outLen = 0;
    uint32_t totalRead = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, TEST_REC_LIMIT);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, TEST_REC_LIMIT);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, sizeof(wbuf));

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    totalRead += readLen;
    ASSERT_EQ(totalRead, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC003
* @spec -
* @title The very first record of a full write blocks, so nothing is reported yet.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 100 bytes and leaves them in the send buffer.
* 3. The server writes another 200 bytes; its first record cannot be sent.
* 4. The server retries with the same parameters after every hand over.
* @expect
* 1. The second write returns HITLS_REC_NORMAL_IO_BUSY with writeLen 0 even though nothing was sent.
* 2. The retries finally return HITLS_SUCCESS with writeLen 200 and the client receives 300 bytes.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC003(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[300] = {0};
    uint8_t rbuf[300] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 3);

    uint32_t outLen = 0;
    uint32_t totalRead = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, TEST_REC_LIMIT, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, TEST_REC_LIMIT);

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + TEST_REC_LIMIT, sizeof(wbuf) - TEST_REC_LIMIT, &outLen),
        HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + TEST_REC_LIMIT, sizeof(wbuf) - TEST_REC_LIMIT, &outLen),
        HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + TEST_REC_LIMIT, sizeof(wbuf) - TEST_REC_LIMIT, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, sizeof(wbuf) - TEST_REC_LIMIT);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    totalRead += readLen;
    ASSERT_EQ(totalRead, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC004
* @spec -
* @title A retry with a shorter length is accepted as long as it covers what was sent and what is pending.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 250 bytes and gets IO busy with 100 sent and 100 pending.
* 3. After the peer takes the first record the server retries with dataLen 200 and reports success.
* @expect
* 1. The retry returns HITLS_SUCCESS with writeLen 200.
* 2. The client receives exactly the first 200 bytes of the buffer.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC004(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[250] = {0};
    uint8_t rbuf[250] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 4);

    uint32_t outLen = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, TEST_REC_LIMIT);

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, 200, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, 200);

    uint32_t readLen2 = 0;
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + readLen, sizeof(rbuf) - readLen, &readLen2), HITLS_SUCCESS);
    ASSERT_EQ(readLen + readLen2, 200);
    ASSERT_EQ(memcmp(wbuf, rbuf, 200), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC005
* @spec -
* @title A retry that cannot cover the bytes already sent and the pending record is fatal.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 250 bytes and gets IO busy with 100 sent and 100 pending.
* 3. The server retries with a length that is shorter than 100 + 100.
* @expect
* 1. The retry returns HITLS_APP_ERR_WRITE_BAD_RETRY with writeLen 0 and the connection is terminated.
* 2. The client only receives the 200 bytes that were already committed, then writes report
*    HITLS_CM_LINK_FATAL_ALERTED.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC005(int retryLen)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[250] = {0};
    uint8_t rbuf[250] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 5);

    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, (uint32_t)retryLen, &outLen), HITLS_APP_ERR_WRITE_BAD_RETRY);
    ASSERT_EQ(outLen, 0);

    uint32_t totalRead = 0;
    ASSERT_EQ(DrainUntilAlerted(server, client, wbuf, sizeof(wbuf), rbuf, sizeof(rbuf), &totalRead),
        HITLS_CM_LINK_FATAL_ALERTED);
    ASSERT_EQ(totalRead, 200);
    ASSERT_EQ(memcmp(wbuf, rbuf, 200), 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC006
* @spec -
* @title A retry with a longer length writes the extra data once the pending record is out.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 150 and establish a link.
* 2. The server writes 250 bytes and gets IO busy with 150 sent and 100 pending.
* 3. The server retries with dataLen 300.
* @expect
* 1. The retry ends with HITLS_SUCCESS and writeLen 300.
* 2. The client receives 150 + 100 + 50 bytes in order.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC006(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, 150) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, 150) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[300] = {0};
    uint8_t rbuf[300] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 6);

    uint32_t outLen = 0;
    uint32_t totalRead = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, 250, &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, 150);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, 100);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, sizeof(wbuf));

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, 50);
    totalRead += readLen;
    ASSERT_EQ(totalRead, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC007
* @spec -
* @title Retrying a full write with another buffer is rejected instead of mixing the streams.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 250 bytes and gets IO busy with 100 sent and 100 pending.
* 3. The server retries with a different buffer and a length that satisfies the length check.
* @expect
* 1. The retry does not report success and the connection is terminated.
* 2. The client only receives the 200 committed bytes of the first buffer, none of the new one.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC007(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[250] = {0};
    uint8_t other[350] = {0};
    uint8_t rbuf[250] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 7);
    memset(other, 0xFF, sizeof(other));

    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    outLen = 0;
    ASSERT_TRUE(HITLS_Write(server->ssl, other, sizeof(other), &outLen) != HITLS_SUCCESS);
    ASSERT_EQ(outLen, 0);

    uint32_t totalRead = 0;
    ASSERT_EQ(DrainUntilAlerted(server, client, other, sizeof(other), rbuf, sizeof(rbuf), &totalRead),
        HITLS_CM_LINK_FATAL_ALERTED);
    ASSERT_EQ(totalRead, 200);
    ASSERT_EQ(memcmp(wbuf, rbuf, 200), 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC008
* @spec -
* @title HITLS_Flush is rejected in full write mode and does not send anything.
* @precon nan
* @brief
* 1. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. Call HITLS_Flush on an idle connection, then make the write busy and call it again.
* 3. Retry the write with the same parameters.
* @expect
* 1. Both HITLS_Flush calls return HITLS_CONFIG_UNSUPPORT and the pending ciphertext stays untouched.
* 2. The retry returns HITLS_SUCCESS with writeLen 200 and the client receives the whole message.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC008(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[200] = {0};
    uint8_t rbuf[200] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 8);

    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_CONFIG_UNSUPPORT);
    TestErrClear();

    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    uint32_t pendingBefore = 0;
    ASSERT_EQ(HITLS_GetOutPendingSize(server->ssl, &pendingBefore), HITLS_SUCCESS);
    ASSERT_TRUE(pendingBefore > 0);

    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_CONFIG_UNSUPPORT);
    TestErrClear();

    uint32_t pendingAfter = 0;
    ASSERT_EQ(HITLS_GetOutPendingSize(server->ssl, &pendingAfter), HITLS_SUCCESS);
    ASSERT_EQ(pendingAfter, pendingBefore);

    uint32_t readLen = 0;
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, TEST_REC_LIMIT);

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, sizeof(wbuf));

    uint32_t readLen2 = 0;
    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + readLen, sizeof(rbuf) - readLen, &readLen2), HITLS_SUCCESS);
    ASSERT_EQ(readLen + readLen2, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC009
* @spec -
* @title Partial write keeps the mbedtls semantics: a successful flush commits the pending record.
* @precon nan
* @brief
* 1. Keep HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100 and establish a link.
* 2. The server writes 100 bytes and then another 100 bytes, the second one cannot be sent.
* 3. HITLS_Flush is called while the link is busy and again after the peer took a record.
* 4. The server continues with the remaining 100 bytes from an advanced buffer.
* @expect
* 1. The first HITLS_Flush returns HITLS_REC_NORMAL_IO_BUSY, the second one HITLS_SUCCESS.
* 2. The client receives 300 bytes in order, no record is sent twice.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC009(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[300] = {0};
    uint8_t rbuf[300] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 9);

    uint32_t outLen = 0;
    uint32_t totalRead = 0;
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, TEST_REC_LIMIT, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, TEST_REC_LIMIT);

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + TEST_REC_LIMIT, TEST_REC_LIMIT, &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_REC_NORMAL_IO_BUSY);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf, sizeof(rbuf), &readLen), HITLS_SUCCESS);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_SUCCESS);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    totalRead += readLen;

    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + 2 * TEST_REC_LIMIT, TEST_REC_LIMIT, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(outLen, TEST_REC_LIMIT);

    FRAME_TrasferMsgBetweenLink(server, client);
    ASSERT_EQ(HITLS_Read(client->ssl, rbuf + totalRead, sizeof(rbuf) - totalRead, &readLen), HITLS_SUCCESS);
    totalRead += readLen;
    ASSERT_EQ(totalRead, sizeof(wbuf));
    ASSERT_EQ(memcmp(wbuf, rbuf, sizeof(wbuf)), 0);

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC010
* @spec -
* @title HITLS_Flush validates its parameters, the async state and the write mode.
* @precon nan
* @brief
* 1. Call HITLS_Flush with a NULL context, then with a context whose record context is not created yet.
* 2. Establish a TLS 1.2 link, clear HITLS_MODE_ENABLE_PARTIAL_WRITE and call HITLS_Flush.
* 3. Assume an outstanding async task (async builds only) and call HITLS_Flush again.
* @expect
* 1. HITLS_NULL_INPUT for both invalid contexts, no error is pushed.
* 2. HITLS_CONFIG_UNSUPPORT on a stream connection in full write mode.
* 3. HITLS_ASYNC_ERR_OPERATION_BUSY, which is checked before the write mode is looked at.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC010(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    HITLS_Ctx *rawCtx = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    ASSERT_EQ(HITLS_Flush(NULL), HITLS_NULL_INPUT);

    FRAME_Init();
    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    /* The record context is created on the first handshake, so an idle context reports the same NULL input. */
    rawCtx = HITLS_New(c_config);
    ASSERT_TRUE(rawCtx != NULL);
    ASSERT_EQ(HITLS_Flush(rawCtx), HITLS_NULL_INPUT);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_CONFIG_UNSUPPORT);
    TestErrClear();

#ifdef HITLS_TLS_FEATURE_MODE_ASYNC
    /* HITLS_Flush rejects an outstanding task before it looks at the write mode. Only the pointer is compared
     * against NULL, so a fake task is enough; it is restored before the connection is released. */
    BSL_ASYNC_Task *savedTask = server->ssl->asyncTask;
    server->ssl->asyncTask = (BSL_ASYNC_Task *)server->ssl;
    ASSERT_EQ(HITLS_Flush(server->ssl), HITLS_ASYNC_ERR_OPERATION_BUSY);
    TestErrClear();
    server->ssl->asyncTask = savedTask;
#endif

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    HITLS_Free(rawCtx);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC011
* @spec -
* @title A full write interrupted by a scheduled KeyUpdate rejects a retry with another buffer.
* @precon nan
* @brief
* 1. Enable the automatic KeyUpdate, clear HITLS_MODE_ENABLE_PARTIAL_WRITE, set record_size_limit to 100,
*    establish a TLS 1.3 link and put the write sequence number at the encryption limit.
* 2. The server writes 300 bytes: the first record is sent, the KeyUpdate that the record schedules cannot
*    be sent, so the call returns busy with no pending record but 100 bytes already sent.
* 3. The server retries with a different buffer.
* @expect
* 1. HITLS_REC_NORMAL_IO_BUSY with writeLen 0 for the first call.
* 2. HITLS_APP_ERR_WRITE_BAD_RETRY with writeLen 0, the two streams are never mixed.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC011(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    FRAME_Init();
    c_config = HITLS_CFG_NewTLS13Config();
    s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetAutoKeyUpdateSupport(c_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetAutoKeyUpdateSupport(s_config, true) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    /* The record size limit cannot be negotiated that small for TLS 1.3 (the handshake records do not fit),
     * so shrink the send limit after the handshake, and put the write sequence number at the encryption limit
     * so that the next record schedules an automatic KeyUpdate. */
    server->ssl->negotiatedInfo.recordSizeLimit = TEST_REC_LIMIT;
    server->ssl->negotiatedInfo.peerRecordSizeLimit = TEST_REC_LIMIT;
    REC_Ctx *recCtx = (REC_Ctx *)server->ssl->recCtx;
    RecConnSetSeqNum(recCtx->writeStates.currentState, REC_MAX_AES_GCM_ENCRYPTION_LIMIT - 1);

    uint8_t wbuf[300] = {0};
    uint8_t other[250] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 11);
    memset(other, 0xFF, sizeof(other));

    /* One record is sent, the KeyUpdate cannot follow it, so nothing is pending while 100 bytes are done. */
    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, sizeof(wbuf), &outLen), HITLS_REC_NORMAL_IO_BUSY);
    ASSERT_EQ(outLen, 0);

    /* The peer takes the first record, so the retry can drive the scheduled KeyUpdate to completion and then
     * reach the write path, where the moved buffer must be rejected. */
    FRAME_TrasferMsgBetweenLink(server, client);

    /* The record layer no longer sees a pending record, the context must still reject the moved buffer. */
    outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, other, sizeof(other), &outLen), HITLS_APP_ERR_WRITE_BAD_RETRY);
    ASSERT_EQ(outLen, 0);
    TestErrClear();

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test SDV_HiTLS_WriteMode_TC012
* @spec -
* @title Only an actual partial write mode change is rejected while a write is in progress.
* @precon nan
* @brief
* 1. Partial write is on by default. Make a write busy so that a record is pending, then repeat the already
*    set bit, add it together with an unrelated bit, and finally clear it.
* 2. Clear HITLS_MODE_ENABLE_PARTIAL_WRITE, make a full write busy, then clear the already cleared bit and
*    finally enable it.
* @expect
* 1. Repeating the set bit and the mask that only adds the unrelated bit succeed; clearing it fails with
*    HITLS_MSG_HANDLE_STATE_ILLEGAL.
* 2. Clearing the already cleared bit succeeds; enabling it fails with HITLS_MSG_HANDLE_STATE_ILLEGAL.
* @prior Level 1
* @auto TRUE
@ */
/* BEGIN_CASE */
void SDV_HiTLS_WriteMode_TC012(void)
{
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    HITLS_Config *c_config2 = NULL;
    HITLS_Config *s_config2 = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    FRAME_LinkObj *client2 = NULL;
    FRAME_LinkObj *server2 = NULL;

    FRAME_Init();

    /* Partial write mode (the default) with a record still pending. */
    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config, TEST_REC_LIMIT) == HITLS_SUCCESS);
    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    uint8_t wbuf[300] = {0};
    InitWriteData(wbuf, sizeof(wbuf), 12);
    uint32_t outLen = 0;
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf, TEST_REC_LIMIT, &outLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Write(server->ssl, wbuf + TEST_REC_LIMIT, TEST_REC_LIMIT, &outLen), HITLS_REC_NORMAL_IO_BUSY);

    /* The bit is already set, so these calls do not switch the mode: they must be accepted, including the
     * mask that also adds an unrelated bit. */
    ASSERT_EQ(HITLS_SetModeSupport(server->ssl, HITLS_MODE_ENABLE_PARTIAL_WRITE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetModeSupport(server->ssl,
        HITLS_MODE_ENABLE_PARTIAL_WRITE | HITLS_MODE_ACCEPT_MOVING_WRITE_BUFFER), HITLS_SUCCESS);
    /* Removing it would switch to the full write semantics with a record still pending. */
    ASSERT_EQ(HITLS_ClearModeSupport(server->ssl, HITLS_MODE_ENABLE_PARTIAL_WRITE), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    TestErrClear();

    /* Full write mode with progress made, so the bit is already clear. */
    c_config2 = HITLS_CFG_NewTLS12Config();
    s_config2 = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config2 != NULL);
    ASSERT_TRUE(s_config2 != NULL);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(c_config2, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_SetRecordSizeLimit(s_config2, TEST_REC_LIMIT) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(c_config2, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    ASSERT_TRUE(HITLS_CFG_ClearModeSupport(s_config2, HITLS_MODE_ENABLE_PARTIAL_WRITE) == HITLS_SUCCESS);
    client2 = FRAME_CreateLink(c_config2, BSL_UIO_TCP);
    ASSERT_TRUE(client2 != NULL);
    server2 = FRAME_CreateLink(s_config2, BSL_UIO_TCP);
    ASSERT_TRUE(server2 != NULL);
    ASSERT_TRUE(FRAME_CreateConnection(client2, server2, true, HS_STATE_BUTT) == HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Write(server2->ssl, wbuf, 250, &outLen), HITLS_REC_NORMAL_IO_BUSY);

    /* Clearing an already cleared bit does not switch the mode. */
    ASSERT_EQ(HITLS_ClearModeSupport(server2->ssl, HITLS_MODE_ENABLE_PARTIAL_WRITE), HITLS_SUCCESS);
    /* Enabling it would switch the mode with a full write still in progress. */
    ASSERT_EQ(HITLS_SetModeSupport(server2->ssl, HITLS_MODE_ENABLE_PARTIAL_WRITE), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    TestErrClear();

    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    HITLS_CFG_FreeConfig(c_config2);
    HITLS_CFG_FreeConfig(s_config2);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    FRAME_FreeLink(client2);
    FRAME_FreeLink(server2);
}
/* END_CASE */
