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

/* INCLUDE_BASE ../consistency/tls12/test_suite_tls12_consistency_rfc5246_malformed_msg */
/* BEGIN_HEADER */

#include "securec.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "tls.h"
#include "bsl_uio.h"
#include "rec.h"
#include "crypt.h"
#include "rec_conn.h"
#include "record.h"
#include "bsl_uio.h"
#include "hitls.h"
#include "frame_tls.h"
#include "cert_callback.h"
/* END_HEADER */

/* UserData structure transferred from the server to the alpnCb callback */

static uint8_t S_parsedList[100];
static uint32_t S_parsedListLen;
static TlsAlpnExtCtx alpnServerCtx = {0};

static uint8_t C_parsedList[100];
static uint32_t C_parsedListLen;

static int32_t ConfigAlpn(HITLS_Config *tlsConfig, char *AlpnList, bool isCient)
{

    int32_t ret;
    char defaultAlpnList[] = "http/1.1,spdy/1,spdy/2,spdy/3";
    char *pAlpnList = NULL;
    uint32_t AlpnListLen = 0;
    if (AlpnList != NULL){
        pAlpnList = AlpnList;
        AlpnListLen = strlen(pAlpnList);
    } else {
        pAlpnList = defaultAlpnList;
        AlpnListLen = strlen(pAlpnList);
    }

    /* client set alpn */
    if (isCient) {
        ret = ExampleAlpnParseProtocolList(C_parsedList, &C_parsedListLen, (uint8_t *)pAlpnList, AlpnListLen);
        ASSERT_EQ(ret, HITLS_SUCCESS);
        ret = HITLS_CFG_SetAlpnProtos(tlsConfig, C_parsedList, C_parsedListLen);
        ASSERT_EQ(ret, HITLS_SUCCESS);
    /* server set alpn and alpnSelectCb */
    } else {
        ret = ExampleAlpnParseProtocolList(S_parsedList, &S_parsedListLen, (uint8_t *)pAlpnList, AlpnListLen);
        ASSERT_EQ(ret, HITLS_SUCCESS);
        alpnServerCtx = (TlsAlpnExtCtx){ S_parsedList, S_parsedListLen };
        ret = HITLS_CFG_SetAlpnProtosSelectCb(tlsConfig, ExampleAlpnCbForLlt, &alpnServerCtx);
        ASSERT_EQ(ret, HITLS_SUCCESS);
    }
EXIT:
    return ret;
}

/**
 * @test UT_TLS_ALPN_PARSE_PROTO_FUNC_TC001
 * @title  ALPN function test
 * @precon  nan
 * @brief   server set alpn and alpn callback，client set alpn. The server supports the protocol configured on
            the client .Expect result 1
 * @expect  1. server returns the protocol supported by the client
*/
/* BEGIN_CASE */
void UT_TLS_ALPN_PARSE_PROTO_FUNC_TC001(int version)
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *s_config = NULL;
    HITLS_Config *c_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    if (version == HITLS_VERSION_TLS12) {
        c_config = HITLS_CFG_NewTLS12Config();
        s_config = HITLS_CFG_NewTLS12Config();
    } else if (version == HITLS_VERSION_TLS13) {
        c_config = HITLS_CFG_NewTLS13Config();
        s_config = HITLS_CFG_NewTLS13Config();
    }
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    uint16_t signAlgs[] = {CERT_SIG_SCHEME_RSA_PKCS1_SHA256, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256};
    HITLS_CFG_SetGroups(c_config, groups, sizeof(groups) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(c_config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));

    HITLS_CFG_SetGroups(s_config, groups, sizeof(groups) / sizeof(uint16_t));
    HITLS_CFG_SetSignature(s_config, signAlgs, sizeof(signAlgs) / sizeof(uint16_t));
    ConfigAlpn(s_config, NULL, false);
    ConfigAlpn(c_config, NULL, true);

    client = FRAME_CreateLink(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);

    server = FRAME_CreateLink(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    int32_t ret;
    ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_SUCCESS);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_Ctx *serverTlsCtx = FRAME_GetTlsCtx(server);

    uint8_t *clientAlpnProtosname = NULL;
    uint32_t clientAlpnProtosnameLen = 0;
    HITLS_GetSelectedAlpnProto(clientTlsCtx, &clientAlpnProtosname, &clientAlpnProtosnameLen);
    ASSERT_TRUE(memcmp(clientAlpnProtosname, "http/1.1", 8) == 0);
    ASSERT_TRUE(clientAlpnProtosnameLen == 8);

    uint8_t *serverAlpnProtosname = NULL;
    uint32_t serverAlpnProtosnameLen = 0;
    HITLS_GetSelectedAlpnProto(serverTlsCtx, &serverAlpnProtosname, &serverAlpnProtosnameLen);
    ASSERT_TRUE(memcmp(serverAlpnProtosname, "http/1.1", 8) == 0);
    ASSERT_TRUE(serverAlpnProtosnameLen == 8);

EXIT:
    HITLS_CFG_FreeConfig(s_config);
    HITLS_CFG_FreeConfig(c_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/**
 * @test UT_TLS_ALPN_SELECT_FUNC_TC001
 * @title  HITLS_SelectAlpnProtocol function test
 * @precon  nan
 * @brief  server set alpn, client set alpn. The server supports the protocol configured on the client .Expect result 1.
 * @expect  1. cmp out with "http/1.1", outLen is 8.
*/
/* BEGIN_CASE */
void UT_TLS_ALPN_SELECT_FUNC_TC001()
{
    const char *clientAlpnList = "\x06spdy/3\x08http/1.1";
    const char *serverAlpnList = "\x08http/1.1\x06spdy/3";
    uint8_t *out = NULL;
    uint8_t outLen = 0;

    int32_t ret = HITLS_SelectAlpnProtocol(&out, &outLen, (const uint8_t *)serverAlpnList, strlen(serverAlpnList),
        (const uint8_t *)clientAlpnList, strlen(clientAlpnList));
    ASSERT_EQ(ret, HITLS_SUCCESS);
    ASSERT_EQ(outLen, 8);
    ASSERT_TRUE(memcmp(out, "http/1.1", 8) == 0);

EXIT:
    return;
}
/* END_CASE */

/**
 * @test UT_TLS_ALPN_SELECT_FUNC_TC002
 * @title  HITLS_SelectAlpnProtocol function test
 * @precon  nan
 * @brief  server set alpn, client set alpn. The server supports the protocol configured on the client .Expect result 1.
 * @expect  1. cmp out with "http/1.1", outLen is 8.
*/
/* BEGIN_CASE */
void UT_TLS_ALPN_SELECT_FUNC_TC002(
    int serverAlpnLen, Hex *serverAlpnList, int clientAlpnLen, Hex *clientAlpnList, int expectedRet, Hex *expectedOut)
{
    uint8_t *out = NULL;
    uint8_t outLen = 0;
    uint8_t *tempClientAlpn = clientAlpnList->x;
    uint32_t tempClientAlpnLen = clientAlpnLen;
    uint8_t *tempServerAlpn = serverAlpnList->x;
    uint32_t tempServerAlpnLen = serverAlpnLen;

    if (serverAlpnLen == -1) {
        tempServerAlpn = NULL;
        tempServerAlpnLen = 0;
    }
    if (clientAlpnLen == -1) {
        tempClientAlpn = NULL;
        tempClientAlpnLen = 0;
    }

    int32_t ret = HITLS_SelectAlpnProtocol(&out, &outLen, (const uint8_t *)tempServerAlpn, tempServerAlpnLen,
        (const uint8_t *)tempClientAlpn, tempClientAlpnLen);
    ASSERT_EQ(ret, expectedRet);
    ASSERT_EQ(outLen, expectedOut->len);
    ASSERT_TRUE(memcmp(out, expectedOut->x, expectedOut->len) == 0);

EXIT:
    return;
}
/* END_CASE */

