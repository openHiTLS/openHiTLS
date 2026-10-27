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
#include "hlt.h"
#include "logger.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_status_request.h"
#include "hitls_pki_cert.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_errno.h"
#include "frame_tls.h"
#include "frame_link.h"
#include "frame_io.h"
#include "cert_callback.h"
#include "bsl_list.h"
#include "bsl_sal.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_msg.h"
#include "hs_extensions.h"
#include "hitls_session.h"
int32_t ParseCertEntryOcspStatus(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint32_t chainidx);
int32_t CheckCertificateStatusType(TLS_Ctx *ctx, const HS_MsgType msgType);
int32_t ClientRecvCertificateStatus(TLS_Ctx *ctx, const HS_Msg *hsMsg);
/* END_HEADER */

/* Certificate chain + OCSP responses for the stapling tests. The server uses
 * "server" (EE, issued by "inter"); responses carry a CertID matching the EE
 * and the intermediate so both single- and multi-response scenarios work. */
#define STAPLING_CERTS_PATH "../testdata/tls/certificate/der/ocsp_stapling/"

static int32_t g_statusCbCount = 0;
static int32_t g_statusCbCtxCount = 0;
static HITLS_CERT_OcspResp **g_serverList = NULL;
static BSL_Buffer g_rsaSerial = {0}; /* serial of the RSA EE certificate, for ServerStaplingCbSelective */

static void FreeOcspRespArray(HITLS_CERT_OcspResp **arr)
{
    if (arr == NULL) {
        return;
    }
    for (uint32_t i = 0; arr[i] != NULL; i++) {
        HITLS_OCSP_RespFree((HITLS_OCSP_Resp *)arr[i]);
    }
    BSL_SAL_Free(arr);
}

static void TestSendAlert(const TLS_Ctx *ctx, ALERT_Level level, ALERT_Description description)
{
    (void)ctx;
    (void)level;
    (void)description;
}

/* Load one DER OCSP response from a file into an array (single entry + trailing
 * NULL that terminates FreeOcspRespArray's scan). */
static HITLS_CERT_OcspResp **CreateOcspRespArrayFromFile(const char *file)
{
    FILE *fp = fopen(file, "rb");
    if (fp == NULL) {
        return NULL;
    }
    (void)fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    (void)fseek(fp, 0, SEEK_SET);
    if (len <= 0 || len >= (1 << 24)) {
        (void)fclose(fp);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)BSL_SAL_Malloc((uint32_t)len);
    if (buf == NULL || fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        BSL_SAL_FREE(buf);
        (void)fclose(fp);
        return NULL;
    }
    (void)fclose(fp);
    HITLS_CERT_OcspResp **arr = (HITLS_CERT_OcspResp **)BSL_SAL_Calloc(2, sizeof(HITLS_CERT_OcspResp *));
    if (arr == NULL) {
        BSL_SAL_FREE(buf);
        return NULL;
    }
    BSL_Buffer encode = {buf, (uint32_t)len};
    HITLS_OCSP_Resp *pkiResp = NULL;
    if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &encode, &pkiResp) != HITLS_PKI_SUCCESS || pkiResp == NULL) {
        BSL_SAL_FREE(buf);
        BSL_SAL_Free(arr);
        return NULL;
    }
    arr[0] = (HITLS_CERT_OcspResp *)pkiResp;
    BSL_SAL_FREE(buf);
    return arr;
}

/* Build an array of two OCSP responses (EE + intermediate) for multi-response
 * TLS 1.3 scenarios. */
static HITLS_CERT_OcspResp **CreateTwoOcspRespArray(void)
{
    HITLS_CERT_OcspResp **arr = (HITLS_CERT_OcspResp **)BSL_SAL_Calloc(3, sizeof(HITLS_CERT_OcspResp *));
    if (arr == NULL) {
        return NULL;
    }
    const char *files[2] = {STAPLING_CERTS_PATH "ee_ocsp_signer.der", STAPLING_CERTS_PATH "inter_ocsp.der"};
    for (uint32_t i = 0; i < 2; i++) {
        HITLS_CERT_OcspResp **one = CreateOcspRespArrayFromFile(files[i]);
        if (one == NULL) {
            FreeOcspRespArray(arr);
            return NULL;
        }
        arr[i] = one[0];
        BSL_SAL_Free(one);
    }
    return arr;
}

/* Create the OCSP response array for the EE certificate (issuer-signed). */
static HITLS_CERT_OcspResp **CreateOcspRespArray(void)
{
    return CreateOcspRespArrayFromFile(STAPLING_CERTS_PATH "ee_ocsp_issuer.der");
}

/* RSA variant used by the RSA-key-exchange TLS 1.2 state-machine test. */
static HITLS_CERT_OcspResp **CreateRsaOcspRespArray(void)
{
    return CreateOcspRespArrayFromFile(STAPLING_CERTS_PATH "rsa_ee_ocsp.der");
}

/* Configure the RSA server certificate chain (root/inter trusted, RSA EE loaded). */
static void LoadRsaStaplingCerts(HITLS_Config *config, bool isServer)
{
    if (isServer) {
        (void)HITLS_CFG_LoadCertFile(config, STAPLING_CERTS_PATH "rsa_server.der", TLS_PARSE_FORMAT_ASN1);
        (void)HITLS_CFG_LoadKeyFile(config, STAPLING_CERTS_PATH "rsa_server.key.der", TLS_PARSE_FORMAT_ASN1);
    }
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    (void)HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, STAPLING_CERTS_PATH "root.der", &root);
    (void)HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, STAPLING_CERTS_PATH "inter.der", &inter);
    if (root != NULL) {
        (void)HITLS_CFG_AddCertToStore(config, root, TLS_CERT_STORE_TYPE_DEFAULT, true);
        HITLS_X509_CertFree(root);
    }
    if (inter != NULL) {
        (void)HITLS_CFG_AddCertToStore(config, inter, TLS_CERT_STORE_TYPE_DEFAULT, true);
        HITLS_X509_CertFree(inter);
    }
}

/* Configure the OCSP stapling certificate chain on a link config: a server
 * loads the new EE certificate and private key, and both sides trust the new
 * root/intermediate CA. */
static void LoadStaplingCerts(HITLS_Config *config, bool isServer)
{
    if (isServer) {
        (void)HITLS_CFG_LoadCertFile(config, STAPLING_CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
        (void)HITLS_CFG_LoadKeyFile(config, STAPLING_CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);
    }
    HITLS_X509_Cert *root = NULL;
    HITLS_X509_Cert *inter = NULL;
    (void)HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, STAPLING_CERTS_PATH "root.der", &root);
    (void)HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, STAPLING_CERTS_PATH "inter.der", &inter);
    if (root != NULL) {
        (void)HITLS_CFG_AddCertToStore(config, root, TLS_CERT_STORE_TYPE_DEFAULT, true);
        HITLS_X509_CertFree(root);
    }
    if (inter != NULL) {
        (void)HITLS_CFG_AddCertToStore(config, inter, TLS_CERT_STORE_TYPE_DEFAULT, true);
        HITLS_X509_CertFree(inter);
    }
}

static int32_t ClientStatusCb(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    (void)arg;
    g_statusCbCount++;
    return HITLS_SUCCESS;
}

static int32_t ClientStatusCbCtx(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    (void)arg;
    g_statusCbCtxCount++;
    return HITLS_SUCCESS;
}

static int32_t ClientStatusCbBadResp(HITLS_Ctx *ctx, void *arg)
{
    (void)ctx;
    (void)arg;
    return HITLS_STATUS_REJECT;
}

static int32_t ServerStaplingCbSkip(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                    HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)outResp;
    (void)arg;
    return HITLS_STAPLING_SKIP;
}

static int32_t ServerStaplingCbErr(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                   HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)outResp;
    (void)arg;
    return HITLS_STAPLING_ERROR;
}

static int32_t ServerStaplingCbInvalid(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                       HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)outResp;
    (void)arg;
    return HITLS_MSG_HANDLE_OCSP_STATUS_ERR;
}

/* Returns the EE certificate's OCSP response directly via *outResp (borrowed). */
static int32_t ServerStaplingCb(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)arg;
    if (g_serverList == NULL) {
        g_serverList = CreateOcspRespArray();
        if (g_serverList == NULL || g_serverList[0] == NULL) {
            return HITLS_STAPLING_ERROR;
        }
    }
    *outResp = g_serverList[0];
    return HITLS_STAPLING_SEND;
}

/* Supplies OCSP responses for both the EE and the intermediate certificate
 * (TLS 1.3 multi-response scenario): one response per certificate. */
static int32_t ServerStaplingCbMulti(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                     HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)arg;
    if (g_serverList == NULL) {
        g_serverList = CreateTwoOcspRespArray();
        if (g_serverList == NULL) {
            return HITLS_STAPLING_ERROR;
        }
    }
    *outResp = (chainidx < 2) ? g_serverList[chainidx] : NULL;
    return HITLS_STAPLING_SEND;
}

/* Supplies the OCSP response for the RSA EE certificate (RSA key exchange test). */
static int32_t ServerStaplingCbRsa(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                   HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)arg;
    if (g_serverList == NULL) {
        g_serverList = CreateRsaOcspRespArray();
        if (g_serverList == NULL || g_serverList[0] == NULL) {
            return HITLS_STAPLING_ERROR;
        }
    }
    *outResp = g_serverList[0];
    return HITLS_STAPLING_SEND;
}

/* Returns the RSA response only when the currently selected EE certificate is
 * the RSA one (checked via HITLS_GetCertificate's serial); otherwise skips.
 * This proves the per-certificate callback runs after the cipher-suite-driven
 * certificate selection, not against a pre-selection default. */
static int32_t ServerStaplingCbSelective(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                         HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)cert;
    (void)chainidx;
    (void)arg;
    if (g_serverList == NULL) {
        g_serverList = CreateRsaOcspRespArray();
        if (g_serverList == NULL || g_serverList[0] == NULL) {
            return HITLS_STAPLING_ERROR;
        }
    }
    *outResp = NULL;
    HITLS_CERT_X509 *ee = HITLS_GetCertificate(ctx);
    if (ee == NULL) {
        return HITLS_STAPLING_SEND; /* SEND with NULL -> no response, skipped */
    }
    BSL_Buffer serial = {0};
    if (HITLS_X509_CertCtrl(ee, HITLS_X509_GET_SERIALNUM, &serial, sizeof(BSL_Buffer)) == HITLS_PKI_SUCCESS) {
        /* serial is a shallow copy referencing the certificate; do not free it. */
        if (serial.dataLen == g_rsaSerial.dataLen && memcmp(serial.data, g_rsaSerial.data, serial.dataLen) == 0) {
            *outResp = g_serverList[0];
        }
    }
    return HITLS_STAPLING_SEND;
}

/* SEND with no response for the EE certificate: "no response for the EE
 * certificate". The library must skip stapling (no echo, no empty
 * CertificateStatus) instead of sending a malformed empty message. */
static int32_t ServerStaplingCbNullFirst(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                         HITLS_CERT_OcspResp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)chainidx;
    (void)outResp;
    (void)arg;
    return HITLS_STAPLING_SEND;
}

/* Stateful (session ID) TLS 1.2 session resumption: both peers must cache
 * sessions and session tickets are turned off so the session ID is non-empty. */
static int32_t EnableStatefulSessionResume(HITLS_Config *config)
{
    int32_t ret = HITLS_CFG_SetSessionCacheMode(config, HITLS_SESS_CACHE_BOTH);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ret = HITLS_CFG_SetSessionTicketSupport(config, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_CFG_SetTicketNums(config, 0);
}

/* Drive the renegotiation handshake to completion using only the public API:
 * alternate HITLS_Write / HITLS_Read with link transfer until the application
 * data makes a full round trip, which proves both peers finished the handshake.
 * IO_BUSY / RECV_BUF_EMPTY mean the handshake still needs more messages. */
static int32_t DriveRenegotiationToComplete(FRAME_LinkObj *client, FRAME_LinkObj *server)
{
    uint8_t appData = 1;
    uint8_t backData = 0;
    for (uint32_t count = 0; count < 30; count++) {
        uint32_t writeLen = 0;
        int32_t clientRet = HITLS_Write(FRAME_GetTlsCtx(client), &appData, sizeof(appData), &writeLen);
        if (clientRet != HITLS_SUCCESS && clientRet != HITLS_REC_NORMAL_IO_BUSY &&
            clientRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return clientRet;
        }
        int32_t ret = FRAME_TrasferMsgBetweenLink(client, server);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        uint32_t readLen = 0;
        int32_t serverRet = HITLS_Read(FRAME_GetTlsCtx(server), &backData, sizeof(backData), &readLen);
        if (serverRet != HITLS_SUCCESS && serverRet != HITLS_REC_NORMAL_IO_BUSY &&
            serverRet != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return serverRet;
        }
        ret = FRAME_TrasferMsgBetweenLink(server, client);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
        if (clientRet == HITLS_SUCCESS && serverRet == HITLS_SUCCESS && writeLen == sizeof(appData) &&
            readLen == sizeof(backData) && backData == appData) {
            return HITLS_SUCCESS;
        }
    }
    return HITLS_INTERNAL_EXCEPTION;
}

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_CB_TC001
* @spec  -
* @title  TLS 1.2: client requests OCSP stapling, server provides the response via callback.
* @precon  nan
* @brief
1. Create TLS 1.2 client and server configs. Client enables OCSP stapling and registers a status callback. Server registers a stapling callback that sets the OCSP response.
2. Establish a full handshake.
3. Check the client peer OCSP response list and the status callback invocation.
* @expect  1. Handshake succeeds. 2. The client stores one peer OCSP response and the status callback is invoked once.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_CB_TC001()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_NO_RESP_TC002
* @spec  -
* @title  TLS 1.2: client requests OCSP stapling but the server has no response.
* @precon  nan
* @brief
1. Create TLS 1.2 client and server configs. Client enables OCSP stapling and registers a status callback. Server does not provide any OCSP response.
2. Establish a full handshake.
3. Check the client peer OCSP response list and the status callback invocation.
* @expect  1. Handshake succeeds without stapling. 2. The client stores no peer OCSP response; the status callback is invoked with an empty list and the application accepts.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_NO_RESP_TC002()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_NOT_REQ_TC003
* @spec  -
* @title  TLS 1.2: client does not request OCSP stapling.
* @precon  nan
* @brief
1. Create TLS 1.2 client and server configs without enabling OCSP stapling.
2. Establish a full handshake.
3. Check that no peer OCSP response is stored.
* @expect  1. Handshake succeeds. 2. The client stores no peer OCSP response.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_NOT_REQ_TC003()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS13_CB_TC004
* @spec  -
* @title  TLS 1.3: client requests OCSP stapling, server embeds the response in CertificateEntry.
* @precon  nan
* @brief
1. Create TLS 1.3 client and server configs. Client enables OCSP stapling and registers a status callback. Server registers a stapling callback.
2. Establish a full handshake.
3. Check the client peer OCSP response list and the status callback invocation after Finished.
* @expect  1. Handshake succeeds. 2. The client stores the peer OCSP response and the status callback is invoked once.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS13_CB_TC004()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS13Config();
    s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_PARAM_TC005
* @spec  -
* @title  OCSP stapling API null-parameter checks.
* @precon  nan
* @brief
1. Call each OCSP stapling API with a NULL handle and check the return value.
* @expect  1. Every call returns HITLS_NULL_INPUT.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_PARAM_TC005()
{
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(NULL, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(NULL, ClientStatusCb, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetStatusCb(NULL, ClientStatusCb, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(NULL, ServerStaplingCb, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_SetStaplingOneCertCb(NULL, ServerStaplingCb, NULL), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(NULL, NULL, NULL), HITLS_NULL_INPUT);
EXIT:
    return;
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_CB_TC006
* @spec  -
* @title  TLS 1.2: server stapling callback and ctx-level client callback registration.
* @precon  nan
* @brief
1. Create TLS 1.2 client and server configs. Client enables OCSP stapling and registers both config-level and ctx-level status callbacks. Server registers a stapling callback that sets the response list and returns HITLS_STAPLING_SEND.
2. Establish a full handshake.
3. Check that the ctx-level callback registration is used (config-level is not).
* @expect  1. Handshake succeeds. 2. The ctx-level registration is invoked and the config-level registration is not.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_CB_TC006()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_statusCbCtxCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* Register the ctx-level callback, which overwrites the config-level one in
     * the connection's config copy. */
    ASSERT_EQ(HITLS_SetStatusCb(FRAME_GetTlsCtx(client), ClientStatusCbCtx, NULL), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCtxCount, 1);
    ASSERT_EQ(g_statusCbCount, 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_DTLS12_RESTRICT_TC007
* @spec  -
* @title  DTLS 1.2: status_request is restricted to stream TLS 1.2/1.3.
* @precon  nan
* @brief
1. Create DTLS 1.2 client and server configs. Client enables the status request and registers a status callback. Server registers a stapling callback.
2. Establish a full DTLS 1.2 handshake.
3. Check that no OCSP stapling occurred.
* @expect  1. Handshake succeeds. 2. No peer OCSP response is stored and the status callback is not invoked.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_DTLS12_RESTRICT_TC007()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewDTLS12Config();
    s_config = HITLS_CFG_NewDTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS13_UNSOLICITED_TC009
* @spec  -
* @title  TLS 1.3: an unsolicited CertificateEntry status_request is rejected.
* @precon  nan
* @brief
1. Create TLS 1.3 client configs without requesting and with requesting the status request.
2. Feed a CertificateEntry status_request extension body to ParseCertEntryOcspStatus.
3. Check that it is rejected when not requested and accepted when requested.
* @expect  1. Not-requested: returns an error (rejected). 2. Requested: returns HITLS_SUCCESS.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS13_UNSOLICITED_TC009()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *notReqConfig = NULL;
    HITLS_Config *reqConfig = NULL;
    FRAME_LinkObj *notReqLink = NULL;
    FRAME_LinkObj *reqLink = NULL;

    notReqConfig = HITLS_CFG_NewTLS13Config();
    reqConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(notReqConfig != NULL);
    ASSERT_TRUE(reqConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(reqConfig, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);

    notReqLink = FRAME_CreateLink(notReqConfig, BSL_UIO_TCP);
    reqLink = FRAME_CreateLink(reqConfig, BSL_UIO_TCP);
    ASSERT_TRUE(notReqLink != NULL);
    ASSERT_TRUE(reqLink != NULL);

    /* A CertificateEntry status_request extension body carrying a minimal
     * status-only OCSPResponse (status internalError, no responseBytes):
     * status_type(1) + respLen(3) + DER. */
    const uint8_t extBody[] = {0x01, 0x00, 0x00, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x02};

    /* Not requested: the unsolicited extension must be rejected. */
    /* ParseErrorProcess sends the alert through ctx->method.sendAlert; a test stub
     * avoids depending on CONN_Init state on a freshly created link. */
    TLS_Ctx *notReqTls = (TLS_Ctx *)FRAME_GetTlsCtx(notReqLink);
    notReqTls->method.sendAlert = TestSendAlert;
    int32_t ret = ParseCertEntryOcspStatus(notReqTls, extBody, sizeof(extBody), 0);
    ASSERT_NE(ret, HITLS_SUCCESS);

    /* Requested: the extension is accepted and stored. */
    TLS_Ctx *reqTls = (TLS_Ctx *)FRAME_GetTlsCtx(reqLink);
    reqTls->method.sendAlert = TestSendAlert;
    ret = ParseCertEntryOcspStatus(reqTls, extBody, sizeof(extBody), 0);
    ASSERT_EQ(ret, HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(notReqConfig);
    HITLS_CFG_FreeConfig(reqConfig);
    FRAME_FreeLink(notReqLink);
    FRAME_FreeLink(reqLink);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_BAD_RESP_TC010
* @spec  -
* @title  TLS 1.2: an unsatisfactory OCSP response aborts the handshake.
* @precon  nan
* @brief
1. TLS 1.2 client requests stapling and registers a status callback that returns an error.
2. Server registers a stapling callback and provides an OCSP response.
3. Establish the handshake.
* @expect  1. The handshake fails (the unsatisfactory response aborts per RFC 6066).
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_BAD_RESP_TC010()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCbBadResp, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_ACK_NO_RESP_TC011
* @spec  -
* @title  TLS 1.2: client tolerates an ack without a CertificateStatus message.
* @precon  nan
* @brief
1. Drive a TLS 1.2 stapling handshake (ECDHE, which requires ServerKeyExchange) until the client waits for CertificateStatus.
2. Feed the messages that may follow a skipped CertificateStatus.
3. Check that only the messages consistent with the negotiated key exchange are accepted.
* @expect  1. ServerKeyExchange is accepted and the state moves on. 2. CertificateRequest / ServerHelloDone are rejected because ServerKeyExchange is still required. 3. Other messages are rejected.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_ACK_NO_RESP_TC011()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    /* Drive until the client has received the acknowledgment and waits for CertificateStatus. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_STATUS), HITLS_SUCCESS);

    TLS_Ctx *tls = (TLS_Ctx *)FRAME_GetTlsCtx(client);
    ASSERT_TRUE(tls->hsCtx != NULL);
    ASSERT_EQ(tls->hsCtx->state, TRY_RECV_CERTIFICATE_STATUS);

    /* The server sent ServerKeyExchange instead of CertificateStatus: continue. */
    ASSERT_EQ(CheckCertificateStatusType(tls, SERVER_KEY_EXCHANGE), HITLS_SUCCESS);
    ASSERT_EQ(tls->hsCtx->state, TRY_RECV_SERVER_KEY_EXCHANGE);

    /* ServerKeyExchange is still required (ECDHE), so skipping it is unexpected. */
    tls->hsCtx->state = TRY_RECV_CERTIFICATE_STATUS;
    ASSERT_NE(CheckCertificateStatusType(tls, CERTIFICATE_REQUEST), HITLS_SUCCESS);
    tls->hsCtx->state = TRY_RECV_CERTIFICATE_STATUS;
    ASSERT_NE(CheckCertificateStatusType(tls, SERVER_HELLO_DONE), HITLS_SUCCESS);

    /* An unrelated message remains unexpected. */
    tls->hsCtx->state = TRY_RECV_CERTIFICATE_STATUS;
    ASSERT_NE(CheckCertificateStatusType(tls, CLIENT_HELLO), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */
/* @
* @test  SDV_TLS_OCSP_STAPLING_STAPLING_CB_SKIP_TC012
* @spec  -
* @title  TLS 1.2: server stapling callback returning SKIP sends no status.
* @precon  nan
* @brief
1. Client requests stapling and registers a status callback. Server stapling callback returns HITLS_STAPLING_SKIP.
2. Establish the handshake.
3. Check that no stapling occurred; the status callback is still invoked with an empty list.
* @expect  1. Handshake succeeds without stapling; the status callback is invoked once with an empty list.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_STAPLING_CB_SKIP_TC012()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbSkip, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_STAPLING_CB_ERR_TC013
* @spec  -
* @title  TLS 1.2: server stapling callback returning an internal error aborts.
* @precon  nan
* @brief
1. Client requests stapling. Server stapling callback returns HITLS_STAPLING_ERROR.
2. Establish the handshake.
* @expect  1. The handshake fails.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_STAPLING_CB_ERR_TC013()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbErr, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_STAPLING_CB_INVALID_TC014
* @spec  -
* @title  TLS 1.2: an invalid server stapling callback return aborts.
* @precon  nan
* @brief
1. Client requests stapling. Server stapling callback returns a value outside the defined set.
2. Establish the handshake.
* @expect  1. The handshake fails (invalid callback return is rejected).
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_STAPLING_CB_INVALID_TC014()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbInvalid, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_NO_RESP_REJECT_TC015
* @spec  -
* @title  TLS 1.2: no stapled response with a rejecting status callback aborts.
* @precon  nan
* @brief
1. Client requests stapling and registers a status callback that returns HITLS_STATUS_REJECT.
2. Server stapling callback returns HITLS_STAPLING_SKIP (no response is sent).
3. Establish the handshake.
* @expect  1. The handshake fails (the application rejects the missing stapled response).
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_NO_RESP_REJECT_TC015()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCbBadResp, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbSkip, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    ASSERT_NE(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_STATUS_TYPE_VALIDATE_TC016
* @spec  -
* @title  Status request type is validated against the supported set.
* @precon  nan
* @brief
1. Call HITLS_CFG_SetStatusRequestType with the supported values (enable/disable) and invalid ones.
* @expect  1. OCSP(1) and DISABLE(-1) succeed; 0 and 2 are rejected with HITLS_INVALID_INPUT.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_STATUS_TYPE_VALIDATE_TC016()
{
    HITLS_Config *config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(config, HITLS_STATUS_REQUEST_TYPE_DISABLE), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(config, 0), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(config, HITLS_STATUS_REQUEST_TYPE_OCSP + 1), HITLS_INVALID_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_CERTENTRY_STRICT_TC019
* @spec  -
* @title  TLS 1.3: malformed CertificateEntry status_request bodies are rejected per RFC 6066.
* @precon  nan
* @brief
1. Create a TLS 1.3 client that requested the status request and feed it malformed CertificateEntry extension bodies.
2. Cover a truncated header, an unknown status type, a zero-length OCSPResponse, and a response length that overruns the body.
* @expect  1. Every malformed body is rejected with a non-success code instead of being silently ignored.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_CERTENTRY_STRICT_TC019()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *reqConfig = NULL;
    FRAME_LinkObj *reqLink = NULL;

    reqConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(reqConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(reqConfig, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    reqLink = FRAME_CreateLink(reqConfig, BSL_UIO_TCP);
    ASSERT_TRUE(reqLink != NULL);

    TLS_Ctx *tls = (TLS_Ctx *)FRAME_GetTlsCtx(reqLink);
    tls->method.sendAlert = TestSendAlert;

    /* Truncated header: cannot carry status_type(1) + response length(3). */
    const uint8_t tooShort[] = {0x01};
    ASSERT_NE(ParseCertEntryOcspStatus(tls, tooShort, sizeof(tooShort), 0), HITLS_SUCCESS);

    /* Unknown status type (only ocsp(1) is defined by RFC 6066). */
    const uint8_t badType[] = {0x02, 0x00, 0x00, 0x01, 0x00};
    ASSERT_NE(ParseCertEntryOcspStatus(tls, badType, sizeof(badType), 0), HITLS_SUCCESS);

    /* Zero-length OCSPResponse violates opaque<1..2^24-1>. */
    const uint8_t zeroLen[] = {0x01, 0x00, 0x00, 0x00};
    ASSERT_NE(ParseCertEntryOcspStatus(tls, zeroLen, sizeof(zeroLen), 0), HITLS_SUCCESS);

    /* Declared response length overruns the extension body. */
    const uint8_t overrun[] = {0x01, 0x00, 0x00, 0x05, 0x00};
    ASSERT_NE(ParseCertEntryOcspStatus(tls, overrun, sizeof(overrun), 0), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(reqConfig);
    FRAME_FreeLink(reqLink);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_EMPTY_RESP_TC020
* @spec  -
* @title  TLS 1.2: an empty OCSPResponse violates opaque<1..2^24-1> and is rejected.
* @precon  nan
* @brief
1. Create a TLS 1.2 client that requested the status request.
2. Hand ClientRecvCertificateStatus a CertificateStatus message with status_type=ocsp but a zero-length response.
* @expect  1. The empty response is rejected with a non-success code instead of being accepted as "no stapling".
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_EMPTY_RESP_TC020()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *reqConfig = NULL;
    FRAME_LinkObj *reqLink = NULL;

    reqConfig = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(reqConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(reqConfig, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    reqLink = FRAME_CreateLink(reqConfig, BSL_UIO_TCP);
    ASSERT_TRUE(reqLink != NULL);

    TLS_Ctx *tls = (TLS_Ctx *)FRAME_GetTlsCtx(reqLink);
    tls->method.sendAlert = TestSendAlert;

    HS_Msg hsMsg;
    (void)memset(&hsMsg, 0, sizeof(hsMsg));
    hsMsg.body.certificateStatus.statusType = HITLS_STATUS_REQUEST_TYPE_OCSP;
    hsMsg.body.certificateStatus.response = NULL;
    hsMsg.body.certificateStatus.responseLen = 0;
    ASSERT_NE(ClientRecvCertificateStatus(tls, &hsMsg), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(reqConfig);
    FRAME_FreeLink(reqLink);
}
/* END_CASE */
/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_ACK_NO_RESP_RSA_TC021
* @spec  -
* @title  TLS 1.2: ack without CertificateStatus, RSA key exchange accepts the non-SKE follow-ups.
* @precon  nan
* @brief
1. Drive a TLS 1.2 stapling handshake with the RSA cipher suite (no ServerKeyExchange needed) until the client waits for CertificateStatus.
2. Feed CertificateRequest and ServerHelloDone, which are legal when ServerKeyExchange is not required.
3. Check the state transitions instead of aborting.
* @expect  1. CertificateRequest / ServerHelloDone are accepted and the state moves on. 2. ServerKeyExchange is rejected.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_ACK_NO_RESP_RSA_TC021()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_serverList = NULL;
    uint16_t rsaSuite = HITLS_RSA_WITH_AES_128_CBC_SHA;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(c_config, &rsaSuite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(s_config, &rsaSuite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbRsa, NULL), HITLS_SUCCESS);

    LoadRsaStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    LoadRsaStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    ASSERT_TRUE(server != NULL);

    /* Drive until the client has received the acknowledgment and waits for CertificateStatus. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_CERTIFICATE_STATUS), HITLS_SUCCESS);

    TLS_Ctx *tls = (TLS_Ctx *)FRAME_GetTlsCtx(client);
    ASSERT_TRUE(tls->hsCtx != NULL);
    ASSERT_EQ(tls->hsCtx->state, TRY_RECV_CERTIFICATE_STATUS);

    /* RSA needs no ServerKeyExchange, so ServerKeyExchange is unexpected here. */
    ASSERT_NE(CheckCertificateStatusType(tls, SERVER_KEY_EXCHANGE), HITLS_SUCCESS);

    /* The server sent CertificateRequest instead of CertificateStatus: continue. */
    tls->hsCtx->state = TRY_RECV_CERTIFICATE_STATUS;
    ASSERT_EQ(CheckCertificateStatusType(tls, CERTIFICATE_REQUEST), HITLS_SUCCESS);
    ASSERT_EQ(tls->hsCtx->state, TRY_RECV_CERTIFICATE_REQUEST);

    /* The server sent ServerHelloDone instead of CertificateStatus: continue. */
    tls->hsCtx->state = TRY_RECV_CERTIFICATE_STATUS;
    ASSERT_EQ(CheckCertificateStatusType(tls, SERVER_HELLO_DONE), HITLS_SUCCESS);
    ASSERT_EQ(tls->hsCtx->state, TRY_RECV_SERVER_HELLO_DONE);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */
/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS13_CHAIN_ALIGN_TC022
* @spec  -
* @title  TLS 1.3: peer OCSP responses align with the certificate chain by depth.
* @precon  nan
* @brief
1. Create a TLS 1.3 client that requested the status request.
2. Feed CertificateEntry OCSP responses at depth 0 and depth 2 (the intermediate certificate at depth 1 carries none).
3. Check that the stored list keeps an empty-response placeholder at depth 1 so the index matches the certificate chain.
* @expect  1. The list length is 3; the first/last entries hold the responses; the middle entry is an empty placeholder.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS13_CHAIN_ALIGN_TC022()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *reqConfig = NULL;
    FRAME_LinkObj *reqLink = NULL;

    reqConfig = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(reqConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(reqConfig, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    reqLink = FRAME_CreateLink(reqConfig, BSL_UIO_TCP);
    ASSERT_TRUE(reqLink != NULL);

    TLS_Ctx *tls = (TLS_Ctx *)FRAME_GetTlsCtx(reqLink);
    tls->method.sendAlert = TestSendAlert;

    /* Two CertificateEntry status_request bodies carrying a minimal status-only
     * OCSPResponse (status internalError, no responseBytes): status_type(1) + respLen(3) + DER. */
    const uint8_t respBody[] = {0x01, 0x00, 0x00, 0x05, 0x30, 0x03, 0x0a, 0x01, 0x02};
    ASSERT_EQ(ParseCertEntryOcspStatus(tls, respBody, sizeof(respBody), 0), HITLS_SUCCESS);
    /* Depth 1 has no status_request extension and is skipped by the parser. */
    ASSERT_EQ(ParseCertEntryOcspStatus(tls, respBody, sizeof(respBody), 2), HITLS_SUCCESS);

    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList((HITLS_Ctx *)tls, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList != NULL);
    ASSERT_EQ(respCount, 3);
    /* Depth 0 (EE) and depth 2 carry a response; depth 1 has no status_request
     * extension and is left as a NULL placeholder so the index aligns with the chain. */
    ASSERT_TRUE(respList[0] != NULL);
    ASSERT_TRUE(respList[1] == NULL);
    ASSERT_TRUE(respList[2] != NULL);

EXIT:
    HITLS_CFG_FreeConfig(reqConfig);
    FRAME_FreeLink(reqLink);
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_NO_CB_TC023
* @spec  -
* @title  TLS 1.2: without a server stapling callback nothing is sent.
* @precon  nan
* @brief
1. Create TLS 1.2 client and server configs. Client enables OCSP stapling and registers a status callback. Server registers no stapling callback.
2. Establish a full handshake.
3. Check that no CertificateStatus is sent: the client has no peer response, and the status callback is invoked to report the empty result.
* @expect  1. Handshake succeeds. 2. No peer OCSP response is stored; the client status callback is invoked once.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_NO_CB_TC023()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, NULL, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    /* The client requested stapling, so it is still notified that no response was
     * received; the application decides whether an empty list is acceptable. */
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */
/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS13_MULTI_RESP_TC024
* @spec  -
* @title  TLS 1.3: OCSP responses are embedded for both the EE and the intermediate certificate.
* @precon  nan
* @brief
1. Create TLS 1.3 client and server configs. Client requests stapling. Server provides OCSP responses for the EE and the intermediate certificates via the stapling callback.
2. Establish a full handshake.
3. Check that both CertificateEntry extensions carry a matching response.
* @expect  1. Handshake succeeds. 2. The client stores two peer responses (EE + intermediate), each with a successful status.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS13_MULTI_RESP_TC024()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS13Config();
    s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);

    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbMulti, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_RESUME_TC025
* @spec  -
* @title  TLS 1.2 session resumption: the server does not acknowledge status_request.
* @precon  nan
* @brief
1. Establish a full TLS 1.2 handshake with stapling and keep the session.
2. Resume the session with fresh links.
3. Stop after the resumed ServerHello and check that the client did not set statusExpected.
4. Complete the abbreviated handshake.
* @expect  1. The first handshake delivers stapling. 2. The resumed ServerHello carries no status_request
*          acknowledgment, no CertificateStatus is sent, and the client status callback runs only once.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_RESUME_TC025()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(EnableStatefulSessionResume(c_config), HITLS_SUCCESS);
    ASSERT_EQ(EnableStatefulSessionResume(s_config), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* First handshake: full, with stapling delivered. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_statusCbCount, 1);
    session = HITLS_GetDupSession(FRAME_GetTlsCtx(client));
    ASSERT_TRUE(session != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    /* The first server ctx no longer references the application list. */
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }

    /* Resumed abbreviated handshake with the same configurations. */
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(FRAME_GetTlsCtx(client), session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_SERVER_HELLO), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(FRAME_GetTlsCtx(client), &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);
    /* An abbreviated handshake cannot deliver CertificateStatus, so the server
     * must not acknowledge status_request in the resumed ServerHello; the client
     * therefore does not set statusExpected for this handshake. */
    ASSERT_TRUE(FRAME_GetTlsCtx(client)->statusExpected == false);
    /* No CertificateStatus in the abbreviated handshake: no new peer response and
     * the client status callback is not invoked a second time. */
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(FRAME_GetTlsCtx(client), &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_SESS_Free(session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_RENEGO_TC026
* @spec  -
* @title  TLS 1.2 renegotiation re-delivers the OCSP response.
* @precon  nan
* @brief
1. Establish a full TLS 1.2 handshake with stapling.
2. Initiate renegotiation on both peers.
3. Complete the renegotiation handshake.
4. Check that the client receives a fresh OCSP response and the callback runs again.
* @expect  1. The first handshake delivers stapling. 2. After renegotiation the client holds a new peer OCSP
*          response and the status callback is invoked twice in total.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_RENEGO_TC026()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetRenegotiationSupport(FRAME_GetTlsCtx(client), true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetRenegotiationSupport(FRAME_GetTlsCtx(server), true), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_statusCbCount, 1);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);

    ASSERT_EQ(HITLS_Renegotiate(FRAME_GetTlsCtx(client)), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Renegotiate(FRAME_GetTlsCtx(server)), HITLS_SUCCESS);
    /* HITLS_Renegotiate resets both stapling states: the client's peer response
     * list is freed, so the previously borrowed respList is no longer valid.
     * The server no longer references the application list either, so it is
     * released here before the new handshake reallocates it. */
    respList = NULL;
    respCount = 0;
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }

    ASSERT_EQ(FRAME_CreateRenegotiationState(client, server, false, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 2);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_RENEGO_CIPHER_TC027
* @spec  -
* @title  TLS 1.2 renegotiation with a changed cipher suite runs a full handshake and re-delivers OCSP.
* @precon  nan
* @brief
1. Establish a full TLS 1.2 handshake with stapling and the AES-128 cipher suite.
2. Change the cipher suite of both peers to AES-256 through the public API.
3. Initiate renegotiation and drive it to completion using only public API read/write.
4. Check that the handshake is a full one (not resumed), negotiates AES-256, and re-delivers stapling.
* @expect  1. The first handshake delivers stapling. 2. Renegotiation is a full handshake that negotiates
*          AES-256 and delivers a fresh OCSP response; the client status callback runs twice in total.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_RENEGO_CIPHER_TC027()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *renegoSession = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    uint16_t cipher128 = HITLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    uint16_t cipher256 = HITLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(c_config, &cipher128, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(s_config, &cipher128, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetRenegotiationSupport(FRAME_GetTlsCtx(client), true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetRenegotiationSupport(FRAME_GetTlsCtx(server), true), HITLS_SUCCESS);

    /* First handshake: full, AES-128, with stapling delivered. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_statusCbCount, 1);
    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);

    /* Change the cipher suite of both peers before renegotiating. */
    ASSERT_EQ(HITLS_SetCipherSuites(clientTlsCtx, &cipher256, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetCipherSuites(FRAME_GetTlsCtx(server), &cipher256, 1), HITLS_SUCCESS);

    ASSERT_EQ(HITLS_Renegotiate(clientTlsCtx), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Renegotiate(FRAME_GetTlsCtx(server)), HITLS_SUCCESS);
    /* HITLS_Renegotiate resets both stapling states: the client's peer response
     * list is freed, so the previously borrowed respList is no longer valid.
     * The server no longer references the application list either, so it is
     * released here before the new handshake reallocates it. */
    respList = NULL;
    respCount = 0;
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }

    /* Full handshake renegotiation driven purely by public API reads/writes. */
    ASSERT_EQ(DriveRenegotiationToComplete(client, server), HITLS_SUCCESS);

    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(clientTlsCtx, &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(!isReused);
    /* The changed cipher suite must be negotiated. */
    renegoSession = HITLS_GetDupSession(clientTlsCtx);
    ASSERT_TRUE(renegoSession != NULL);
    uint16_t negotiatedSuite = 0;
    ASSERT_EQ(HITLS_SESS_GetCipherSuite(renegoSession, &negotiatedSuite), HITLS_SUCCESS);
    ASSERT_EQ(negotiatedSuite, cipher256);
    /* The stapling state is released once the (renegotiation) handshake is
     * done, so the peer response list is no longer available. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 2);

EXIT:
    HITLS_SESS_Free(renegoSession);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS13_RESUME_TC028
* @spec  -
* @title  TLS 1.3 session resumption: no stapling and the client status callback is not invoked.
* @precon  nan
* @brief
1. Establish a full TLS 1.3 handshake with stapling and keep the session.
2. Resume the session with fresh links.
3. Complete the resumed handshake and check it is a PSK resumption.
4. Check that no peer OCSP response is delivered and the status callback runs only once.
* @expect  1. The first handshake delivers stapling. 2. The resumed handshake reports no peer OCSP response and
*          does not invoke the client status callback again.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS13_RESUME_TC028()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_Session *session = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS13Config();
    s_config = HITLS_CFG_NewTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCb, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    /* First handshake: full, with stapling delivered. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    ASSERT_EQ(g_statusCbCount, 1);
    session = HITLS_GetDupSession(FRAME_GetTlsCtx(client));
    ASSERT_TRUE(session != NULL);

    FRAME_FreeLink(client);
    client = NULL;
    FRAME_FreeLink(server);
    server = NULL;
    /* The first server ctx no longer references the application list. */
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }

    /* Resumed handshake with the same configurations. */
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(HITLS_SetSession(FRAME_GetTlsCtx(client), session), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);
    bool isReused = false;
    ASSERT_EQ(HITLS_IsSessionReused(FRAME_GetTlsCtx(client), &isReused), HITLS_SUCCESS);
    ASSERT_TRUE(isReused);
    /* A resumed handshake carries no Certificate / CertificateEntry: no new peer
     * response and the client status callback is not invoked a second time. */
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(FRAME_GetTlsCtx(client), &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_SESS_Free(session);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_NULL_FIRST_TC029
* @spec  -
* @title  TLS 1.2: a NULL first (EE) response entry skips stapling instead of sending an empty CertificateStatus.
* @precon  nan
* @brief
1. Create a TLS 1.2 handshake where the client requests stapling and the server callback returns SEND
   but provides a response list whose first (EE) entry is NULL.
2. Complete the handshake.
3. Check that the server did not echo status_request and the client gets no peer response.
* @expect  1. The handshake succeeds (no empty CertificateStatus is sent). 2. The client holds no peer OCSP
*          response and the status callback reports an empty list once.
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_NULL_FIRST_TC029()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbNullFirst, NULL), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    /* The server skipped the echo, so the client never expects a CertificateStatus
     * and stores nothing; the status callback still runs once with an empty list. */
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL || respCount == 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */

/* @
* @test  SDV_TLS_OCSP_STAPLING_TLS12_MULTI_CERT_TC030
* @spec  -
* @title  TLS 1.2: the stapling callback runs after the cipher-suite-driven certificate selection.
* @precon  nan
* @brief
1. Configure a server with both an RSA and an ECDSA certificate pair and force the ECDHE-RSA cipher suite.
2. The callback returns the RSA OCSP response only when the selected EE certificate is the RSA one.
3. Complete the handshake and check stapling is delivered for the selected RSA certificate.
* @expect  1. The handshake succeeds. 2. The client receives the RSA stapled response (proving the
*          callback saw the selected certificate, not the default ECDSA one).
* @prior  Level 2
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_TLS_OCSP_STAPLING_TLS12_MULTI_CERT_TC030()
{
    FRAME_Init();
    RegDefaultMemCallback();
    HITLS_Config *c_config = NULL;
    HITLS_Config *s_config = NULL;
    FRAME_LinkObj *client = NULL;
    FRAME_LinkObj *server = NULL;
    HITLS_X509_Cert *rsaCert = NULL;
    g_statusCbCount = 0;
    g_serverList = NULL;
    uint16_t suite = HITLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

    c_config = HITLS_CFG_NewTLS12Config();
    s_config = HITLS_CFG_NewTLS12Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(c_config, &suite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetCipherSuites(s_config, &suite, 1), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusRequestType(c_config, HITLS_STATUS_REQUEST_TYPE_OCSP), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStatusCb(c_config, ClientStatusCb, NULL), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetStaplingOneCertCb(s_config, ServerStaplingCbSelective, NULL), HITLS_SUCCESS);

    /* Capture the RSA EE serial so the callback can tell it apart from the
     * default (last loaded) ECDSA certificate. */
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, STAPLING_CERTS_PATH "rsa_server.der", &rsaCert), HITLS_SUCCESS);
    ASSERT_TRUE(rsaCert != NULL);
    ASSERT_EQ(HITLS_X509_CertCtrl(rsaCert, HITLS_X509_GET_SERIALNUM, &g_rsaSerial, sizeof(BSL_Buffer)), HITLS_SUCCESS);

    LoadStaplingCerts(c_config, false);
    client = FRAME_CreateLinkEx(c_config, BSL_UIO_TCP);
    ASSERT_TRUE(client != NULL);
    /* Load the RSA pair first so the default/current key type is the ECDSA pair
     * loaded last; the ECDHE-RSA suite then selects the RSA certificate and the
     * callback must see it (not the default ECDSA one). */
    LoadRsaStaplingCerts(s_config, true);
    LoadStaplingCerts(s_config, true);
    server = FRAME_CreateLinkEx(s_config, BSL_UIO_TCP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_Ctx *clientTlsCtx = FRAME_GetTlsCtx(client);
    HITLS_CERT_OcspResp **respList = NULL;
    uint32_t respCount = 0;
    /* The stapling state is per-handshake: once the handshake completes, the
     * peer response list is released, so a post-handshake call returns an
     * empty list. The status callback already saw the response while the
     * handshake was in progress. */
    ASSERT_EQ(HITLS_GetPeerOcspResponseList(clientTlsCtx, &respList, &respCount), HITLS_SUCCESS);
    ASSERT_TRUE(respList == NULL);
    ASSERT_EQ(respCount, 0);
    ASSERT_EQ(g_statusCbCount, 1);

EXIT:
    HITLS_X509_CertFree(rsaCert);
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
    if (g_serverList != NULL) {
        FreeOcspRespArray(g_serverList);
        g_serverList = NULL;
    }
}
/* END_CASE */
