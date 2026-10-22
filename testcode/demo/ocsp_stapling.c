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

/* OCSP stapling (RFC 6066 status_request) demo over configurable TLS versions.
 * Runs a server thread and a client thread on one loopback socket:
 *  - server registers a per-certificate stapling callback
 *    (HITLS_CFG_SetStaplingCbPerCert) that returns each certificate's OCSP
 *    response directly and returns HITLS_STAPLING_SEND;
 *  - client requests the status (HITLS_CFG_SetStatusRequestType) and, in the
 *    status callback, reads the stapled responses with
 *    HITLS_GetPeerOcspResponseList and prints them.
 * openHiTLS treats the OCSP response as opaque DER; validation is up to the app.
 *
 * Usage:
 *     ocsp_stapling <client_versions> <server_versions> <client_cb> <server_cb> [trace]
 *       client_versions / server_versions: TLS version range, e.g. tls1.2 or
 *         tls1.2:tls1.3 (min:max, colon separated). The public config interface
 *         supports tls1.2/tls1.3 only; tls1.0/tls1.1 tokens are rejected with a
 *         clear error (the library does not expose them for configuration).
 *       client_cb / server_cb: 1 to register the callback, 0 otherwise.
 *       trace: 1 to enable the per-message protocol trace, 0 (default) to disable.
 *
 * The server staples a real OCSP response that is embedded as DER in the demo,
 * so no network access or helper binary is required. At the end the negotiated
 * TLS version and whether each callback was invoked are printed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bsl_sal.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "hitls.h"
#include "hitls_cert.h"
#include "hitls_status_request.h"
#include "hitls_pki_ocsp.h"
#include "hitls_pki_errno.h"
#include "hitls_debug.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_pki_cert.h"
#include "crypt_errno.h"

#define CERTS_PATH  "../../../testcode/testdata/tls/certificate/der/ocsp_stapling/"
#define LISTEN_PORT 23451

/* A real OCSPResponse (RFC 6960) for a live responder, embedded as DER so the
 * demo runs without network access or a helper binary. */
static const uint8_t gOcspRespDer[] = {
    0x30, 0x82, 0x02, 0x93, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x02, 0x8c, 0x30, 0x82, 0x02, 0x88, 0x06, 0x09, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x02, 0x79, 0x30, 0x82, 0x02, 0x75, 0x30, 0x81, 0xa3, 0xa1,
    0x2a, 0x30, 0x28, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x4f, 0x43, 0x53, 0x50, 0x20,
    0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61,
    0x74, 0x65, 0x20, 0x43, 0x41, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x31, 0x30, 0x31, 0x39, 0x31, 0x33, 0x32, 0x39,
    0x32, 0x38, 0x5a, 0x30, 0x64, 0x30, 0x62, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14, 0x28, 0xcf, 0x2f, 0x4c, 0x34, 0xc4, 0x84, 0x55, 0x7a, 0x70, 0x14, 0x09, 0x7f, 0xba, 0xef, 0xbf,
    0x72, 0x82, 0x65, 0x81, 0x04, 0x14, 0x60, 0xc3, 0x96, 0x36, 0xab, 0x02, 0xd4, 0xb6, 0x2c, 0xd7, 0x37, 0x25, 0xc3,
    0xbd, 0x42, 0xc6, 0x2e, 0xb0, 0x67, 0xf2, 0x02, 0x14, 0x29, 0xc4, 0x5b, 0x81, 0x92, 0x0f, 0x0d, 0xf0, 0xae, 0xad,
    0x31, 0xbd, 0x50, 0x44, 0x5c, 0x39, 0x80, 0xb7, 0x24, 0x66, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x31,
    0x30, 0x31, 0x39, 0x31, 0x33, 0x32, 0x39, 0x32, 0x38, 0x5a, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xb7, 0x73, 0x31, 0x71, 0xc9, 0xff, 0x72, 0xc5,
    0x25, 0x1e, 0x81, 0x49, 0x9f, 0xe0, 0x98, 0xa8, 0x3a, 0x40, 0x0b, 0x41, 0x61, 0x70, 0x33, 0x17, 0x61, 0xc5, 0xba,
    0x83, 0x7f, 0x32, 0xe0, 0x79, 0x02, 0x21, 0x00, 0x9c, 0x50, 0x15, 0x68, 0x44, 0x9a, 0x6c, 0x38, 0xc9, 0xb9, 0x8b,
    0x4e, 0x67, 0x78, 0x0c, 0x47, 0xb1, 0xa6, 0x6d, 0xbc, 0x0f, 0x01, 0x1e, 0xee, 0x0a, 0x88, 0x92, 0xd3, 0x4c, 0x3d,
    0x98, 0x13, 0xa0, 0x82, 0x01, 0x74, 0x30, 0x82, 0x01, 0x70, 0x30, 0x82, 0x01, 0x6c, 0x30, 0x82, 0x01, 0x13, 0xa0,
    0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4f, 0xf6, 0xdc, 0x2d, 0xcf, 0xb1, 0x71, 0x1c, 0xef, 0x01, 0xca, 0xf6, 0x3b,
    0x03, 0x6c, 0x78, 0xa8, 0xf4, 0x86, 0x50, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x20, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x53,
    0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
    0x32, 0x36, 0x31, 0x30, 0x31, 0x39, 0x31, 0x33, 0x32, 0x39, 0x32, 0x38, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x30,
    0x31, 0x36, 0x31, 0x33, 0x32, 0x39, 0x32, 0x38, 0x5a, 0x30, 0x28, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x1d, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x53, 0x74, 0x61, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x83, 0x64, 0xac, 0x6f, 0xec, 0x94, 0xee, 0x95, 0xcc, 0x60, 0xb5, 0x40, 0x1e, 0x59, 0x12, 0x43, 0x22,
    0xde, 0x39, 0x2e, 0x4e, 0x7b, 0x03, 0xba, 0xf9, 0x73, 0xac, 0xc0, 0xca, 0xd8, 0x79, 0x3c, 0x22, 0x83, 0x72, 0x17,
    0x20, 0xc0, 0x44, 0xc2, 0x47, 0xf8, 0x98, 0x7c, 0x6c, 0x6f, 0x9b, 0xca, 0x3e, 0x49, 0xbd, 0xd5, 0xc0, 0x33, 0x87,
    0x27, 0x11, 0x67, 0x06, 0x74, 0xbd, 0x88, 0xcf, 0x16, 0xa3, 0x23, 0x30, 0x21, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
    0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x30, 0xc9, 0x23, 0xaf, 0x1c, 0x9a, 0x74, 0x8e, 0xbf, 0x47, 0x2c,
    0xa2, 0x3f, 0xd9, 0x53, 0xa0, 0xcd, 0xe8, 0x5f, 0x58, 0x9c, 0x7c, 0xcf, 0x56, 0x92, 0x18, 0xe6, 0x92, 0x58, 0xf2,
    0xdd, 0x7f, 0x02, 0x20, 0x06, 0xdb, 0xc2, 0x80, 0x39, 0xd0, 0x50, 0x05, 0xb2, 0x47, 0x68, 0x6f, 0x49, 0x1a, 0x08,
    0x41, 0xd7, 0x04, 0x9e, 0x1d, 0xbd, 0x53, 0x5e, 0x57, 0x4b, 0x02, 0xbe, 0xfa, 0x16, 0xdd, 0x1d, 0xd4,
};

static uint16_t gClientMinVer = 0;
static uint16_t gClientMaxVer = 0;
static uint16_t gServerMinVer = 0;
static uint16_t gServerMaxVer = 0;
static int32_t gClientCbEnabled = 0;
static int32_t gServerCbEnabled = 0;
static int32_t gTraceEnabled = 0;
static const uint8_t *gRespData = NULL;
static uint32_t gRespLen = 0;
static volatile int32_t gClientCbCalled = 0;
static volatile int32_t gServerCbCalled = 0;
static uint16_t gClientNegotiatedVer = 0;
static uint16_t gServerNegotiatedVer = 0;

/* Parse a version token ("tls1.0" .. "tls1.3") into a HITLS_VERSION_TLSxx. */
static int32_t ParseVersion(const char *token, uint16_t *version)
{
    if (strcmp(token, "tls1.0") == 0) {
        *version = HITLS_VERSION_TLS10;
    } else if (strcmp(token, "tls1.1") == 0) {
        *version = HITLS_VERSION_TLS11;
    } else if (strcmp(token, "tls1.2") == 0) {
        *version = HITLS_VERSION_TLS12;
    } else if (strcmp(token, "tls1.3") == 0) {
        *version = HITLS_VERSION_TLS13;
    } else {
        return -1;
    }
    return 0;
}

/* Parse a version range argument: "tls1.2" or "tls1.0:tls1.3" (min:max). */
static int32_t ParseVersionRange(const char *arg, uint16_t *minVersion, uint16_t *maxVersion)
{
    char buf[64];
    if (arg == NULL || arg[0] == '\0' || strlen(arg) >= sizeof(buf)) {
        return -1;
    }
    (void)snprintf(buf, sizeof(buf), "%s", arg);
    char *colon = strchr(buf, ':');
    if (colon == NULL) {
        if (ParseVersion(buf, minVersion) != 0) {
            return -1;
        }
        *maxVersion = *minVersion;
    } else {
        *colon = '\0';
        if (ParseVersion(buf, minVersion) != 0 || ParseVersion(colon + 1, maxVersion) != 0) {
            return -1;
        }
        if (*minVersion > *maxVersion) {
            uint16_t tmp = *minVersion;
            *minVersion = *maxVersion;
            *maxVersion = tmp;
        }
    }
    return 0;
}

static const char *VersionToStr(uint16_t version)
{
    switch (version) {
        case HITLS_VERSION_TLS10:
            return "TLS 1.0";
        case HITLS_VERSION_TLS11:
            return "TLS 1.1";
        case HITLS_VERSION_TLS12:
            return "TLS 1.2";
        case HITLS_VERSION_TLS13:
            return "TLS 1.3";
        default:
            return "unknown";
    }
}

/* Use the embedded OCSP response DER. The response is for the ocsp_client preset
 * certificate, which differs from the local demo certificate; openHiTLS does not
 * validate the response, so it only demonstrates the data flow. */
static void LoadOcspResponse(void)
{
    gRespData = gOcspRespDer;
    gRespLen = sizeof(gOcspRespDer);
    printf("[server] loaded %u-byte embedded OCSP response.\n", gRespLen);
}

/* Server stapling callback: called before the CertificateStatus message is
 * built (TLS 1.2) or the Certificate message (TLS 1.3). It is invoked once per
 * certificate; the response is returned directly via *outResp and is borrowed
 * for the handshake. The embedded DER is parsed once and reused, so no response
 * is leaked across invocations. */
static HITLS_OCSP_Resp *gRespCached = NULL;

static int32_t ServerStaplingCb(HITLS_Ctx *ctx, const HITLS_CERT_X509 *cert, uint32_t chainidx,
                                HITLS_OCSP_Resp **outResp, void *arg)
{
    (void)ctx;
    (void)cert;
    (void)arg;
    gServerCbCalled = 1;
    if (gRespCached == NULL) {
        BSL_Buffer encode = {(uint8_t *)gRespData, gRespLen};
        if (HITLS_OCSP_RespParseBuff(BSL_FORMAT_ASN1, &encode, &gRespCached) != HITLS_PKI_SUCCESS ||
            gRespCached == NULL) {
            printf("[server] stapling callback: cannot parse the OCSP response.\n");
            return HITLS_STAPLING_ERROR;
        }
    }
    *outResp = gRespCached;
    printf("[server] stapling callback: %u-byte OCSP response supplied (chainidx %u).\n", gRespLen, chainidx);
    return HITLS_STAPLING_SEND;
}

/* Client status callback: called after the stapling outcome is known.
 * Fetch and print the peer OCSP responses. */
static int32_t ClientStatusCb(HITLS_Ctx *ctx, void *arg)
{
    (void)arg;
    gClientCbCalled = 1;
    HITLS_OCSP_Resp **arr = NULL;
    uint32_t count = 0;
    if (HITLS_GetPeerOcspResponseList(ctx, &arr, &count) != HITLS_SUCCESS || arr == NULL || count == 0) {
        printf("[client] status callback: no peer OCSP response.\n");
        return HITLS_STATUS_OK;
    }
    printf("[client] status callback: %u peer OCSP response(s).\n", count);
    for (uint32_t i = 0; i < count; i++) {
        if (arr[i] == NULL) {
            printf("[client]   depth %u: (no response)\n", i);
        } else {
            int32_t status = -1;
            (void)HITLS_OCSP_RespCtrl(arr[i], HITLS_OCSP_RESP_GET_STATUS, &status, sizeof(status));
            printf("[client]   depth %u: OCSP response, status %d\n", i, status);
        }
    }
    return HITLS_STATUS_OK;
}

/* Protocol message trace callback: prints direction, content type and a short
 * hex dump of every TLS message exchanged. */
static void MsgTraceCb(int32_t writePoint, int32_t tlsVersion, int32_t contentType, const void *msg, uint32_t msgLen,
                       HITLS_Ctx *ctx, void *arg)
{
    (void)tlsVersion;
    (void)ctx;
    (void)arg;
    const char *dir = (writePoint == 0) ? ">>>" : "<<<";
    printf("[trace] %s content_type=%d len=%u\n", dir, contentType, msgLen);
    const uint8_t *p = (const uint8_t *)msg;
    uint32_t show = (msgLen > 16) ? 16 : msgLen;
    printf("[trace]   ");
    for (uint32_t i = 0; i < show; i++) {
        printf("%02x ", p[i]);
    }
    if (msgLen > 16) {
        printf("... (%u bytes total)", msgLen);
    }
    printf("\n");
}

static int32_t RunServer(void)
{
    int32_t ret = 0;
    int fd = -1;
    int infd = -1;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        printf("[server] socket failed\n");
        return -1;
    }
    int option = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        goto EXIT;
    }
    if (listen(fd, 1) != 0) {
        goto EXIT;
    }

    struct sockaddr_in peer;
    socklen_t peerLen = sizeof(peer);
    infd = accept(fd, (struct sockaddr *)&peer, &peerLen);
    if (infd < 0) {
        printf("[server] accept failed.\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLSConfig();
    if (config == NULL) {
        goto EXIT;
    }
    ret = HITLS_CFG_SetVersion(config, gServerMinVer, gServerMaxVer);
    if (ret != HITLS_SUCCESS) {
        printf(
            "[server] HITLS_CFG_SetVersion(0x%04x, 0x%04x) failed: 0x%x (the public config interface only supports tls1.2/tls1.3).\n",
            gServerMinVer, gServerMaxVer, ret);
        goto EXIT;
    }
    ret = HITLS_CFG_SetClientVerifySupport(config, false); /* do not ask for a client cert */
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    if (gServerCbEnabled) {
        ret = HITLS_CFG_SetStaplingCbPerCert(config, ServerStaplingCb, NULL);
        if (ret != HITLS_SUCCESS) {
            goto EXIT;
        }
    }
    if (gTraceEnabled) {
        ret = HITLS_CFG_SetMsgCb(config, MsgTraceCb);
        if (ret != HITLS_SUCCESS) {
            goto EXIT;
        }
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "root.der", &rootCA);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", &subCA);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_LoadCertFile(config, CERTS_PATH "server.der", TLS_PARSE_FORMAT_ASN1);
    HITLS_CFG_LoadKeyFile(config, CERTS_PATH "server.key.der", TLS_PARSE_FORMAT_ASN1);

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        goto EXIT;
    }
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        goto EXIT;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(infd), &infd);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        goto EXIT;
    }

    ret = HITLS_Accept(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("[server] HITLS_Accept failed: 0x%x.\n", ret);
        goto EXIT;
    }
    uint16_t negotiated = 0;
    (void)HITLS_GetNegotiatedVersion((HITLS_Ctx *)ctx, &negotiated);
    gServerNegotiatedVer = negotiated;
    printf("[server] negotiated TLS version: %s (0x%04x).\n", VersionToStr(negotiated), negotiated);
    printf("[server] handshake with stapling completed.\n");
    ret = 0;

EXIT:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    if (infd >= 0) {
        close(infd);
    }
    if (fd >= 0) {
        close(fd);
    }
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    return ret;
}

static int32_t RunClient(void)
{
    int32_t ret = 0;
    int fd = -1;
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    HITLS_X509_Cert *rootCA = NULL;
    HITLS_X509_Cert *subCA = NULL;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("[client] connect failed.\n");
        goto EXIT;
    }

    config = HITLS_CFG_NewTLSConfig();
    if (config == NULL) {
        printf("[client] HITLS_CFG_NewTLSConfig failed.\n");
        goto EXIT;
    }
    ret = HITLS_CFG_SetVersion(config, gClientMinVer, gClientMaxVer);
    if (ret != HITLS_SUCCESS) {
        printf(
            "[client] HITLS_CFG_SetVersion(0x%04x, 0x%04x) failed: 0x%x (the public config interface only supports tls1.2/tls1.3).\n",
            gClientMinVer, gClientMaxVer, ret);
        goto EXIT;
    }
    ret = HITLS_CFG_SetCheckKeyUsage(config, false);
    if (ret != HITLS_SUCCESS) {
        printf("[client] HITLS_CFG_SetCheckKeyUsage failed: 0x%x.\n", ret);
        goto EXIT;
    }
    if (gClientCbEnabled) {
        /* Request OCSP stapling and register the status callback. */
        ret = HITLS_CFG_SetStatusRequestType(config, HITLS_STATUS_REQUEST_TYPE_OCSP);
        if (ret != HITLS_SUCCESS) {
            printf("[client] HITLS_CFG_SetStatusRequestType failed: 0x%x.\n", ret);
            goto EXIT;
        }
        ret = HITLS_CFG_SetStatusCb(config, ClientStatusCb, NULL);
        if (ret != HITLS_SUCCESS) {
            printf("[client] HITLS_CFG_SetStatusCb failed: 0x%x.\n", ret);
            goto EXIT;
        }
    }
    if (gTraceEnabled) {
        ret = HITLS_CFG_SetMsgCb(config, MsgTraceCb);
        if (ret != HITLS_SUCCESS) {
            printf("[client] HITLS_CFG_SetMsgCb failed: 0x%x.\n", ret);
            goto EXIT;
        }
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "root.der", &rootCA);
    if (ret != HITLS_SUCCESS) {
        printf("[client] parse ca.der failed: 0x%x.\n", ret);
        goto EXIT;
    }
    ret = HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, CERTS_PATH "inter.der", &subCA);
    if (ret != HITLS_SUCCESS) {
        printf("[client] parse inter.der failed: 0x%x.\n", ret);
        goto EXIT;
    }
    HITLS_CFG_AddCertToStore(config, rootCA, TLS_CERT_STORE_TYPE_DEFAULT, true);
    HITLS_CFG_AddCertToStore(config, subCA, TLS_CERT_STORE_TYPE_DEFAULT, true);

    ctx = HITLS_New(config);
    if (ctx == NULL) {
        printf("[client] HITLS_New failed.\n");
        goto EXIT;
    }
    uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    if (uio == NULL) {
        printf("[client] BSL_UIO_New failed.\n");
        goto EXIT;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
    if (ret != HITLS_SUCCESS) {
        printf("[client] BSL_UIO_Ctrl failed: 0x%x.\n", ret);
        goto EXIT;
    }
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        printf("[client] HITLS_SetUio failed: 0x%x.\n", ret);
        goto EXIT;
    }

    ret = HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS) {
        printf("[client] HITLS_Connect failed: 0x%x.\n", ret);
        goto EXIT;
    }
    uint16_t negotiated = 0;
    (void)HITLS_GetNegotiatedVersion((HITLS_Ctx *)ctx, &negotiated);
    gClientNegotiatedVer = negotiated;
    printf("[client] negotiated TLS version: %s (0x%04x).\n", VersionToStr(negotiated), negotiated);
    printf("[client] handshake with stapling completed.\n");
    ret = 0;

EXIT:
    HITLS_Close(ctx);
    HITLS_Free(ctx);
    HITLS_CFG_FreeConfig(config);
    if (fd >= 0) {
        close(fd);
    }
    HITLS_X509_CertFree(rootCA);
    HITLS_X509_CertFree(subCA);
    BSL_UIO_Free(uio);
    return ret;
}

int main(int argc, char *argv[])
{
    int32_t ret = 0;
    pthread_t tid = 0;

    if (argc != 5 && argc != 6) {
        printf("Usage: %s <client_versions> <server_versions> <client_cb> <server_cb> [trace]\n", argv[0]);
        printf("  client_versions/server_versions: tls1.2|tls1.3, a range as min:max, e.g. tls1.2:tls1.3\n");
        printf("  (tls1.0/tls1.1 are not supported by the public config interface)\n");
        printf("  client_cb/server_cb: 1 to register the OCSP callback, 0 otherwise\n");
        printf("  trace: 1 to enable the per-message protocol trace, 0 (default) to disable it\n");
        return -1;
    }
    if (ParseVersionRange(argv[1], &gClientMinVer, &gClientMaxVer) != 0 ||
        ParseVersionRange(argv[2], &gServerMinVer, &gServerMaxVer) != 0) {
        printf("invalid version range: '%s' / '%s'.\n", argv[1], argv[2]);
        return -1;
    }
    gClientCbEnabled = (atoi(argv[3]) != 0);
    gServerCbEnabled = (atoi(argv[4]) != 0);
    gTraceEnabled = (argc == 6) ? (atoi(argv[5]) != 0) : 0;

    printf("client versions: %s, server versions: %s, client_cb: %d, server_cb: %d, trace: %d.\n", argv[1], argv[2],
           gClientCbEnabled, gServerCbEnabled, gTraceEnabled);

    /* Closing a socket peer triggers SIGPIPE on the other side; the demo
     * handles connection cleanup explicitly and must not be killed by it. */
    signal(SIGPIPE, SIG_IGN);

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x.\n", ret);
        return -1;
    }
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();

    LoadOcspResponse();

    if (pthread_create(&tid, NULL, (void *(*)(void *))RunServer, NULL) != 0) {
        printf("create server thread failed.\n");
        ret = -1;
        goto EXIT;
    }
    usleep(100 * 1000); /* let the server listen first */
    ret = RunClient();
    pthread_join(tid, NULL);

    printf("\n== summary ==\n");
    printf("negotiated TLS version: %s (0x%04x).\n", VersionToStr(gClientNegotiatedVer), gClientNegotiatedVer);
    printf("client OCSP callback registered: %d, invoked: %d.\n", gClientCbEnabled, gClientCbCalled);
    printf("server OCSP callback registered: %d, invoked: %d.\n", gServerCbEnabled, gServerCbCalled);

EXIT:
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
