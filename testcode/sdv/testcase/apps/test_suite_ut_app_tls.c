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
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "app_client.h"
#include "app_errno.h"
#include "app_provider.h"
#include "app_server.h"
#include "app_tls_common.h"
#include "stub_utils.h"
/* END_HEADER */

#define TLS_AUTH_CA "../testdata/tls/certificate/pem/rsa_sha256/ca.pem"
#define TLS_AUTH_INTER_CA "../testdata/tls/certificate/pem/rsa_sha256/inter.pem"
#define TLS_AUTH_CLIENT_CERT "../testdata/tls/certificate/pem/rsa_sha256/client.pem"
#define TLS_AUTH_CLIENT_KEY "../testdata/tls/certificate/pem/rsa_sha256/client.key.pem"
#define TLS_AUTH_SERVER_CERT "../testdata/tls/certificate/pem/rsa_sha256/server.pem"
#define TLS_AUTH_SERVER_KEY "../testdata/tls/certificate/pem/rsa_sha256/server.key.pem"
#define TLS_AUTH_SERVER_NAME "certificate.testend.com"
#define TLS_AUTH_WRONG_SERVER_NAME "wrong.testend.com"
#define TLS_AUTH_TIMEOUT_MS 5000
#define TLS_AUTH_WAIT_INTERVAL_US 10000
#define TLS_AUTH_IGNORE_CLIENT_RET INT32_MIN
#define TLS_AUTH_BIND_PLACEHOLDER "127.0.0.1:4433"
#define TLCP_AUTH_CA "../testdata/tls/certificate/der/sm2_cert_userid_and_san/ca.der"
#define TLCP_AUTH_INTER_CA "../testdata/tls/certificate/der/sm2_cert_userid_and_san/inter.der"
#define TLCP_AUTH_ENC_CERT "../testdata/tls/certificate/der/sm2_cert_userid_and_san/enc.der"
#define TLCP_AUTH_ENC_KEY "../testdata/tls/certificate/der/sm2_cert_userid_and_san/enc.key.der"
#define TLCP_AUTH_SIGN_CERT "../testdata/tls/certificate/der/sm2_cert_userid_and_san/sign.der"
#define TLCP_AUTH_SIGN_KEY "../testdata/tls/certificate/der/sm2_cert_userid_and_san/sign.key.der"
#define TLCP_AUTH_SERVER_NAME "localhost"
#define TLCP_AUTH_WRONG_SERVER_NAME "wrong.localhost"

STUB_DEFINE_RET2(int, CreateTCPListenSocket, APP_NetworkAddr *, int);
STUB_DEFINE_RET1(struct hostent *, gethostbyname, const char *);
STUB_DEFINE_RET1(int32_t, HITLS_Accept, HITLS_Ctx *);

static int g_serverReadyFd = -1;
static bool g_serverHandshakeObserved = false;
static bool g_serverHandshakeSucceeded = false;

static int STUB_CreateTCPListenSocket(APP_NetworkAddr *addr, int backlog)
{
    real_CreateTCPListenSocket_func_t realFunc = get_real_CreateTCPListenSocket();
    if (realFunc == NULL || addr == NULL) {
        return -1;
    }

    if (g_serverReadyFd >= 0) {
        addr->port = 0;
    }
    int listenFd = realFunc(addr, backlog);
    if (listenFd >= 0 && g_serverReadyFd >= 0) {
        struct sockaddr_in boundAddr = {0};
        socklen_t boundAddrLen = sizeof(boundAddr);
        int32_t boundPort = -1;
        if (getsockname(listenFd, (struct sockaddr *)&boundAddr, &boundAddrLen) == 0) {
            boundPort = (int32_t)ntohs(boundAddr.sin_port);
        }
        (void)write(g_serverReadyFd, &boundPort, sizeof(boundPort));
        (void)close(g_serverReadyFd);
        g_serverReadyFd = -1;
    }
    return listenFd;
}

static struct hostent *STUB_GetHostByName(const char *name)
{
    static char loopback[] = {127, 0, 0, 1};
    static char *addressList[] = {loopback, NULL};
    static struct hostent host = {
        .h_name = (char *)TLS_AUTH_SERVER_NAME,
        .h_aliases = NULL,
        .h_addrtype = AF_INET,
        .h_length = (int)sizeof(loopback),
        .h_addr_list = addressList,
    };

    if (name == NULL || (strcmp(name, TLS_AUTH_SERVER_NAME) != 0 &&
        strcmp(name, TLS_AUTH_WRONG_SERVER_NAME) != 0 &&
        strcmp(name, TLCP_AUTH_SERVER_NAME) != 0 &&
        strcmp(name, TLCP_AUTH_WRONG_SERVER_NAME) != 0)) {
        return NULL;
    }
    return &host;
}

static int32_t STUB_RecordHITLSAccept(HITLS_Ctx *ctx)
{
    real_HITLS_Accept_func_t realFunc = get_real_HITLS_Accept();
    if (realFunc == NULL) {
        return HITLS_APP_ERR_HANDSHAKE;
    }

    int32_t ret = realFunc(ctx);
    if (ret == HITLS_SUCCESS) {
        g_serverHandshakeObserved = true;
        g_serverHandshakeSucceeded = true;
    } else if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_REC_NORMAL_IO_BUSY) {
        g_serverHandshakeObserved = true;
        g_serverHandshakeSucceeded = false;
    }
    return ret;
}

static bool WaitForServerReady(int fd, int32_t *boundPort)
{
    if (boundPort == NULL) {
        return false;
    }
    struct pollfd pollFd = {
        .fd = fd,
        .events = POLLIN,
    };
    int ret;
    do {
        ret = poll(&pollFd, 1, TLS_AUTH_TIMEOUT_MS);
    } while (ret < 0 && errno == EINTR);
    if (ret != 1 || (pollFd.revents & POLLIN) == 0) {
        return false;
    }

    ssize_t readLen;
    do {
        readLen = read(fd, boundPort, sizeof(*boundPort));
    } while (readLen < 0 && errno == EINTR);
    return readLen == sizeof(*boundPort) && *boundPort > 0 && *boundPort <= UINT16_MAX;
}

static bool WaitForServerExit(pid_t pid, int *status)
{
    int waitCount = TLS_AUTH_TIMEOUT_MS * 1000 / TLS_AUTH_WAIT_INTERVAL_US;
    while (waitCount-- > 0) {
        pid_t ret = waitpid(pid, status, WNOHANG);
        if (ret == pid) {
            return true;
        }
        if (ret < 0 && errno != EINTR) {
            return false;
        }
        (void)usleep(TLS_AUTH_WAIT_INTERVAL_US);
    }
    return false;
}

static void StopServer(pid_t pid)
{
    if (pid <= 0) {
        return;
    }

    int status = 0;
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid || (ret < 0 && errno == ECHILD)) {
        return;
    }

    (void)kill(pid, SIGTERM);
    if (WaitForServerExit(pid, &status)) {
        return;
    }
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
}

static int RunServer(int argc, char **argv)
{
    if (APP_Create_LibCtx() == NULL) {
        return HITLS_APP_INIT_FAILED;
    }
    int ret = HITLS_ServerMain(argc, argv);
    HITLS_APP_FreeLibCtx();
    return ret;
}

static int RunClient(int argc, char **argv)
{
    if (APP_Create_LibCtx() == NULL) {
        return HITLS_APP_INIT_FAILED;
    }
    int ret = HITLS_ClientMain(argc, argv);
    HITLS_APP_FreeLibCtx();
    return ret;
}

static bool RunHandshakeProcesses(char **serverArgv, size_t serverArgc, char **clientArgv, int clientArgc,
    char *clientPort, size_t clientPortSize, int expectedClientRet, bool expectServerHandshakeSuccess)
{
    int readyPipe[2];
    if (pipe(readyPipe) != 0) {
        return false;
    }

    pid_t serverPid = fork();
    if (serverPid < 0) {
        (void)close(readyPipe[0]);
        (void)close(readyPipe[1]);
        return false;
    }
    if (serverPid == 0) {
        (void)close(readyPipe[0]);
        g_serverReadyFd = readyPipe[1];
        g_serverHandshakeObserved = false;
        g_serverHandshakeSucceeded = false;
        STUB_REPLACE(CreateTCPListenSocket, STUB_CreateTCPListenSocket);
        STUB_REPLACE(HITLS_Accept, STUB_RecordHITLSAccept);
        int ret = RunServer((int)serverArgc, serverArgv);
        if (g_serverReadyFd >= 0) {
            (void)close(g_serverReadyFd);
        }
        bool serverResultMatches = g_serverHandshakeObserved &&
            g_serverHandshakeSucceeded == expectServerHandshakeSuccess;
        _exit(ret == HITLS_APP_SUCCESS && serverResultMatches ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    (void)close(readyPipe[1]);
    int32_t boundPort = -1;
    if (!WaitForServerReady(readyPipe[0], &boundPort)) {
        (void)close(readyPipe[0]);
        StopServer(serverPid);
        return false;
    }
    (void)close(readyPipe[0]);
    int portLen = snprintf(clientPort, clientPortSize, "%d", boundPort);
    if (portLen < 0 || (size_t)portLen >= clientPortSize) {
        StopServer(serverPid);
        return false;
    }

    void (*oldSigpipeHandler)(int) = signal(SIGPIPE, SIG_IGN);
    STUB_REPLACE(gethostbyname, STUB_GetHostByName);
    int clientRet = RunClient(clientArgc, clientArgv);
    STUB_RESTORE(gethostbyname);
    if (oldSigpipeHandler != SIG_ERR) {
        (void)signal(SIGPIPE, oldSigpipeHandler);
    }

    int serverStatus = 0;
    bool serverExited = WaitForServerExit(serverPid, &serverStatus);
    if (!serverExited) {
        StopServer(serverPid);
    }
    bool clientResultMatches = expectedClientRet == TLS_AUTH_IGNORE_CLIENT_RET || clientRet == expectedClientRet;
    return clientResultMatches && serverExited &&
        WIFEXITED(serverStatus) && WEXITSTATUS(serverStatus) == EXIT_SUCCESS;
}

static bool RunTlsHandshake(const char *protocol, const char *cipher, const char *serverName,
    bool provideClientCert, int expectedClientRet, bool expectServerHandshakeSuccess)
{
    if (get_real_CreateTCPListenSocket() == NULL) {
        return false;
    }

    char portString[8] = {0};

    char *serverArgv[] = {
        "s_server", "-accept", TLS_AUTH_BIND_PLACEHOLDER, (char *)protocol,
        "-cipher", (char *)cipher,
        "-CAfile", TLS_AUTH_CA, "-chainCAfile", TLS_AUTH_INTER_CA,
        "-cert", TLS_AUTH_SERVER_CERT, "-key", TLS_AUTH_SERVER_KEY,
        "-accept_once", "-quiet",
    };
    char *clientArgv[18];
    int clientArgc = 0;
    clientArgv[clientArgc++] = "s_client";
    clientArgv[clientArgc++] = "-host";
    clientArgv[clientArgc++] = (char *)serverName;
    clientArgv[clientArgc++] = "-port";
    clientArgv[clientArgc++] = portString;
    clientArgv[clientArgc++] = (char *)protocol;
    clientArgv[clientArgc++] = "-cipher";
    clientArgv[clientArgc++] = (char *)cipher;
    clientArgv[clientArgc++] = "-CAfile";
    clientArgv[clientArgc++] = TLS_AUTH_CA;
    clientArgv[clientArgc++] = "-chainCAfile";
    clientArgv[clientArgc++] = TLS_AUTH_INTER_CA;
    if (provideClientCert) {
        clientArgv[clientArgc++] = "-cert";
        clientArgv[clientArgc++] = TLS_AUTH_CLIENT_CERT;
        clientArgv[clientArgc++] = "-key";
        clientArgv[clientArgc++] = TLS_AUTH_CLIENT_KEY;
    }
    clientArgv[clientArgc++] = "-prexit";
    clientArgv[clientArgc++] = "-quiet";

    return RunHandshakeProcesses(serverArgv, sizeof(serverArgv) / sizeof(serverArgv[0]),
        clientArgv, clientArgc, portString, sizeof(portString), expectedClientRet, expectServerHandshakeSuccess);
}

static bool RunTlcpHandshake(const char *cipher, const char *serverName, bool provideClientCert,
    int expectedClientRet, bool expectServerHandshakeSuccess)
{
    if (get_real_CreateTCPListenSocket() == NULL) {
        return false;
    }

    char portString[8] = {0};

    char *serverArgv[] = {
        "s_server", "-accept", TLS_AUTH_BIND_PLACEHOLDER, "-tlcp", "-cipher", (char *)cipher,
        "-CAfile", TLCP_AUTH_CA, "-chainCAfile", TLCP_AUTH_INTER_CA,
        "-tlcp_enc_cert", TLCP_AUTH_ENC_CERT, "-tlcp_enc_key", TLCP_AUTH_ENC_KEY,
        "-tlcp_sign_cert", TLCP_AUTH_SIGN_CERT, "-tlcp_sign_key", TLCP_AUTH_SIGN_KEY,
        "-certform", "DER", "-keyform", "DER", "-accept_once", "-quiet",
    };
    char *clientArgv[26];
    int clientArgc = 0;
    clientArgv[clientArgc++] = "s_client";
    clientArgv[clientArgc++] = "-host";
    clientArgv[clientArgc++] = (char *)serverName;
    clientArgv[clientArgc++] = "-port";
    clientArgv[clientArgc++] = portString;
    clientArgv[clientArgc++] = "-tlcp";
    clientArgv[clientArgc++] = "-cipher";
    clientArgv[clientArgc++] = (char *)cipher;
    clientArgv[clientArgc++] = "-CAfile";
    clientArgv[clientArgc++] = TLCP_AUTH_CA;
    clientArgv[clientArgc++] = "-chainCAfile";
    clientArgv[clientArgc++] = TLCP_AUTH_INTER_CA;
    if (provideClientCert) {
        clientArgv[clientArgc++] = "-tlcp_enc_cert";
        clientArgv[clientArgc++] = TLCP_AUTH_ENC_CERT;
        clientArgv[clientArgc++] = "-tlcp_enc_key";
        clientArgv[clientArgc++] = TLCP_AUTH_ENC_KEY;
        clientArgv[clientArgc++] = "-tlcp_sign_cert";
        clientArgv[clientArgc++] = TLCP_AUTH_SIGN_CERT;
        clientArgv[clientArgc++] = "-tlcp_sign_key";
        clientArgv[clientArgc++] = TLCP_AUTH_SIGN_KEY;
    }
    clientArgv[clientArgc++] = "-certform";
    clientArgv[clientArgc++] = "DER";
    clientArgv[clientArgc++] = "-keyform";
    clientArgv[clientArgc++] = "DER";
    clientArgv[clientArgc++] = "-prexit";
    clientArgv[clientArgc++] = "-quiet";

    return RunHandshakeProcesses(serverArgv, sizeof(serverArgv) / sizeof(serverArgv[0]),
        clientArgv, clientArgc, portString, sizeof(portString), expectedClientRet, expectServerHandshakeSuccess);
}

/**
 * @test UT_HITLS_APP_TlsMutualAuth_TC001
 * @spec  -
 * @title Test a successful TLS mutual-authentication handshake between s_server and s_client
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlsMutualAuth_TC001(char *protocol, char *cipher)
{
    ASSERT_TRUE(RunTlsHandshake(protocol, cipher, TLS_AUTH_SERVER_NAME,
        true, HITLS_APP_SUCCESS, true));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_TlsMutualAuth_TC002
 * @spec  -
 * @title Test that the server rejects a TLS client without a certificate
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlsMutualAuth_TC002(char *protocol, char *cipher)
{
    /* A TLS 1.3 client may finish -prexit before receiving the server's rejection alert. */
    ASSERT_TRUE(RunTlsHandshake(protocol, cipher, TLS_AUTH_SERVER_NAME,
        false, TLS_AUTH_IGNORE_CLIENT_RET, false));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_TlsMutualAuth_TC003
 * @spec  -
 * @title Test that the client rejects a server certificate with a mismatched hostname
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlsMutualAuth_TC003(char *protocol, char *cipher)
{
    ASSERT_TRUE(RunTlsHandshake(protocol, cipher, TLS_AUTH_WRONG_SERVER_NAME,
        true, HITLS_APP_ERR_HANDSHAKE, false));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_TlcpMutualAuth_TC001
 * @spec  -
 * @title Test a successful TLCP mutual-authentication handshake with SM2 certificates
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlcpMutualAuth_TC001(char *cipher)
{
    ASSERT_TRUE(RunTlcpHandshake(cipher, TLCP_AUTH_SERVER_NAME,
        true, HITLS_APP_SUCCESS, true));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_TlcpMutualAuth_TC002
 * @spec  -
 * @title Test that a TLCP server rejects a client without SM2 certificates
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlcpMutualAuth_TC002(char *cipher)
{
    ASSERT_TRUE(RunTlcpHandshake(cipher, TLCP_AUTH_SERVER_NAME,
        false, TLS_AUTH_IGNORE_CLIENT_RET, false));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_TlcpMutualAuth_TC003
 * @spec  -
 * @title Test that a TLCP client rejects an SM2 server certificate with a mismatched hostname
 */
/* BEGIN_CASE */
void UT_HITLS_APP_TlcpMutualAuth_TC003(char *cipher)
{
    ASSERT_TRUE(RunTlcpHandshake(cipher, TLCP_AUTH_WRONG_SERVER_NAME,
        true, HITLS_APP_ERR_HANDSHAKE, false));

EXIT:
    STUB_RESTORE(gethostbyname);
    return;
}
/* END_CASE */
