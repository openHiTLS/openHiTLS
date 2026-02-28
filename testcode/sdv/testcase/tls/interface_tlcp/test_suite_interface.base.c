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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>
#include "securec.h"
#include "bsl_sal.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "conn_init.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "recv_process.h"
#include "frame_tls.h"
#include "frame_msg.h"
#include "simulate_io.h"
#include "parser_frame_msg.h"
#include "pack_frame_msg.h"
#include "frame_io.h"
#include "frame_link.h"
#include "cert.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "hlt.h"
#include "sctp_channel.h"
#include "logger.h"

#define READ_BUF_SIZE (18 * 1024)       /* Maximum length of the read message buffer */

typedef struct {
    HITLS_Config *config;
    FRAME_LinkObj *client;
    FRAME_LinkObj *server;
    HITLS_HandshakeState state;
    bool isClient;
    int32_t emsMode;
    bool isSupportClientVerify;
    bool isSupportNoClientCert;
    bool isServerExtendedMasterSecret;
    bool isSupportRenegotiation; /* Renegotiation support flag */
    bool needStopBeforeRecvCCS;  /* CCS test, so that the TRY_RECV_FINISH stops before the CCS message is received */
} HandshakeTestInfo;


int32_t SendHelloReq(HITLS_Ctx *ctx)
{
    /** Initialize the message buffer. */
    uint8_t buf[HS_MSG_HEADER_SIZE] = {0u};
    size_t len = HS_MSG_HEADER_SIZE;

    /** Write records. */
    return REC_Write(ctx, REC_TYPE_HANDSHAKE, buf, len);
}

#define TEST_CLIENT_SEND_FAIL 1

void TestSetCertPath(HLT_Ctx_Config *ctxConfig, char *SignatureType)
{
    if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA1", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA1")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA1_EE_PATH, RSA_SHA1_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA256", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA256")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA256_EE_PATH3, RSA_SHA256_PRIV_PATH3, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA384", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA384")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA384_EE_PATH, RSA_SHA384_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_RSA_PKCS1_SHA512", strlen("CERT_SIG_SCHEME_RSA_PKCS1_SHA512")) ==
                   0 ||
               strncmp(SignatureType,
                   "CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512",
                   strlen("CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512")) == 0) {
        HLT_SetCertPath(
            ctxConfig, RSA_SHA_CA_PATH, RSA_SHA_CHAIN_PATH, RSA_SHA512_EE_PATH, RSA_SHA512_PRIV_PATH, "NULL", "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA256_EE_PATH,
            ECDSA_SHA256_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA384_EE_PATH,
            ECDSA_SHA384_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType,
                   "CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512",
                   strlen("CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA_CA_PATH,
            ECDSA_SHA_CHAIN_PATH,
            ECDSA_SHA512_EE_PATH,
            ECDSA_SHA512_PRIV_PATH,
            "NULL",
            "NULL");
    } else if (strncmp(SignatureType, "CERT_SIG_SCHEME_ECDSA_SHA1", strlen("CERT_SIG_SCHEME_ECDSA_SHA1")) == 0) {
        HLT_SetCertPath(ctxConfig,
            ECDSA_SHA1_CA_PATH,
            ECDSA_SHA1_CHAIN_PATH,
            ECDSA_SHA1_EE_PATH,
            ECDSA_SHA1_PRIV_PATH,
            "NULL",
            "NULL");
    }
}
