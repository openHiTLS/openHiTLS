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

#ifndef STATUS_REQUEST_H
#define STATUS_REQUEST_H

#include "tls.h"
#include "hs_msg.h"
#include "parse_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 6066: whether a ServerHello status_request acknowledgment is legal for
 * the negotiated protocol (stream TLS up to 1.2; TLS 1.3 answers in
 * CertificateEntry instead). Shared by the client parse path and the client
 * ServerHello extension check so the version rule stays in one place. */
bool IsServerHelloStatusRequestValid(const TLS_Ctx *ctx);

#ifdef HITLS_TLS_HOST_CLIENT
/* Client: pack the status_request extension in the ClientHello. */
int32_t PackClientStatusRequest(const TLS_Ctx *ctx, PackPacket *pkt);

/* Client: parse the empty status_request acknowledgment in the ServerHello
 * (stream TLS up to 1.2; TLS 1.3 answers in CertificateEntry instead). */
int32_t ParseServerStatusRequest(ParsePacket *pkt);

/* Client (stream TLS up to 1.2): process a received CertificateStatus message. */
int32_t ClientRecvCertificateStatus(TLS_Ctx *ctx, const HS_Msg *hsMsg);

/* Client (TLS 1.3): parse a CertificateEntry status_request extension and store the
 * decoded OCSP response at chainidx. */
int32_t ParseCertEntryOcspStatus(TLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, uint32_t chainidx);

/* Client: notify the application once the server flight is fully received so it
 * can decide on the stapling outcome — after ServerHelloDone on stream TLS
 * 1.0-1.2, after the server Finished on TLS 1.3. */
int32_t ClientNotifyOcspStatus(TLS_Ctx *ctx);
#endif /* HITLS_TLS_HOST_CLIENT */

#ifdef HITLS_TLS_HOST_SERVER
/* Server: pack the empty status_request acknowledgment in the ServerHello
 * (stream TLS up to 1.2; TLS 1.3 answers in CertificateEntry instead). */
int32_t PackServerStatusRequest(const TLS_Ctx *ctx, PackPacket *pkt);

/* Server: parse the status_request extension in the ClientHello (stream TLS 1.0-1.3). */
int32_t ParseClientStatusRequest(ParsePacket *pkt, ClientHelloMsg *msg);

/* Server (TLS 1.2): fetch the EE certificate's OCSP response from the
 * per-certificate callback after the certificate chain has been selected
 * (called after ProcessCertCallback in ServerPostProcessClientHello). */
int32_t ServerFetchStaplingEeResp(TLS_Ctx *ctx);

/* Server (stream TLS up to 1.2): build the CertificateStatus handshake message body. */
int32_t PackCertificateStatus(const TLS_Ctx *ctx, PackPacket *pkt);

/* Server (stream TLS up to 1.2): send the CertificateStatus message and advance the state machine. */
int32_t ServerSendCertificateStatusProcess(TLS_Ctx *ctx);

/* Server (TLS 1.3): pack a CertificateEntry status_request extension at chainidx. */
int32_t PackCertEntryOcspStatus(TLS_Ctx *ctx, HITLS_CERT_X509 *cert, PackPacket *pkt, uint32_t chainidx);

/* Server: reports whether the server sends a CertificateStatus message (stream
 * TLS up to 1.2; TLS 1.3 embeds the response in CertificateEntry instead). The
 * application callback is invoked when the status_request extension is parsed.
 * On success *needSend holds the decision; real failures (invalid response,
 * encode/OOM) are propagated so the caller can abort the handshake, matching
 * the TLS 1.3 CertificateEntry path. */
int32_t ServerNeedSendCertificateStatus(const TLS_Ctx *ctx, bool *needSend);
#endif /* HITLS_TLS_HOST_SERVER */

/* Release the OCSP stapling state owned by the ctx. */
void CleanOcspStapling(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STATUS_REQUEST_H */
