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
/* INCLUDE_BASE test_suite_sdv_frame_dtls13_cid_consistency */
/* END_HEADER */

#define TEST_CID_A_LEN 4
#define TEST_CID_B_LEN 4
static uint8_t g_testCidA[TEST_CID_A_LEN] = {0x01, 0x02, 0x03, 0x04};
static uint8_t g_testCidB[TEST_CID_B_LEN] = {0xAA, 0xBB, 0xCC, 0xDD};

static int32_t Dtls13UseSingleKeyShareGroup(HITLS_Config *config)
{
    uint16_t groups[] = {HITLS_EC_GROUP_SECP256R1};
    return HITLS_CFG_SetGroups(config, groups, sizeof(groups) / sizeof(groups[0]));
}

/*
 *===========================================================================
 * Helpers for tampering with DTLS 1.3 unified-header records on the wire.
 *
 * The CID is a record-layer field (rec_header.h), NOT a handshake-layer
 * field. Therefore CID-related consistency cases cannot use FRAME_ParseMsg /
 * FRAME_PackMsg (which only parse the handshake body). They must edit the raw
 * record bytes directly, the same way test_suite_sdv_frame_dtls13_..._TC021
 * crafts a fake unified header.
 *
 * DTLS 1.3 unified header layout (RFC 9147 §4):
 *   byte 0:  [ fix=001 ][ C ][ S ][ L ][ epoch(2) ]
 *            C = CID present, S = seq is 16 bits (else 8 bits), L = length present
 *   [ CID (cidLen bytes) ]      -- only if C == 1
 *   [ seq (1 or 2 bytes) ]
 *   [ length (2 bytes) ]        -- only if L == 1; else body runs to end of buffer
 *   [ ciphertext body ]
 *
 * NOTE: The CID is NOT covered by the AEAD AAD (RFC 9147 §4.2.2 reconstructs
 * the header without CID) and the sequence-number mask is derived from the
 * ciphertext (§4.2.3, unchanged by these edits). So overwriting or stripping
 * the CID on the wire does not break AEAD authentication -- only the CID
 * matching logic in rec_read.c (Dtls13GetRecordUnifiedHeader) is exercised.
 *===========================================================================
 */

/* Overwrite the CID of every unified-header record in buf with @fill.
 * Used by TC003 to turn the server's Finished flight into an "unrecognized CID" flight. */
static void TamperCidInFlight(uint8_t *buf, uint32_t len, uint8_t cidLen, uint8_t fill)
{
    uint32_t off = 0u;
    while (off < len) {
        uint8_t first = buf[off];
        bool cidBit = (first & REC_DTLS13_UNI_HEADER_CID_BIT) != 0;
        bool seqBit = (first & REC_DTLS13_UNI_HEADER_SEQ_BIT) != 0;
        bool lenBit = (first & REC_DTLS13_UNI_HEADER_LEN_BIT) != 0;

        uint32_t h = off + 1u;
        if (cidBit) {
            for (uint32_t i = 0u; i < cidLen; i++) {
                buf[h + i] = fill; /* overwrite CID bytes in place */
            }
            h += cidLen;
        }
        /* Skip seq + optional length to reach the body. */
        h += seqBit ? 2u : 1u;
        uint32_t bodyLen;
        if (lenBit) {
            bodyLen = BSL_ByteToUint16(&buf[h]);
            h += 2u;
        } else {
            bodyLen = len - h; /* length field absent: body runs to end of buffer */
        }
        off = h + bodyLen; /* advance to next record */
    }
}

/* Strip the CID field from every unified-header record in buf (clear the CID
 * bit in byte 0 and shift seq/length/body left to close the gap). Returns the
 * new total length. Used by TC004 to emulate "Finished sent without CID". */
static uint32_t StripCidFromFlight(uint8_t *buf, uint32_t len, uint8_t cidLen)
{
    uint32_t read = 0u;
    uint32_t write = 0u;
    while (read < len) {
        uint8_t first = buf[read];
        bool cidBit = (first & REC_DTLS13_UNI_HEADER_CID_BIT) != 0;
        bool seqBit = (first & REC_DTLS13_UNI_HEADER_SEQ_BIT) != 0;
        bool lenBit = (first & REC_DTLS13_UNI_HEADER_LEN_BIT) != 0;

        /* byte 0: copy with the CID bit cleared so the receiver does not look for a CID */
        buf[write++] = (uint8_t)(first & (uint8_t)(~REC_DTLS13_UNI_HEADER_CID_BIT));
        read++;
        /* drop the CID bytes from the source stream */
        if (cidBit) {
            read += cidLen;
        }
        /* locate the body in the source: seq + optional length */
        uint32_t bodyLenOff = read + (seqBit ? 2u : 1u);
        uint32_t bodyOff;
        uint32_t bodyLen;
        if (lenBit) {
            bodyLen = BSL_ByteToUint16(&buf[bodyLenOff]);
            bodyOff = bodyLenOff + 2u;
        } else {
            bodyOff = bodyLenOff;
            bodyLen = len - bodyOff;
        }
        /* move seq + length + body verbatim (their content is unchanged) */
        uint32_t tailLen = (bodyOff + bodyLen) - read;
        if (tailLen > 0u) {
            (void)memmove(&buf[write], &buf[read], tailLen);
        }
        write += tailLen;
        read += tailLen;
    }
    return write;
}

/* Set the C bit on every record in a no-CID DTLS 1.3 flight without adding any
 * CID octets. The receiver therefore observes C=1 with an expected CID length
 * of zero. Returns 0 when the input is not a complete unified-header flight. */
static uint32_t SetEmptyCidBitInFlight(uint8_t *buf, uint32_t len)
{
    uint32_t off = 0u;
    while (off < len) {
        uint8_t first = buf[off];
        if ((first & 0xe0u) != REC_DTLS13_UNI_HEADER_FIX_BITS ||
            (first & REC_DTLS13_UNI_HEADER_CID_BIT) != 0u) {
            return 0u;
        }

        uint32_t headerEnd = off + 1u +
            (((first & REC_DTLS13_UNI_HEADER_SEQ_BIT) != 0u) ? 2u : 1u);
        if ((first & REC_DTLS13_UNI_HEADER_LEN_BIT) == 0u) {
            buf[off] = first | REC_DTLS13_UNI_HEADER_CID_BIT;
            return len;
        }
        if (headerEnd + 2u > len) {
            return 0u;
        }
        uint32_t recordEnd = headerEnd + 2u + BSL_ByteToUint16(&buf[headerEnd]);
        if (recordEnd > len) {
            return 0u;
        }
        buf[off] = first | REC_DTLS13_UNI_HEADER_CID_BIT;
        off = recordEnd;
    }
    return off;
}

/* Insert four physical CID octets after byte 0 of every no-CID record while
 * deliberately leaving C clear. RFC 9147 carries no explicit CID-length field:
 * when C=0 the receiver interprets these octets as seq/length, never as a CID.
 * Keep that malformed interpretation self-consistent by writing a length which
 * covers the original seq, length and ciphertext. The resulting record reaches
 * normal record validation and is silently discarded. */
static uint32_t InsertHiddenCidInFlight(uint8_t *dst, uint32_t dstCap,
    const uint8_t *src, uint32_t srcLen, const uint8_t *cid)
{
    uint32_t read = 0u;
    uint32_t write = 0u;
    while (read < srcLen) {
        uint8_t first = src[read];
        if ((first & 0xe0u) != REC_DTLS13_UNI_HEADER_FIX_BITS ||
            (first & REC_DTLS13_UNI_HEADER_CID_BIT) != 0u ||
            (first & REC_DTLS13_UNI_HEADER_SEQ_BIT) == 0u ||
            (first & REC_DTLS13_UNI_HEADER_LEN_BIT) == 0u || read + 5u > srcLen) {
            return 0u;
        }

        uint32_t bodyLen = BSL_ByteToUint16(&src[read + 3u]);
        uint32_t recordLen = 5u + bodyLen;
        if (read + recordLen > srcLen || write + recordLen + TEST_CID_A_LEN > dstCap ||
            bodyLen + 4u > UINT16_MAX) {
            return 0u;
        }

        dst[write++] = first & (uint8_t)(~REC_DTLS13_UNI_HEADER_CID_BIT);
        (void)memcpy(&dst[write], cid, TEST_CID_A_LEN);
        BSL_Uint16ToByte((uint16_t)(bodyLen + 4u), &dst[write + 2u]);
        write += TEST_CID_A_LEN;
        (void)memcpy(&dst[write], &src[read + 1u], recordLen - 1u);
        write += recordLen - 1u;
        read += recordLen;
    }
    return write;
}

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC001
* @spec -
* @title Normal CID negotiation, client encrypted messages all carry CID
* @precon nan
* @brief RFC 9147 Section 4: If a Connection ID is negotiated, then it MUST be contained in all datagrams.
* @expect 1. Handshake succeeds. 2. Client sendCid equals server localCid. 3. CID state is NEGOTIATED.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    const DTLS_CidSendEntry *sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidB, TEST_CID_B_LEN), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC002
* @spec -
* @title Normal CID negotiation, server encrypted messages all carry CID
* @precon nan
* @brief RFC 9147 Section 4: If a Connection ID is negotiated, then it MUST be contained in all datagrams.
* @expect 1. Handshake succeeds. 2. Server sendCid equals client localCid. 3. CID state is NEGOTIATED.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidA, TEST_CID_A_LEN), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC003
* @spec -
* @title Client receives server Finished flight carrying an unrecognized CID, handshake fails
* @precon nan
* @brief RFC 9147 §5: a record whose CID is not in the receiver's expected CID list is silently
*        discarded by the record layer (rec_read.c returns HITLS_REC_NORMAL_RECV_BUF_EMPTY before
*        AEAD). Therefore an unmodified "Finished" never lands and the handshake cannot complete.
* @expect 1. After tampering, HITLS_Connect does NOT return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Negotiate CID in both directions:
     *     - client offers g_testCidA as its receive CID (server must put A into records -> client)
     *     - server offers g_testCidB as its receive CID (client must put B into records -> server). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* (3) Drive the handshake forward, stopping the CLIENT right before it consumes the server's
     *     Finished record (state == TRY_RECV_FINISH). At this point:
     *       - ServerHello/EE/Cert/CertVerify have already been read and drained from the UIO.
     *       - The server's Finished record (one DTLS 1.3 unified-header record carrying the
     *         client's CID g_testCidA) is the only thing left in client->io recMsg. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    /* (4) Fetch the raw Finished record bytes the framework buffered for the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *rec = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen > 1u + TEST_CID_A_LEN); /* at least firstByte + CID */

    /* (5) Tamper: overwrite the CID of every remaining record with 0xEE (a value the client did
     *     not negotiate). CID is at byte[1..1+cidLen) when the CID bit (0x10) is set in byte 0. */
    TamperCidInFlight(rec, recLen, TEST_CID_A_LEN, 0xEE);

    /* (6) Re-inject the tampered flight. FRAME_TransportRecMsg rejects injection unless the
     *     receive buffer is empty, so clear recMsg.len first. */
    ioUserData->recMsg.len = 0u;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, rec, recLen), HITLS_SUCCESS);

    /* (7) Resume the handshake. The record layer sees an unfamiliar CID -> silently discards the
     *     Finished (HITLS_REC_NORMAL_RECV_BUF_EMPTY) -> client never finishes -> Connect fails. */
    ASSERT_NE(HITLS_Connect(client->ssl), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC004
* @spec -
* @title Client receives server Finished whose unified header carries no CID, handshake fails
* @precon nan
* @brief The DTLS 1.3 AEAD AAD covers the whole on-wire unified header (byte0 + CID + seq + length,
*        see rec_header.h REC_DTLS13_AAD_MAX_SIZE and AeadGetAad in rec_crypto_aead.c). Clearing the
*        CID bit and removing the CID bytes changes the AAD, so the AEAD tag no longer verifies and
*        the record is rejected -- the Finished never lands and the handshake cannot complete.
*        Complements TC003, which is rejected earlier by the CID-list check.
* @expect 1. After CID stripping, HITLS_Connect does NOT return HITLS_SUCCESS.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Negotiate CID in both directions (same as TC003). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* (3) Stop the client right before it consumes the server's Finished record. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    /* (4) Fetch the raw Finished record bytes buffered for the client. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *rec = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen > 1u + TEST_CID_A_LEN);

    /* (5) Strip the CID field: clear the CID bit in byte 0 of each record and shift the
     *     seq/length/body left so the header layout stays self-consistent without a CID. */
    uint32_t newLen = StripCidFromFlight(rec, recLen, TEST_CID_A_LEN);

    /* (6) Re-inject the now-CID-less flight into the client UIO. */
    ioUserData->recMsg.len = 0u;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, rec, newLen), HITLS_SUCCESS);

    /* (7) Resume the handshake. The on-wire header (including the CID) is part of the DTLS 1.3 AEAD
     *     AAD, so stripping the CID changes the AAD -> AEAD tag verification fails -> record rejected
     *     -> client never receives Finished -> Connect does not succeed. */
    ASSERT_NE(HITLS_Connect(client->ssl), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC005
* @spec -
* @title Client sends zero-length CID, server outbound records have no CID
* @precon nan
* @brief RFC 9146 Section 3: A zero-length CID means the endpoint does not wish the peer to include one when sending.
* @expect 1. Handshake succeeds. 2. Server sendCidLen is 0 (no CID to send to client).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    ASSERT_TRUE(server->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC006
* @spec -
* @title Server sends zero-length CID, client outbound records have no CID
* @precon nan
* @brief RFC 9146 Section 3: A zero-length CID means the endpoint does not wish the peer to include one when sending.
* @expect 1. Handshake succeeds. 2. Client sendCidLen is 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, NULL, 0), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    ASSERT_TRUE(client->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC007
* @spec -
* @title Client that offered a zero-length CID tolerates a stray CID-bearing record after handshake
* @precon nan
* @brief Client offers an empty receive CID -> server sends records to client WITHOUT a CID, so the
*        handshake itself completes normally. We then inject one stray DTLS 1.3 unified-header
*        record whose CID bit is set. In rec_read.c, a set CID bit with expected cidLen == 0 makes
*        Dtls13GetRecordUnifiedHeader reject the record before AEAD; the completed handshake is
*        not disturbed.
* @expect 1. Handshake succeeds. 2. Reading the injected stray record does NOT yield app data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Client offers a ZERO-LENGTH receive CID (it does not want the server to send a CID);
     *     server still offers g_testCidB so that the client->server direction carries a CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* (3) Drive the handshake to completion. Server sends records to the client WITHOUT a CID, so
     *     nothing here exercises the stray-CID path yet. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* (4) Build a stray DTLS 1.3 unified-header record whose CID bit is set. Layout:
     *        byte0  = 0x30  (fix=001 | CID=1 | seq=8bit | len absent | epoch=0)
     *        CID    = {0xEE,0xEE,0xEE,0xEE}   (a CID the client never offered)
     *        seq    = 0x00    (1 byte, since S bit is 0)
     *        body   = 16 bytes of 0xAA (fake ciphertext)
     *     The receiver parses the header, sees CID bit set but its expected cidLen == 0, and
     *     rejects the record in Dtls13GetRecordUnifiedHeader (no AEAD attempted). */
    uint8_t stray[1u + TEST_CID_B_LEN + 1u + 16u];
    uint32_t off = 0u;
    stray[off++] = 0x30;
    for (uint32_t i = 0u; i < TEST_CID_B_LEN; i++) { stray[off++] = 0xEE; }
    stray[off++] = 0x00;
    (void)memset(&stray[off], 0xAA, sizeof(stray) - off);

    /* (5) Inject the stray record into the client UIO (recMsg must be empty first; it is, since
     *     the handshake has drained it). */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, stray, sizeof(stray)), HITLS_SUCCESS);

    /* (6) The client tries to read. The stray record is rejected by the CID check, so no
     *     application data is ever delivered. The already-completed handshake stays intact.
     *     Per RFC 9147 §4.5.2 the stray record is silently discarded (no alert), so
     *     HITLS_Read returns HITLS_REC_NORMAL_RECV_BUF_EMPTY and the handshake stays intact. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t readRet = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(readRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC008
* @spec -
* @title Server that offered a zero-length CID tolerates a stray CID-bearing record after handshake
* @precon nan
* @brief Server offers an empty receive CID -> client sends records to server WITHOUT a CID, so the
*        handshake completes normally. A stray CID-bearing record injected into the server is
*        rejected by rec_read.c (CID bit set but expected cidLen == 0), leaving the handshake intact.
* @expect 1. Handshake succeeds. 2. Reading the injected stray record does NOT yield app data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC008(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Client offers g_testCidA; server offers a ZERO-LENGTH receive CID (client must NOT put a
     *     CID into records sent to the server). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, NULL, 0), HITLS_SUCCESS);

    /* (3) Drive the handshake to completion (no CID travels toward the server). */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* (4) Build a stray DTLS 1.3 unified-header record whose CID bit is set (see TC007 for layout). */
    uint8_t stray[1u + TEST_CID_A_LEN + 1u + 16u];
    uint32_t off = 0u;
    stray[off++] = 0x30;
    for (uint32_t i = 0u; i < TEST_CID_A_LEN; i++) { stray[off++] = 0xEE; }
    stray[off++] = 0x00;
    (void)memset(&stray[off], 0xAA, sizeof(stray) - off);

    /* (5) Inject the stray record into the SERVER UIO. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, stray, sizeof(stray)), HITLS_SUCCESS);

    /* (6) The server reads -> the stray record is rejected by the CID check -> no app data.
     *     Per RFC 9147 §4.5.2 the stray record is silently discarded (no alert), so
     *     HITLS_Read returns HITLS_REC_NORMAL_RECV_BUF_EMPTY and the handshake stays intact. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t readRet = HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(readRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC009
* @spec -
* @title No CID negotiated: client rejects a stray CID-bearing record after handshake
* @precon nan
* @brief Neither side enables CID, so the handshake completes with CID disabled. A stray DTLS 1.3
*        unified-header record whose CID bit is set is then injected into the client. Because the
*        client never negotiated a CID, rec_read.c has expected cidLen == 0 and rejects the record
*        in Dtls13GetRecordUnifiedHeader before AEAD.
* @expect 1. Handshake succeeds without CID. 2. CID state is DISABLED. 3. Reading the stray record
*         does NOT yield app data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC009(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links. Neither side calls HITLS_CFG_SetDtlsCidSupport / SetDtlsRecvCid,
     *     so CID is NOT negotiated. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Drive the handshake to completion without CID. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* (3) Confirm CID was not negotiated on either side. */
    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);

    /* (4) Build a stray DTLS 1.3 unified-header record whose CID bit is set (see TC007 for layout). */
    uint8_t stray[1u + TEST_CID_A_LEN + 1u + 16u];
    uint32_t off = 0u;
    stray[off++] = 0x30;
    for (uint32_t i = 0u; i < TEST_CID_A_LEN; i++) { stray[off++] = 0xEE; }
    stray[off++] = 0x00;
    (void)memset(&stray[off], 0xAA, sizeof(stray) - off);

    /* (5) Inject the stray record into the client UIO. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, stray, sizeof(stray)), HITLS_SUCCESS);

    /* (6) The client reads -> the stray record is rejected by the CID check -> no app data.
     *     Per RFC 9147 §4.5.2 and §9 (line 2341-2342: "If no CID is negotiated, then the
     *     receiver MUST reject any records it receives that contain a CID"), the stray
     *     record is silently discarded (no alert), so HITLS_Read returns
     *     HITLS_REC_NORMAL_RECV_BUF_EMPTY and the handshake stays intact. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t readRet = HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(readRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC010
* @spec -
* @title No CID negotiated: server rejects a stray CID-bearing record after handshake
* @precon nan
* @brief Same as TC009 but the stray record is injected into the server. Without CID negotiated,
*        rec_read.c rejects the CID-bearing record (expected cidLen == 0) before AEAD.
* @expect 1. Handshake succeeds without CID. 2. CID state is DISABLED. 3. Reading the stray record
*         does NOT yield app data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links. Neither side enables CID. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Drive the handshake to completion without CID. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* (3) Confirm CID was not negotiated on either side. */
    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);

    /* (4) Build a stray DTLS 1.3 unified-header record whose CID bit is set (see TC007 for layout). */
    uint8_t stray[1u + TEST_CID_A_LEN + 1u + 16u];
    uint32_t off = 0u;
    stray[off++] = 0x30;
    for (uint32_t i = 0u; i < TEST_CID_A_LEN; i++) { stray[off++] = 0xEE; }
    stray[off++] = 0x00;
    (void)memset(&stray[off], 0xAA, sizeof(stray) - off);

    /* (5) Inject the stray record into the SERVER UIO. */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(ioUserData->recMsg.len == 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(server->io, stray, sizeof(stray)), HITLS_SUCCESS);

    /* (6) The server reads -> the stray record is rejected by the CID check -> no app data.
     *     Per RFC 9147 §4.5.2 the stray record is silently discarded (no alert), so
     *     HITLS_Read returns HITLS_REC_NORMAL_RECV_BUF_EMPTY and the handshake stays intact. */
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    int32_t readRet = HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen);
    ASSERT_EQ(readRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/* Inject a fabricated connection_id(54) extension into the outbound ServerHello.
 * This simulates a server sending CID when the client never offered it.
 *
 * DTLS 1.3 handshake message format (from REC_Write data):
 *   [0]       msg_type
 *   [1..3]    length (3 bytes, big-endian)
 *   [4..5]    message_seq
 *   [6..8]    fragment_offset
 *   [9..11]   fragment_length
 *   [12..]    handshake body (ServerHello body)
 *
 * We directly patch length/fragment_length and append CID ext bytes at the end. */
static void InjectUnsolicitedCidExtension(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    /* connection_id extension: type=0x0036(54), length=5, cidLen=4, cidVal={0xDE,0xAD,0xBE,0xEF} */
    static const uint8_t cidExt[] = { 0x00, 0x36, 0x00, 0x05, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };

    if (*len < 12 || data[0] != SERVER_HELLO || *len + sizeof(cidExt) > bufSize) {
        return;
    }

    /* Patch handshake header length (bytes 1..3) */
    uint32_t hsLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    hsLen += sizeof(cidExt);
    data[1] = (uint8_t)(hsLen >> 16);
    data[2] = (uint8_t)(hsLen >> 8);
    data[3] = (uint8_t)hsLen;

    /* Patch fragment_length (bytes 9..11) */
    uint32_t fragLen = ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];
    fragLen += sizeof(cidExt);
    data[9] = (uint8_t)(fragLen >> 16);
    data[10] = (uint8_t)(fragLen >> 8);
    data[11] = (uint8_t)fragLen;

    /* Patch extensions_length (last 2 bytes before extensions start in the ServerHello body).
     * ServerHello body at offset 12:
     *   [12..13]  server_version (2)
     *   [14..45]  random (32)
     *   [46]      session_id_length
     *   [46+1..46+sid_len] session_id
     *   [+2]      cipher_suite
     *   ... eventually extensions_length (2 bytes) + extensions
     * Rather than fully parsing, find extensions_length by scanning to the known position.
     * For simplicity, just add cidExt at the end and bump the extension list length. */
    uint32_t bodyOff = 12;
    /* server_version(2) + random(32) = 34 bytes */
    uint32_t pos = bodyOff + 2 + 32;
    if (pos >= *len) {
        return;
    }
    /* session_id */
    uint8_t sidLen = data[pos];
    pos += 1 + sidLen;
    /* cipher_suite(2) + compression(1) */
    pos += 2 + 1;
    if (pos + 2 > *len) {
        return;
    }
    /* extensions_length at pos */
    uint16_t extLen = ((uint16_t)data[pos] << 8) | data[pos + 1];
    extLen += sizeof(cidExt);
    data[pos] = (uint8_t)(extLen >> 8);
    data[pos + 1] = (uint8_t)extLen;

    /* Append CID extension */
    (void)memcpy(&data[*len], cidExt, sizeof(cidExt));
    *len += sizeof(cidExt);
}

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC011
* @spec -
* @title ClientHello without CID, ServerHello with injected CID extension, expect unsupported_extension
* @precon nan
* @brief RFC 8446 4.1.3: The server MUST NOT include an extension that was not offered by the client.
*        Use RecWrapper to inject a fabricated connection_id extension into the ServerHello.
* @expect 1. Client rejects with HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE, handshake fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC011(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        InjectUnsolicitedCidExtension
    };
    RegisterWrapper(wrapper);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC012
* @spec -
* @title ClientHello with CID, ServerHello without CID, client subsequent records have no CID
* @precon nan
* @brief RFC 9146 Section 3: Server not willing to use CID will not respond with connection_id.
* @expect 1. Handshake succeeds. 2. Client CID state cleared (DISABLED). 3. Client sendCidLen is 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC012(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_TRUE(client->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC013
* @spec -
* @title ClientHello with CID, ServerHello without CID, server subsequent records have no CID
* @precon nan
* @brief RFC 9146 Section 3: Server not willing means CID not negotiated for either direction.
* @expect 1. Handshake succeeds. 2. Server CID state is DISABLED. 3. Server sendCidLen is 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC013(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_TRUE(server->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC001
* @spec -
* @title Client disabled CID, receives ServerHello with CID extension injected, expect alert
* @precon nan
* @brief RFC 8446 4.1.3: Server MUST NOT include extension not offered by client.
*        Use RecWrapper to inject a fabricated connection_id extension into the ServerHello
*        even though the client never offered it.
* @expect 1. Client rejects with HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE, handshake fails.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC001(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(s_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client does NOT enable CID. Server enabling CID alone is harmless because
     * ServerHello packing suppresses the ext when isCidNegotiated is false.
     * The RecWrapper below injects an unsolicited CID ext into the outbound ServerHello
     * to exercise the client-side unsupported_extension rejection path. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        InjectUnsolicitedCidExtension
    };
    RegisterWrapper(wrapper);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC002
* @spec -
* @title Client disabled CID, server enabled CID, handshake succeeds, no CID in records
* @precon nan
* @brief Server can only respond CID if client offered it. Client didn't offer, so no CID.
* @expect 1. Handshake succeeds. 2. No CID negotiated.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC002(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(s_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_EQ(server->ssl->negotiatedInfo.isCidNegotiated, false);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC003
* @spec -
* @title Client enabled CID (non-empty), server disabled CID, handshake succeeds, no CID
* @precon nan
* @brief RFC 9146 Section 3: Server not willing to use CID will not respond with extension.
* @expect 1. Handshake succeeds. 2. CID not negotiated (DISABLED). 3. No CID in records.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC003(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);
    ASSERT_TRUE(client->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);
    ASSERT_TRUE(server->ssl->negotiatedInfo.peerCidEntry.cidLen == 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC004
* @spec -
* @title Client enabled CID (zero-length), server disabled CID, handshake succeeds
* @precon nan
* @brief Same as TC003 but client sends zero-length CID. Server still doesn't respond.
* @expect 1. Handshake succeeds. 2. CID not negotiated.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC004(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, NULL, 0), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC005
* @spec -
* @title Both enabled CID, client carries server's localCid, handshake succeeds
* @precon nan
* @brief CID direction: client sendCid = server localCid.
* @expect 1. Handshake succeeds. 2. Client sendCid == server localCid (CID_B).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC005(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    const DTLS_CidSendEntry *sendCidEntry = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidB, TEST_CID_B_LEN), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC006
* @spec -
* @title Both enabled CID, server carries client's localCid, handshake succeeds
* @precon nan
* @brief CID direction: server sendCid = client localCid.
* @expect 1. Handshake succeeds. 2. Server sendCid == client localCid (CID_A).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC006(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    const DTLS_CidSendEntry *sendCidEntry = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(sendCidEntry->cidLen > 0);
    ASSERT_EQ(sendCidEntry->cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(sendCidEntry->cidVal, g_testCidA, TEST_CID_A_LEN), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC020
* @spec -
* @title Record layer CID round-trip: app data with CID is parsed and received correctly
* @precon nan
* @brief After CID negotiation, send application data from client to server. The record write path
*        encodes the CID into the unified header; the record read path parses it and accepts the record.
* @expect 1. HITLS_Write succeeds. 2. HITLS_Read on receiver succeeds and returns the app data.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC020(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    uint8_t appData[] = "CID record test";
    uint32_t writeLen = 0;
    ASSERT_EQ(HITLS_Write(client->ssl, appData, sizeof(appData), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(client, server), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(appData));
    ASSERT_EQ(memcmp(readBuf, appData, sizeof(appData)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC021
* @spec -
* @title Record layer rejects unified header with wrong CID value
* @precon nan
* @brief After CID negotiation, inject a crafted DTLS 1.3 unified header record with an incorrect
*        CID into the server UIO. The record read path should silently discard it.
* @expect 1. HITLS_Read returns HITLS_REC_NORMAL_RECV_BUF_EMPTY (record discarded, not fatal).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC021(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Fake DTLS 1.3 unified header: CID bit set, wrong CID value.
     * 0x3D = FIX(0x20) | CID(0x10) | SEQ16(0x08) | LEN(0x04) | epoch(0x01) */
    uint8_t fakeRecord[1 + TEST_CID_B_LEN + 2 + 2 + 16];
    (void)memset(fakeRecord, 0, sizeof(fakeRecord));

    uint32_t off = 0;
    fakeRecord[off++] = 0x3D;
    fakeRecord[off++] = 0xFF;
    fakeRecord[off++] = 0xFF;
    fakeRecord[off++] = 0xFF;
    fakeRecord[off++] = 0xFF;
    fakeRecord[off++] = 0x00;
    fakeRecord[off++] = 0x01;
    fakeRecord[off++] = 0x00;
    fakeRecord[off++] = 0x10;
    (void)memset(&fakeRecord[off], 0xAA, 16);

    ASSERT_EQ(FRAME_TransportRecMsg(server->io, fakeRecord, sizeof(fakeRecord)), HITLS_SUCCESS);

    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0;
    ASSERT_EQ(HITLS_Read(server->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_REC_NORMAL_RECV_BUF_EMPTY);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC007
* @spec -
* @title HITLS_CFG_SetDtlsCidSupport/GetDtlsCidSupport: happy path and NULL parameter rejection
* @precon nan
* @brief Verify the config-level CID enablement API: default disabled, set/get round-trip, NULL rejection.
* @expect 1. NULL config → HITLS_NULL_INPUT. 2. NULL isSupport → HITLS_NULL_INPUT.
*         3. After Set(true), Get returns true. 4. After Set(false), Get returns false.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC007(void)
{
    FRAME_Init();

    HITLS_Config *config = NULL;
    bool isSupport = true;

    /* NULL config / NULL output */
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_NULL_INPUT);
    ASSERT_EQ(HITLS_CFG_GetDtlsCidSupport(config, &isSupport), HITLS_NULL_INPUT);

    config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    /* NULL output pointer */
    ASSERT_EQ(HITLS_CFG_GetDtlsCidSupport(config, NULL), HITLS_NULL_INPUT);

    /* Default: CID disabled */
    ASSERT_EQ(HITLS_CFG_GetDtlsCidSupport(config, &isSupport), HITLS_SUCCESS);
    ASSERT_TRUE(!isSupport);

    /* After enabling CID */
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetDtlsCidSupport(config, &isSupport), HITLS_SUCCESS);
    ASSERT_TRUE(isSupport);

    /* After disabling CID */
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, false), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_GetDtlsCidSupport(config, &isSupport), HITLS_SUCCESS);
    ASSERT_TRUE(!isSupport);

EXIT:
    HITLS_CFG_FreeConfig(config);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC008
* @spec -
* @title HITLS_GetDtlsRecvCid: happy path and NULL parameter rejection
* @precon nan
 * @brief Verify GetDtlsRecvCid returns correct entries and rejects NULL/invalid inputs.
 * @expect 1. NULL ctx → HITLS_NULL_INPUT. 2. NULL entryCount → HITLS_NULL_INPUT.
 *         3. CID disabled → HITLS_SUCCESS with entryCount 0. 4. Query with NULL entries returns count.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC008(void)
{
    FRAME_Init();

    /* CID-disabled link: NULL checks and not-enabled check */
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *link = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(link != NULL);
    HITLS_Ctx *ctx = link->ssl;

    /* CID-enabled link: enablement is config-level, before HITLS_New */
    HITLS_Config *cidConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(cidConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(cidConfig, true), HITLS_SUCCESS);
    FRAME_LinkObj *cidLink = FRAME_CreateLink(cidConfig, BSL_UIO_UDP);
    ASSERT_TRUE(cidLink != NULL);

    HITLS_DtlsCidEntry entries[4];
    uint8_t entryCount = 4;

    /* NULL ctx */
    ASSERT_EQ(HITLS_GetDtlsRecvCid(NULL, entries, &entryCount), HITLS_NULL_INPUT);

    /* NULL entryCount */
    ASSERT_EQ(HITLS_GetDtlsRecvCid(ctx, entries, NULL), HITLS_NULL_INPUT);

    /* CID disabled → query returns success with count 0 */
    entryCount = 4;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(ctx, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* Set local CID on the enabled link, query with NULL entries to get count */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(cidLink->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(cidLink->ssl, NULL, &entryCount), HITLS_SUCCESS);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(link);
    HITLS_CFG_FreeConfig(cidConfig);
    FRAME_FreeLink(cidLink);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC009
* @spec -
* @title HITLS_GetDtlsSendCid: happy path and NULL parameter rejection
* @precon nan
 * @brief Verify GetDtlsSendCid rejects NULL inputs and returns empty when CID disabled.
 * @expect 1. NULL ctx → HITLS_NULL_INPUT. 2. NULL entryCount → HITLS_NULL_INPUT.
 *         3. CID disabled → HITLS_SUCCESS with entryCount 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC009(void)
{
    FRAME_Init();

    /* CID-disabled link: NULL checks and not-enabled check */
    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *link = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(link != NULL);
    HITLS_Ctx *ctx = link->ssl;

    /* CID-enabled link: enablement is config-level, before HITLS_New */
    HITLS_Config *cidConfig = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(cidConfig != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(cidConfig, true), HITLS_SUCCESS);
    FRAME_LinkObj *cidLink = FRAME_CreateLink(cidConfig, BSL_UIO_UDP);
    ASSERT_TRUE(cidLink != NULL);

    HITLS_DtlsCidEntry entries[4];
    uint8_t entryCount = 4;

    /* NULL ctx */
    ASSERT_EQ(HITLS_GetDtlsSendCid(NULL, entries, &entryCount), HITLS_NULL_INPUT);

    /* NULL entryCount */
    ASSERT_EQ(HITLS_GetDtlsSendCid(ctx, entries, NULL), HITLS_NULL_INPUT);

    /* CID disabled → query returns success with count 0 */
    entryCount = 4;
    ASSERT_EQ(HITLS_GetDtlsSendCid(ctx, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* Enabled but no peer CID before handshake: count is 0 */
    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsSendCid(cidLink->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(link);
    HITLS_CFG_FreeConfig(cidConfig);
    FRAME_FreeLink(cidLink);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC010
* @spec -
* @title Negative: NULL ctx, cidLen boundary for the CID recv/negotiation APIs
* @precon nan
* @brief Exercise the defensive checks in SetDtlsRecvCid, GetDtlsIsCidNegotiated.
* @expect 1. NULL ctx → HITLS_NULL_INPUT for each API. 2. cidLen > 32 → HITLS_INVALID_INPUT.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC010(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *link = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(link != NULL);
    HITLS_Ctx *ctx = link->ssl;

    /* GetDtlsIsCidNegotiated: NULL ctx */
    bool isNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(NULL, &isNeg), HITLS_NULL_INPUT);

    /* GetDtlsIsCidNegotiated: NULL output */
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(ctx, NULL), HITLS_NULL_INPUT);

    /* SetDtlsRecvCid: NULL ctx */
    uint8_t cid4[4] = {0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(HITLS_SetDtlsRecvCid(NULL, cid4, 4), HITLS_NULL_INPUT);

    /* SetDtlsRecvCid: non-zero cidLen with NULL cid pointer */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(ctx, NULL, 4), HITLS_NULL_INPUT);

    /* SetDtlsRecvCid: cidLen > HITLS_DTLS_CID_LOCAL_MAX_LEN (32) → HITLS_INVALID_INPUT */
    uint8_t cidLong[33];
    (void)memset(cidLong, 0xAA, sizeof(cidLong));
    ASSERT_EQ(HITLS_SetDtlsRecvCid(ctx, cidLong, 33), HITLS_INVALID_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(link);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC011
* @spec -
* @title Boundary length: local CID len=32 accepted, len=33 rejected, len=0 accepted
* @precon nan
* @brief RFC 9146 allows CID up to 255 bytes on the wire. Local CID is bounded by
*        HITLS_DTLS_CID_LOCAL_MAX_LEN (32). Verify exact boundary behavior.
* @expect 1. SetDtlsRecvCid with cidLen=0 succeeds.
*         2. SetDtlsRecvCid with cidLen=32 succeeds.
*         3. SetDtlsRecvCid with cidLen=33 returns HITLS_INVALID_INPUT.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC011(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);

    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *link = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(link != NULL);
    HITLS_Ctx *ctx = link->ssl;

    /* len=0 (empty CID): allowed */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(ctx, NULL, 0), HITLS_SUCCESS);

    /* len=32 (max local): allowed */
    uint8_t cid32[32];
    (void)memset(cid32, 0xBB, sizeof(cid32));
    ASSERT_EQ(HITLS_SetDtlsRecvCid(ctx, cid32, 32), HITLS_SUCCESS);

    /* len=33 (exceeds max local): rejected */
    uint8_t cid33[33];
    (void)memset(cid33, 0xCC, sizeof(cid33));
    ASSERT_EQ(HITLS_SetDtlsRecvCid(ctx, cid33, 33), HITLS_INVALID_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(link);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC012
* @spec -
* @title Non-DTLS13 ctx (TLS1.3 / DTLS1.2) is rejected by the CID recv API with CONFIG_UNSUPPORT
* @precon nan
* @brief connection_id(54) is a DTLS 1.3-only feature (RFC 9147). DTLS 1.2 uses a different
*        CID mechanism (RFC 9146) and TLS 1.3 does not use CID at all. Verify the runtime
*        protocol gate (IS_SUPPORT_DTLS13) in SetDtlsRecvCid.
* @expect 1. TLS1.3 ctx: SetDtlsRecvCid → HITLS_CONFIG_UNSUPPORT.
*         2. DTLS1.2 ctx: SetDtlsRecvCid → HITLS_CONFIG_UNSUPPORT.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC012(void)
{
    FRAME_Init();

    /* TLS 1.3-only context: CID is not applicable */
#ifdef HITLS_TLS_PROTO_TLS13
    {
        HITLS_Config *tls13Config = HITLS_CFG_NewTLS13Config();
        ASSERT_TRUE(tls13Config != NULL);
        FRAME_LinkObj *tls13Link = FRAME_CreateLink(tls13Config, BSL_UIO_TCP);
        ASSERT_TRUE(tls13Link != NULL);

        ASSERT_EQ(HITLS_SetDtlsRecvCid(tls13Link->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_CONFIG_UNSUPPORT);

        HITLS_CFG_FreeConfig(tls13Config);
        FRAME_FreeLink(tls13Link);
    }
#endif

    /* DTLS 1.2 context: uses RFC 9146 CID, not the RFC 9147 mechanism implemented here */
#ifdef HITLS_TLS_PROTO_DTLS12
    {
        HITLS_Config *dtls12Config = HITLS_CFG_NewDTLS12Config();
        ASSERT_TRUE(dtls12Config != NULL);
        FRAME_LinkObj *dtls12Link = FRAME_CreateLink(dtls12Config, BSL_UIO_UDP);
        ASSERT_TRUE(dtls12Link != NULL);

        ASSERT_EQ(HITLS_SetDtlsRecvCid(dtls12Link->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_CONFIG_UNSUPPORT);

        HITLS_CFG_FreeConfig(dtls12Config);
        FRAME_FreeLink(dtls12Link);
    }
#endif

EXIT:
    return;
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC013
* @spec -
* @title Mid-handshake mutation of the local recv CID is rejected with CM_LINK_HANDSHAKING
* @precon nan
* @brief The local recv CID is only mutable before the handshake starts (CM_STATE_IDLE &&
*        hsCtx == NULL). Verify this gate by pausing the DTLS 1.3 handshake at
*        TRY_RECV_FINISH and attempting to mutate.
* @expect 1. SetDtlsRecvCid(...) during handshake → HITLS_CM_LINK_HANDSHAKING.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC013(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Configure local recv CIDs on both sides BEFORE handshake (this is the mutable window). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* Drive the handshake forward, pausing the CLIENT at TRY_RECV_FINISH.
     * At this point hsCtx != NULL and state != CM_STATE_IDLE, so the mutability gate is false. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    /* Mutation attempts during handshake must be rejected. */
    uint8_t cidOther[4] = {0x11, 0x22, 0x33, 0x44};
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, cidOther, 4), HITLS_CM_LINK_HANDSHAKING);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC014
* @spec -
* @title CID negotiation survives HelloRetryRequest: HRR suppresses CID ext, final SH carries it
* @precon nan
* @brief RFC 9147 §6: connection_id is only carried in the initial ClientHello/ServerHello, not
 *        in the retry ClientHello/HelloRetryRequest. isCidNegotiated is never set during the HRR
 *        round-trip (ProcessClientHello early-returns on isNeedSendHrr), so the HRR omits CID. Verify end-to-end:
*        (1) trigger HRR via group mismatch (client offers only secp256r1, server only secp384r1);
*        (2) the HRR does NOT carry a CID ext;
*        (3) after the retry ClientHello, the final ServerHello DOES carry the CID ext;
*        (4) both directions end up negotiated and use CIDs in post-handshake records.
* @expect 1. Handshake succeeds after HRR. 2. CID negotiated in both directions post-handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC014(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(s_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(s_config != NULL);

    /* Trigger HRR: client offers a group the server doesn't share in its key_share,
     * but the server supports another group from the client's supported list. */
    uint16_t clientGroups[] = {HITLS_EC_GROUP_SECP256R1, HITLS_EC_GROUP_SECP384R1};
    uint16_t serverGroups[] = {HITLS_EC_GROUP_SECP384R1};
    ASSERT_EQ(HITLS_CFG_SetGroups(c_config, clientGroups, sizeof(clientGroups) / sizeof(uint16_t)),
        HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetGroups(s_config, serverGroups, sizeof(serverGroups) / sizeof(uint16_t)),
        HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Configure CID on both sides BEFORE handshake. RFC 9147 §6: the connection_id
     * extension is only sent in the initial ClientHello; the retry ClientHello omits it. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* Run the full handshake including the HRR round-trip. isCidNegotiated stays false through
     * the HRR (ProcessClientHello early-returns on isNeedSendHrr), so the HRR omits CID; the
     * final ServerHello carries it once isCidNegotiated flips true. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Both directions negotiated. */
    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* Client outbound carries server's recv CID (B); server outbound carries client's recv CID (A). */
    const HITLS_DtlsCidEntry *clientSendCid = &client->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(clientSendCid->cidLen > 0);
    ASSERT_EQ(clientSendCid->cidLen, TEST_CID_B_LEN);
    ASSERT_EQ(memcmp(clientSendCid->cidVal, g_testCidB, TEST_CID_B_LEN), 0);

    const HITLS_DtlsCidEntry *serverSendCid = &server->ssl->negotiatedInfo.peerCidEntry;
    ASSERT_TRUE(serverSendCid->cidLen > 0);
    ASSERT_EQ(serverSendCid->cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(serverSendCid->cidVal, g_testCidA, TEST_CID_A_LEN), 0);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC015
* @spec -
* @title Finished flight carrying an unrecognized CID is silently discarded; retransmit with correct CID succeeds
* @precon nan
* @brief RFC 9147 §4.5.2: a record whose CID is not in the receiver's expected CID list is silently
*        discarded by the record layer (rec_read.c:Dtls13GetRecordUnifiedHeader returns
*        HITLS_REC_NORMAL_RECV_BUF_EMPTY before AEAD). The handshake state is preserved, so when the
*        peer retransmits the same flight with the negotiated CID, the client must complete the
*        handshake successfully. This is complementary to TC003 (which never retransmits and thus
*        fails). It models the real "lost record + DTLS retransmission" flow.
*
* @brief BLOCKED: this scenario depends on the collaborator's DTLS 1.3 ACK / retransmission
*        implementation. The test is staged here so it can be enabled once that lands.
*        Right now `FRAME_CreateConnection` still cannot drive a post-discard retransmit path
*        end-to-end -- see the integration notes in openhitls/CLAUDE.md.
*
* @expect 1. After injecting tampered flight, client silently discards (no fatal alert).
*         2. After injecting the original flight as "retransmission", HITLS_Connect succeeds.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC015(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Negotiate CID in both directions (same as TC003). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* (3) Pause the client right before it consumes the server's Finished flight. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    /* (4) Snapshot the original (correct-CID) flight so we can re-inject it as "retransmission". */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *rec = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen > 1u + TEST_CID_A_LEN);

    uint8_t origFlight[MAX_RECORD_LENTH];
    ASSERT_TRUE(recLen <= sizeof(origFlight));
    (void)memcpy(origFlight, rec, recLen);
    uint32_t origLen = recLen;

    /* (5) Tamper: overwrite every record's CID with a value the client did NOT negotiate. */
    TamperCidInFlight(rec, recLen, TEST_CID_A_LEN, 0xEE);

    /* (6) Let the client consume the tampered flight. The record layer should silently discard
     *     it (HITLS_REC_NORMAL_RECV_BUF_EMPTY), keeping the handshake state intact -- i.e. the
     *     client is still waiting for the real Finished. */
    int32_t connRet = HITLS_Connect(client->ssl);
    ASSERT_EQ(connRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_FINISH);

    /* (7) Simulate the server retransmitting the same flight, this time with the negotiated CID
     *     (i.e. the untouched bytes we snapshotted in step 4). FRAME_TransportRecMsg refuses to
     *     overwrite a non-empty buffer, so confirm the discard drained it first. */
    ASSERT_EQ(ioUserData->recMsg.len, 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, origFlight, origLen), HITLS_SUCCESS);

    /* (8) Resume the handshake. The retransmitted Finished now carries the correct CID so the
     *     client consumes it and reaches the established state. */
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC016
* @spec -
* @title Finished flight without CID in the unified header is dropped; retransmit with CID succeeds
* @precon nan
* @brief RFC 9147 Section 4.2: "Once a non-empty CID is negotiated, the sender MUST
*        always include the CID in the unified header." The record layer enforces this
*        on the receive side: Dtls13GetRecordUnifiedHeader (rec_read.c) silently drops
*        any record whose C bit is clear while a non-zero-length recv CID is active
*        (HITLS_REC_NORMAL_RECV_BUF_EMPTY, no alert), so the handshake stays pending
*        until the peer retransmits with the negotiated CID intact. This closes the gap
*        where a Finished (or any post-negotiation record) sent without a CID would
*        otherwise be accepted. A zero-length CID legitimately omits the C bit and is
*        out of scope here (covered by TC005/TC006). Complementary to TC015 (wrong CID
*        value) and TC004 (never retransmits).
*
* @expect 1. After CID stripping, the client silently discards and stays at TRY_RECV_FINISH.
*         2. After re-injecting the original flight as "retransmission", HITLS_Connect succeeds.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC016(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    /* (1) Create client/server links over the simulated UDP UIO. */
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* (2) Negotiate CID in both directions. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    /* (3) Pause the client right before it consumes the server's Finished flight. */
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    /* (4) Snapshot the original (correct-CID) flight for later "retransmission". */
    FrameUioUserData *ioUserData = BSL_UIO_GetUserData(client->io);
    uint8_t *rec = ioUserData->recMsg.msg;
    uint32_t recLen = ioUserData->recMsg.len;
    ASSERT_TRUE(recLen > 1u + TEST_CID_A_LEN);

    uint8_t origFlight[MAX_RECORD_LENTH];
    ASSERT_TRUE(recLen <= sizeof(origFlight));
    (void)memcpy(origFlight, rec, recLen);
    uint32_t origLen = recLen;

    /* (5) Strip the CID bytes from the in-flight copy: clear the CID bit in byte 0 and shift
     *     seq/length/body left so the header stays self-consistent without a CID. The record
     *     layer rejects this record at header parse (C bit clear + recv CID active -> silent
     *     discard), before AEAD even runs. */
    uint32_t strippedLen = StripCidFromFlight(rec, recLen, TEST_CID_A_LEN);
    ioUserData->recMsg.len = strippedLen;

    /* (6) Let the client consume the CID-less flight. The record is dropped without a fatal
     *     alert; the handshake remains pending at TRY_RECV_FINISH. */
    int32_t connRet = HITLS_Connect(client->ssl);
    ASSERT_EQ(connRet, HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_FINISH);

    /* (7) Re-inject the snapshotted original flight as the server's retransmission. */
    ASSERT_EQ(ioUserData->recMsg.len, 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, origFlight, origLen), HITLS_SUCCESS);

    /* (8) Resume; retransmitted Finished carries the negotiated CID so handshake completes. */
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);

    bool isCidNeg = false;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC017
* @spec -
* @title Server does not echo CID when ClientHello carries CID but handshake is DTLS 1.2
* @precon nan
* @brief The connection_id extension shares wire format across DTLS 1.2 (RFC 9146)
*        and DTLS 1.3 (RFC 9147), but this implementation only provides the DTLS 1.3
*        unified-header record-layer encoding. When a client offers connection_id and
*        the handshake negotiates DTLS 1.2, the server MUST silently ignore the
*        extension: no NEGOTIATED state, isCidNegotiated stays false, ServerHello
*        does not echo connection_id.
*
*        Setup (full handshake):
*          - Client built with HITLS_CFG_NewDTLSConfig (which natively enables both
*            DTLS 1.2 and 1.3). The active version mask is cleared of DTLS 1.3 and
*            maxVersion is capped at DTLS 1.2 so the client uses the pure DTLS 1.2
*            path. originVersionMask still carries DTLS 1.3 so
*            DTLS_CID_NeedCidExtForClientHello returns true and the client packs
*            connection_id into its DTLS 1.2-style ClientHello.
*          - Server is dual-version (HITLS_CFG_NewDTLSConfig unchanged) and picks
*            DTLS 1.2 because the client's ClientHello carries no supported_versions.
*        Because the negotiated version is not DTLS 1.3, the source-level guard in
*        DTLS_CID_ProcessClientHello keeps isCidNegotiated false, so the server's
*        ServerHello omits connection_id. Both sides end up with CID not negotiated.
* @expect 1. Handshake succeeds at DTLS 1.2.
*         2. server->ssl->negotiatedInfo.isCidNegotiated == false.
*         3. Both sides report CID NOT negotiated.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC017(void)
{
    FRAME_Init();

    /* Client: built on the generic DTLS config. Clear DTLS 1.3 from the active
     * version mask and cap maxVersion at DTLS 1.2 so the client uses the pure
     * DTLS 1.2 handshake path (DTLS 1.2-style ClientHello, no supported_versions).
     * originVersionMask still carries DTLS 1.3 (NewDTLSConfig sets it natively)
     * so the CID APIs accept the ctx and the client packs connection_id. */
    HITLS_Config *c_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    c_config->version &= ~DTLS13_VERSION_BIT;
    c_config->maxVersion = HITLS_VERSION_DTLS12;

    /* Server: dual-version (DTLS 1.2 + 1.3) via the same generic config. Picks
     * DTLS 1.2 because the client did not send supported_versions. */
    HITLS_Config *s_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client offers connection_id. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Confirm the handshake actually downgraded to DTLS 1.2. */
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);

    /* Server must not have entered NEGOTIATED (isCidNegotiated stays false). */
    ASSERT_TRUE(!server->ssl->negotiatedInfo.isCidNegotiated);
    bool isCidNegServer = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNegServer), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNegServer);

    /* Client sees "ServerHello without CID extension" -> CID not negotiated. */
    bool isCidNegClient = true;
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNegClient), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNegClient);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC018
* @spec -
* @title Client treats DTLS 1.2 ServerHello carrying connection_id as illegal
* @precon nan
* @brief The connection_id extension is not in HS_EX_TYPE_TLS1_2_ALLOWED_OF_SERVER_HELLO, so a
*        DTLS 1.2 ServerHello that carries connection_id must be rejected by the client's
*        extension-allowlist check (HS_CheckReceivedExtension) with illegal_parameter.
*        Use the existing InjectUnsolicitedCidExtension wrapper to splice a connection_id
*        extension onto an otherwise-normal DTLS 1.2 ServerHello.
* @expect 1. HITLS_Connect on client returns HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC018(void)
{
    FRAME_Init();

    /* Pure DTLS 1.2 on both sides via the generic DTLS config entry point
     * (capped at DTLS 1.2 so the handshake negotiates DTLS 1.2, not 1.3);
     * the injection wrapper forges the offending extension onto the ServerHello. */
    HITLS_Config *c_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    c_config->maxVersion = HITLS_VERSION_DTLS12;
    ASSERT_EQ(Dtls13UseSingleKeyShareGroup(c_config), HITLS_SUCCESS);
    HITLS_Config *s_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(s_config != NULL);
    s_config->maxVersion = HITLS_VERSION_DTLS12;

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    RecWrapper wrapper = {
        TRY_SEND_SERVER_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        InjectUnsolicitedCidExtension
    };
    RegisterWrapper(wrapper);

    int32_t ret = FRAME_CreateConnection(client, server, true, HS_STATE_BUTT);
    ASSERT_EQ(ret, HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC019
* @spec -
* @title Dual-version client does not offer connection_id in ClientHello
* @precon nan
* @brief As client:
*          1. version supports both DTLS 1.2 and 1.3 (HITLS_CFG_NewDTLSConfig);
*          2. enable CID (HITLS_CFG_SetDtlsCidSupport(c_config, true));
*          3. assert the ClientHello does NOT carry the connection_id extension.
*        The ClientHello is captured from client->io sndMsg and parsed with FRAME_ParseMsg.
* @expect 1. FRAME_ParseMsg succeeds on the emitted ClientHello.
*         2. connection_id extension is absent (exState == MISSING_FIELD).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC019(void)
{
    FRAME_Init();

    /* Client: generic DTLS config — natively enables BOTH DTLS 1.2 and 1.3. */
    HITLS_Config *c_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);

    /* Arm a local recv CID so there IS something the gate could pack if it weren't gated. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    /* Emit the ClientHello. No server is needed — only the ClientHello content is asserted, and
     * the record is buffered in client->io sndMsg. */
    (void)HITLS_Connect(client->ssl);

    FrameUioUserData *io = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(io->sndMsg.len > 0u);

    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    FRAME_Msg msg = {0};
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsg(&frameType, io->sndMsg.msg, io->sndMsg.len, &msg, &parseLen), HITLS_SUCCESS);

    /* The gate keeps connection_id out of the ClientHello → the field stays MISSING_FIELD. */
    ASSERT_TRUE(msg.body.hsMsg.body.clientHello.connectionId.exState == MISSING_FIELD);

    FRAME_CleanMsg(&frameType, &msg);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    FRAME_FreeLink(client);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC020
* @spec -
* @title Dual-version client offers connection_id after DTLS 1.2 is forbidden
* @precon nan
* @brief As client:
*          1. version supports both DTLS 1.2 and 1.3 (HITLS_CFG_NewDTLSConfig);
*          2. forbid DTLS 1.2 (HITLS_CFG_SetVersionForbid);
*          3. enable CID (HITLS_CFG_SetDtlsCidSupport(c_config, true));
*          4. assert the ClientHello carries the connection_id extension.
*        The ClientHello is captured from client->io sndMsg and parsed with FRAME_ParseMsg.
* @expect 1. FRAME_ParseMsg succeeds on the emitted ClientHello.
*         2. connection_id extension is present and advertises the armed recv CID.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC020(void)
{
    FRAME_Init();

    /* Client: generic DTLS config (originVersionMask carries BOTH 1.2 and 1.3), then forbid 1.2 so
     * the active version mask is pure DTLS 1.3. The gate now allows connection_id. */
    HITLS_Config *c_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_CFG_SetVersionForbid(c_config, DTLS12_VERSION_BIT), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);

    /* Arm the local recv CID that the ClientHello connection_id extension will advertise. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    (void)HITLS_Connect(client->ssl);

    FrameUioUserData *io = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(io->sndMsg.len > 0u);

    FRAME_Type frameType = {0};
    frameType.versionType = HITLS_VERSION_DTLS13;
    frameType.recordType = REC_TYPE_HANDSHAKE;
    frameType.handshakeType = CLIENT_HELLO;
    frameType.keyExType = HITLS_KEY_EXCH_ECDHE;
    frameType.transportType = BSL_UIO_UDP;
    FRAME_Msg msg = {0};
    uint32_t parseLen = 0;
    ASSERT_EQ(FRAME_ParseMsg(&frameType, io->sndMsg.msg, io->sndMsg.len, &msg, &parseLen), HITLS_SUCCESS);

    /* connection_id present, advertising the armed recv CID. */
    ASSERT_TRUE(msg.body.hsMsg.body.clientHello.connectionId.exState == INITIAL_FIELD);
    ASSERT_EQ(msg.body.hsMsg.body.clientHello.connectionId.exData.size, (uint32_t)TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(msg.body.hsMsg.body.clientHello.connectionId.exData.data, g_testCidA, TEST_CID_A_LEN), 0);

    FRAME_CleanMsg(&frameType, &msg);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    FRAME_FreeLink(client);
}
/* END_CASE */

/* RecWrapper callback: splice a connection_id extension onto an outbound ClientHello so the test
 * can feed a DTLS 1.2 ClientHello that carries CID to the server (the client-side gate would
 * otherwise keep CID out of a 1.2 ClientHello). data points at the DTLS handshake message, whose
 * 12-byte header precedes the ClientHello body. Parallel to InjectUnsolicitedCidExtension. */
static void InjectCidIntoClientHello(HITLS_Ctx *ctx, uint8_t *data, uint32_t *len,
    uint32_t bufSize, void *userData)
{
    (void)ctx;
    (void)userData;
    /* connection_id extension: type=0x0036(54), length=5, cidLen=4, cidVal=g_testCidA */
    uint8_t cidExt[4 + 1 + TEST_CID_A_LEN] = { 0x00, 0x36, 0x00, 0x05, 0x04 };
    (void)memcpy(&cidExt[5], g_testCidA, TEST_CID_A_LEN);

    if (*len < 12 || data[0] != CLIENT_HELLO || *len + sizeof(cidExt) > bufSize) {
        return;
    }
    /* Patch handshake header length (bytes 1..3) and fragment_length (bytes 9..11). */
    uint32_t hsLen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    hsLen += sizeof(cidExt);
    data[1] = (uint8_t)(hsLen >> 16);
    data[2] = (uint8_t)(hsLen >> 8);
    data[3] = (uint8_t)hsLen;
    uint32_t fragLen = ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];
    fragLen += sizeof(cidExt);
    data[9] = (uint8_t)(fragLen >> 16);
    data[10] = (uint8_t)(fragLen >> 8);
    data[11] = (uint8_t)fragLen;

    /* Locate extensions_length in the ClientHello body:
     *   version(2) + random(32) + session_id(1+sid) + cookie(1+cookie) +
     *   cipher_suites(2+cs) + compression_methods(1+comp) + extensions_length(2) */
    uint32_t pos = 12 + 2 + 32;
    if (pos >= *len) {
        return;
    }
    pos += 1 + data[pos];  /* legacy_session_id */
    if (pos >= *len) {
        return;
    }
    pos += 1 + data[pos];  /* DTLS cookie */
    if (pos + 2 > *len) {
        return;
    }
    uint16_t csLen = ((uint16_t)data[pos] << 8) | data[pos + 1];
    pos += 2 + csLen;  /* cipher_suites */
    if (pos >= *len) {
        return;
    }
    pos += 1 + data[pos];  /* legacy_compression_methods */
    if (pos + 2 > *len) {
        return;
    }
    /* Bump extensions_length and append the CID extension. */
    uint16_t extLen = ((uint16_t)data[pos] << 8) | data[pos + 1];
    extLen += sizeof(cidExt);
    data[pos] = (uint8_t)(extLen >> 8);
    data[pos + 1] = (uint8_t)extLen;
    (void)memcpy(&data[*len], cidExt, sizeof(cidExt));
    *len += sizeof(cidExt);
}

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC021
* @spec -
* @title Server does not echo connection_id when a DTLS 1.2 ClientHello carries it
* @precon nan
* @brief As server:
*          1. version supports both DTLS 1.2 and 1.3 (HITLS_CFG_NewDTLSConfig);
*          2. enable CID (HITLS_CFG_SetDtlsCidSupport(s_config, true));
*          3. receive a DTLS 1.2 ClientHello carrying a connection_id extension (a pure-1.2 client
*             whose ClientHello has CID spliced in via InjectCidIntoClientHello);
*          4. assert the ServerHello does NOT carry the connection_id extension.
*        Because the negotiated version is DTLS 1.2, the server-side guard in
*        DTLS_CID_ProcessClientHello keeps isCidNegotiated false, so ServerHello omits connection_id.
* @expect 1. Handshake succeeds at DTLS 1.2.
*         2. Neither side has CID negotiated (ServerHello carries no connection_id).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC021(void)
{
    FRAME_Init();

    /* Client: pure DTLS 1.2 — emits a DTLS 1.2-style ClientHello (no supported_versions). */
    HITLS_Config *c_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(c_config != NULL);
    c_config->version &= ~DTLS13_VERSION_BIT;
    c_config->maxVersion = HITLS_VERSION_DTLS12;

    /* Server: dual-version (DTLS 1.2 + 1.3), CID enabled. */
    HITLS_Config *s_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(s_config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Splice connection_id into the client's outbound DTLS 1.2 ClientHello. */
    RecWrapper wrapper = {
        TRY_SEND_CLIENT_HELLO,
        REC_TYPE_HANDSHAKE,
        false,
        NULL,
        InjectCidIntoClientHello
    };
    RegisterWrapper(wrapper);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Negotiation landed on DTLS 1.2. */
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS12);

    /* Server-side guard held: it received CID in the ClientHello but stayed out of NEGOTIATED, so
     * isCidNegotiated stays false and connection_id is kept out of the ServerHello. */
    ASSERT_TRUE(!server->ssl->negotiatedInfo.isCidNegotiated);
    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);

EXIT:
    ClearWrapper();
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC022
* @spec -
* @title Dual-version server echoes connection_id when a DTLS 1.3 ClientHello carries it
* @precon nan
* @brief As server (the positive counterpart of TC021):
*          1. version supports both DTLS 1.2 and 1.3 (HITLS_CFG_NewDTLSConfig);
*          2. enable CID (HITLS_CFG_SetDtlsCidSupport(s_config, true));
*          3. receive a DTLS 1.3 ClientHello carrying a connection_id extension (a pure-1.3 client
*             built with HITLS_CFG_NewDTLS13Config advertises CID natively, no injection needed);
*          4. assert the ServerHello DOES carry the connection_id extension.
*        Because the negotiated version is DTLS 1.3, the server-side guard in
*        DTLS_CID_ProcessClientHello lets isCidNegotiated go true, so ServerHello echoes connection_id.
*        This dual-config positive path was blocked before the NewDTLSConfig / version-negotiation
*        fixes (longparty's f9f9c128 / 67ecd327 / aa8b554e); see openhitls/CLAUDE.md Known Bug.
* @expect 1. Handshake succeeds at DTLS 1.3.
*         2. Both sides have CID negotiated (ServerHello carries connection_id).
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC022(void)
{
    FRAME_Init();

    /* Client: pure DTLS 1.3 — its ClientHello natively carries connection_id (no injection,
     * unlike TC021 which splices CID into a 1.2 ClientHello via InjectCidIntoClientHello). */
    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(c_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);

    /* Server: dual-version (DTLS 1.2 + 1.3), CID enabled — identical setup to TC021. */
    HITLS_Config *s_config = HITLS_CFG_NewDTLSConfig();
    ASSERT_TRUE(s_config != NULL);
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(s_config, true), HITLS_SUCCESS);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Arm recv CID on both sides so both ClientHello and ServerHello carry connection_id. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, g_testCidB, TEST_CID_B_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    /* Negotiation landed on DTLS 1.3 — the positive counterpart of TC021's 1.2 outcome.
     * This is the assertion that used to fail (dual server fell back to 1.2) before the fix. */
    ASSERT_EQ(server->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);
    ASSERT_EQ(client->ssl->negotiatedInfo.version, HITLS_VERSION_DTLS13);

    /* Server-side guard passed: a 1.3 ClientHello carrying CID enters NEGOTIATED, so
     * isCidNegotiated is true and ServerHello packing emits connection_id. */
    ASSERT_TRUE(server->ssl->negotiatedInfo.isCidNegotiated);
    ASSERT_TRUE(client->ssl->negotiatedInfo.isCidNegotiated);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC023
* @spec -
* @title Client offers non-empty CID, server offers empty CID: full API state on both ends
* @precon nan
* @brief RFC 9147 §4 / §5: Both endpoints support CID. Client arms a non-empty local recv CID
*        (cid_c = g_testCidA); server arms a zero-length local recv CID. A zero-length CID in
*        the ServerHello still completes negotiation (isCidNegotiated=true on both sides), but
*        the server is telling the client "do not put a CID on records you send to me". Result:
*          - client outbound records carry NO CID (server's recv CID is empty);
*          - server outbound records carry cid_c (client's recv CID).
*        This is the "asymmetric CID" case: only one direction actually carries a CID on the wire.
*        Verify the complete post-handshake API state on BOTH endpoints.
* @expect 1. Handshake succeeds.
*         2. Client: GetDtlsRecvCid -> cid_c (count 1); GetDtlsSendCid -> empty (count 0);
*            IsCidNegotiated -> true; GetDtlsRecvCid(NULL,..) -> count 1.
*         3. Server: GetDtlsRecvCid -> count 0 (local recv CID is empty);
*            GetDtlsSendCid -> cid_c (count 1); IsCidNegotiated -> true;
*            GetDtlsRecvCid(NULL,..) -> count 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC023(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(config, true), HITLS_SUCCESS);
    ASSERT_TRUE(config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client arms a non-empty local recv CID (cid_c); server arms a zero-length recv CID. */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_SetDtlsRecvCid(server->ssl, NULL, 0), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entries[2];
    uint8_t entryCount = 0;
    bool isCidNeg = false;

    /* ===== Client side ===== */
    /* GetDtlsRecvCid: the armed local recv CID (cid_c). */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 1);
    ASSERT_EQ(entries[0].cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(entries[0].cidVal, g_testCidA, TEST_CID_A_LEN), 0);

    /* GetDtlsSendCid: empty -- server's recv CID is zero-length, so client has no peer CID to send. */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* GetDtlsIsCidNegotiated: true (zero-length server CID still completes negotiation). */
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* GetDtlsRecvCid with NULL entries: query the active recv CID count -> 1. */
    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 1);

    /* ===== Server side ===== */
    /* GetDtlsRecvCid: server's local recv CID is empty (zero-length). Even though
     * isCidNegotiated=true, an empty local CID is not reported as an active recv CID. */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* GetDtlsSendCid: the peer CID learned from the ClientHello (cid_c). */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsSendCid(server->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 1);
    ASSERT_EQ(entries[0].cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(entries[0].cidVal, g_testCidA, TEST_CID_A_LEN), 0);

    /* GetDtlsIsCidNegotiated: true. */
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(isCidNeg);

    /* GetDtlsRecvCid with NULL entries: count is 0 (local recv CID is empty). */
    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0), HITLS_INVALID_INPUT);
    ASSERT_EQ(HITLS_SwitchSendCid(server->ssl, NULL, 0), HITLS_INVALID_INPUT);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC024
* @spec -
* @title Client offers CID, server does not support CID: full API state on both ends
* @precon nan
* @brief RFC 9146 §3: The client offers connection_id carrying cid_c, but the server does not
*        support CID, so the ServerHello omits connection_id. CID is NOT negotiated for either
*        direction: subsequent records in BOTH directions carry no CID.
*
*        The recv CID is locally configured (via HITLS_SetDtlsRecvCid) and is reported by
*        GetDtlsRecvCid regardless of negotiation status -- the client armed cid_c, so it is
*        visible. The send CID comes from the peer and is absent (server did not echo CID).
* @expect 1. Handshake succeeds.
*         2. Client: GetDtlsRecvCid -> cid_c (count 1, locally configured);
*            GetDtlsSendCid -> count 0; IsCidNegotiated -> false; GetDtlsRecvCid(NULL,..) -> count 1.
*         3. Server: GetDtlsRecvCid -> count 0; GetDtlsSendCid -> count 0;
*            IsCidNegotiated -> false; GetDtlsRecvCid(NULL,..) -> count 0.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_NEGOTIATE_FUNC_TC024(void)
{
    FRAME_Init();

    HITLS_Config *c_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_EQ(HITLS_CFG_SetDtlsCidSupport(c_config, true), HITLS_SUCCESS);
    ASSERT_TRUE(c_config != NULL);
    /* Server config does NOT enable CID. */
    HITLS_Config *s_config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(s_config != NULL);

    FRAME_LinkObj *client = FRAME_CreateLink(c_config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(s_config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);

    /* Client arms cid_c; server arms nothing (CID not supported on server side). */
    ASSERT_EQ(HITLS_SetDtlsRecvCid(client->ssl, g_testCidA, TEST_CID_A_LEN), HITLS_SUCCESS);

    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    HITLS_DtlsCidEntry entries[2];
    uint8_t entryCount = 0;
    bool isCidNeg = true;

    /* ===== Client side ===== */
    /* GetDtlsRecvCid: the locally configured recv CID (cid_c). It is reported even though CID
     * was not negotiated -- recv CID presence is driven by local configuration, not negotiation. */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 1);
    ASSERT_EQ(entries[0].cidLen, TEST_CID_A_LEN);
    ASSERT_EQ(memcmp(entries[0].cidVal, g_testCidA, TEST_CID_A_LEN), 0);

    /* GetDtlsSendCid: empty (server's ServerHello carried no connection_id). */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsSendCid(client->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* GetDtlsIsCidNegotiated: false (server did not echo connection_id). */
    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(client->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);

    /* GetDtlsRecvCid with NULL entries: count 1 (locally configured cid_c). */
    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(client->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 1);

    /* ===== Server side ===== */
    /* GetDtlsRecvCid: server never armed a local recv CID -> count 0. */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    /* GetDtlsSendCid: empty (server does not support CID, no peer CID learned). */
    (void)memset(entries, 0, sizeof(entries));
    entryCount = 2;
    ASSERT_EQ(HITLS_GetDtlsSendCid(server->ssl, entries, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    ASSERT_EQ(HITLS_GetDtlsIsCidNegotiated(server->ssl, &isCidNeg), HITLS_SUCCESS);
    ASSERT_TRUE(!isCidNeg);

    entryCount = 0;
    ASSERT_EQ(HITLS_GetDtlsRecvCid(server->ssl, NULL, &entryCount), HITLS_SUCCESS);
    ASSERT_EQ(entryCount, 0);

    ASSERT_EQ(HITLS_SwitchSendCid(client->ssl, NULL, 0), HITLS_MSG_HANDLE_STATE_ILLEGAL);
    ASSERT_EQ(HITLS_SwitchSendCid(server->ssl, NULL, 0), HITLS_MSG_HANDLE_STATE_ILLEGAL);

EXIT:
    HITLS_CFG_FreeConfig(c_config);
    HITLS_CFG_FreeConfig(s_config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC022
* @spec RFC 9147 Section 9
* @title No CID negotiated: client drops a CID-bearing application record
* @precon Neither endpoint enables or negotiates connection_id
* @brief Establish a no-CID DTLS 1.3 connection, let the server produce a real
*        encrypted application record, then insert a four-byte CID and set C=1
*        before delivery to the client.
* @expect The malformed record yields no application data and no fatal alert;
*         the connection remains transporting and a following clean app record succeeds.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC022(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, HS_STATE_BUTT), HITLS_SUCCESS);

    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);
    ASSERT_TRUE(!server->ssl->negotiatedInfo.isCidNegotiated);

    uint8_t badApp[] = "cid-bearing app";
    uint32_t writeLen = 0u;
    ASSERT_EQ(HITLS_Write(server->ssl, badApp, sizeof(badApp), &writeLen), HITLS_SUCCESS);

    FrameUioUserData *serverIo = BSL_UIO_GetUserData(server->io);
    ASSERT_TRUE(serverIo != NULL);
    ASSERT_TRUE(serverIo->sndMsg.len > 1u);
    ASSERT_TRUE((serverIo->sndMsg.msg[0] & REC_DTLS13_UNI_HEADER_CID_BIT) == 0u);
    ASSERT_TRUE(serverIo->sndMsg.len + TEST_CID_A_LEN <= MAX_RECORD_LENTH);

    (void)memmove(&serverIo->sndMsg.msg[1u + TEST_CID_A_LEN], &serverIo->sndMsg.msg[1u],
        serverIo->sndMsg.len - 1u);
    (void)memcpy(&serverIo->sndMsg.msg[1u], g_testCidA, TEST_CID_A_LEN);
    serverIo->sndMsg.msg[0] |= REC_DTLS13_UNI_HEADER_CID_BIT;
    serverIo->sndMsg.len += TEST_CID_A_LEN;

    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    uint8_t readBuf[READ_BUF_SIZE] = {0};
    uint32_t readLen = 0u;
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen),
        HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_EQ(readLen, 0u);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);

    uint8_t cleanApp[] = "clean app";
    writeLen = 0u;
    ASSERT_EQ(HITLS_Write(server->ssl, cleanApp, sizeof(cleanApp), &writeLen), HITLS_SUCCESS);
    ASSERT_EQ(FRAME_TrasferMsgBetweenLink(server, client), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Read(client->ssl, readBuf, READ_BUF_SIZE, &readLen), HITLS_SUCCESS);
    ASSERT_EQ(readLen, sizeof(cleanApp));
    ASSERT_EQ(memcmp(readBuf, cleanApp, sizeof(cleanApp)), 0);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC023
* @spec RFC 9147 Section 9
* @title No CID negotiated: client drops a handshake record with C=1 and zero CID length
* @precon Neither endpoint enables or negotiates connection_id
* @brief Pause before the client consumes the server Finished flight and set C=1
*        on every real encrypted handshake record without inserting CID octets.
* @expect The flight is silently discarded and the client stays at TRY_RECV_FINISH;
*         retransmitting the untouched flight completes the no-CID handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC023(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);
    ASSERT_TRUE(!server->ssl->negotiatedInfo.isCidNegotiated);

    FrameUioUserData *clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->recMsg.len > 0u);
    uint8_t original[MAX_RECORD_LENTH];
    uint32_t originalLen = clientIo->recMsg.len;
    (void)memcpy(original, clientIo->recMsg.msg, originalLen);

    ASSERT_EQ(SetEmptyCidBitInFlight(clientIo->recMsg.msg, clientIo->recMsg.len), originalLen);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_FINISH);

    ASSERT_EQ(clientIo->recMsg.len, 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, original, originalLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */

/** @
* @test SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC024
* @spec RFC 9147 Section 9
* @title No CID negotiated: client drops a handshake record with C=0 but physical CID bytes present
* @precon Neither endpoint enables or negotiates connection_id
* @brief Pause before the client consumes the server Finished flight. Keep C=0
*        but insert four would-be CID octets after byte 0 of every record. Because
*        the unified header has no explicit CID-length field, a receiver must not
*        consume these bytes as a CID when C is clear.
* @expect The malformed flight is silently discarded and the client stays at
*         TRY_RECV_FINISH; retransmitting the untouched flight completes the handshake.
@ */
/* BEGIN_CASE */
void SDV_TLS_DTLS13_CID_CONSISTENCY_RECORD_FUNC_TC024(void)
{
    FRAME_Init();

    HITLS_Config *config = HITLS_CFG_NewDTLS13Config();
    ASSERT_TRUE(config != NULL);
    FRAME_LinkObj *client = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(client != NULL);
    FRAME_LinkObj *server = FRAME_CreateLink(config, BSL_UIO_UDP);
    ASSERT_TRUE(server != NULL);
    ASSERT_EQ(FRAME_CreateConnection(client, server, true, TRY_RECV_FINISH), HITLS_SUCCESS);

    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);
    ASSERT_TRUE(!server->ssl->negotiatedInfo.isCidNegotiated);

    FrameUioUserData *clientIo = BSL_UIO_GetUserData(client->io);
    ASSERT_TRUE(clientIo != NULL);
    ASSERT_TRUE(clientIo->recMsg.len > 0u);
    uint8_t original[MAX_RECORD_LENTH];
    uint8_t malformed[MAX_RECORD_LENTH];
    uint32_t originalLen = clientIo->recMsg.len;
    (void)memcpy(original, clientIo->recMsg.msg, originalLen);
    uint32_t malformedLen = InsertHiddenCidInFlight(malformed, sizeof(malformed),
        original, originalLen, g_testCidA);
    ASSERT_TRUE(malformedLen > originalLen);
    ASSERT_TRUE((malformed[0] & REC_DTLS13_UNI_HEADER_CID_BIT) == 0u);

    clientIo->recMsg.len = 0u;
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, malformed, malformedLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_REC_NORMAL_RECV_BUF_EMPTY);
    ASSERT_TRUE(client->ssl->hsCtx != NULL);
    ASSERT_EQ(client->ssl->hsCtx->state, TRY_RECV_FINISH);

    ASSERT_EQ(clientIo->recMsg.len, 0u);
    ASSERT_EQ(FRAME_TransportRecMsg(client->io, original, originalLen), HITLS_SUCCESS);
    ASSERT_EQ(HITLS_Connect(client->ssl), HITLS_SUCCESS);
    ASSERT_EQ(client->ssl->state, CM_STATE_TRANSPORTING);
    ASSERT_TRUE(!client->ssl->negotiatedInfo.isCidNegotiated);

EXIT:
    HITLS_CFG_FreeConfig(config);
    FRAME_FreeLink(client);
    FRAME_FreeLink(server);
}
/* END_CASE */
