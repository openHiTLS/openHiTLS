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

#include "securec.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "hitls_error.h"
#include "hitls_crypt_type.h"
#include "tls.h"
#include "hs_ctx.h"
#include "hs_extensions.h"
#include "frame_tls.h"
#include "frame_msg.h"

#define SIZE_OF_UINT_24 3u
#define SIZE_OF_UINT_48 6u

static int32_t ParseFieldInteger8(const uint8_t *buffer, uint32_t bufLen, FRAME_Integer *field, uint32_t *offset)
{
    if (bufLen < sizeof(uint8_t)) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->state = INITIAL_FIELD;
    field->data = buffer[0];
    *offset += sizeof(uint8_t);
    return HITLS_SUCCESS;
}

static int32_t ParseFieldInteger16(const uint8_t *buffer, uint32_t bufLen, FRAME_Integer *field, uint32_t *offset)
{
    if (bufLen < sizeof(uint16_t)) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->state = INITIAL_FIELD;
    field->data = BSL_ByteToUint16(buffer);
    *offset += sizeof(uint16_t);
    return HITLS_SUCCESS;
}

static int32_t ParseFieldInteger24(const uint8_t *buffer, uint32_t bufLen, FRAME_Integer *field, uint32_t *offset)
{
    if (bufLen < SIZE_OF_UINT_24) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->state = INITIAL_FIELD;
    field->data = BSL_ByteToUint24(buffer);
    *offset += SIZE_OF_UINT_24;
    return HITLS_SUCCESS;
}

static int32_t ParseFieldInteger32(const uint8_t *buffer, uint32_t bufLen, FRAME_Integer *field, uint32_t *offset)
{
    if (bufLen < sizeof(uint32_t)) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->state = INITIAL_FIELD;
    field->data = BSL_ByteToUint32(buffer);
    *offset += sizeof(uint32_t);
    return HITLS_SUCCESS;
}

static int32_t ParseFieldInteger48(const uint8_t *buffer, uint32_t bufLen, FRAME_Integer *field, uint32_t *offset)
{
    if (bufLen < SIZE_OF_UINT_48) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->state = INITIAL_FIELD;
    field->data = BSL_ByteToUint48(buffer);
    *offset += SIZE_OF_UINT_48;
    return HITLS_SUCCESS;
}

static int32_t ParseFieldArray8(const uint8_t *buffer, uint32_t bufLen, FRAME_Array8 *field, uint32_t fieldLen,
                                uint32_t *offset)
{
    if (bufLen < fieldLen) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    BSL_SAL_FREE(field->data);
    field->data = BSL_SAL_Dump(buffer, fieldLen);
    if (field->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    field->size = fieldLen;
    field->state = INITIAL_FIELD;
    *offset += fieldLen;
    return HITLS_SUCCESS;
}

static int32_t ParseFieldArray16(const uint8_t *buffer, uint32_t bufLen, FRAME_Array16 *field, uint32_t fieldLen,
                                 uint32_t *offset)
{
    if ((bufLen < fieldLen) || (fieldLen % sizeof(uint16_t) != 0)) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    field->data = BSL_SAL_Calloc(1u, fieldLen);
    if (field->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    field->size = fieldLen / sizeof(uint16_t);
    for (uint32_t i = 0; i < field->size; i++) {
        field->data[i] = BSL_ByteToUint16(&buffer[i * sizeof(uint16_t)]);
    }
    field->state = INITIAL_FIELD;
    *offset += fieldLen;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtArray8(const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtArray8 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger8(&buffer[exOffset], bufLen - exOffset, &field->exDataLen, &exOffset);
    ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->exData, field->exDataLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtArrayForList(
    const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtArray8 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exDataLen, &exOffset);
    ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->exData, field->exDataLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsSessionTicketExtArray8(
    const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtArray8 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exDataLen, &exOffset);
    if (field->exDataLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->exData, field->exDataLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtArray16(const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtArray16 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen - exOffset, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exDataLen, &exOffset);
    ParseFieldArray16(&buffer[exOffset], bufLen - exOffset, &field->exData, field->exDataLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtPskIdentity(const uint8_t *buffer, uint32_t bufLen, FRAME_HsArrayPskIdentity *field,
    uint32_t fieldLen, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->state = INITIAL_FIELD;
    uint32_t size = 0;
    FRAME_Integer tmpIdentityLen = { 0 };
    while (exOffset < fieldLen) {
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &tmpIdentityLen, &exOffset);
        exOffset += (tmpIdentityLen.data + sizeof(uint32_t));
        if (exOffset <= fieldLen) {
            size++;
        }
    }
    if (size == 0) {
        return HITLS_SUCCESS;
    }
    field->data = BSL_SAL_Calloc(size, sizeof(FRAME_HsPskIdentity));
    if (field->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    field->size = size;
    exOffset = 0;
    for (uint32_t i = 0; i < size; i++) {
        field->data[i].state = INITIAL_FIELD;
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data[i].identityLen, &exOffset);
        ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->data[i].identity,
            field->data[i].identityLen.data, &exOffset);
        ParseFieldInteger32(&buffer[exOffset], bufLen - exOffset, &field->data[i].obfuscatedTicketAge, &exOffset);
    }
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtPskBinder(const uint8_t *buffer, uint32_t bufLen, FRAME_HsArrayPskBinder *field,
    uint32_t fieldLen, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->state = INITIAL_FIELD;
    uint32_t size = 0;
    FRAME_Integer tmpBinderLen = { 0 };
    while (exOffset < fieldLen) {
        ParseFieldInteger8(&buffer[exOffset], bufLen - exOffset, &tmpBinderLen, &exOffset);
        exOffset += tmpBinderLen.data;
        if (exOffset <= fieldLen) {
            size++;
        }
    }
    if (size == 0) {
        return HITLS_SUCCESS;
    }
    field->data = BSL_SAL_Calloc(size, sizeof(FRAME_HsPskBinder));
    if (field->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    field->size = size;
    exOffset = 0;
    for (uint32_t i = 0; i < size; i++) {
        field->data[i].state = INITIAL_FIELD;
        ParseFieldInteger8(&buffer[exOffset], bufLen - exOffset, &field->data[i].binderLen, &exOffset);
        ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->data[i].binder,
            field->data[i].binderLen.data, &exOffset);
    }
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtPsk(const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtOfferedPsks *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen - exOffset, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->identitySize, &exOffset);
    ParseHsExtPskIdentity(&buffer[exOffset], bufLen - exOffset, &field->identities,
        field->identitySize.data, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->binderSize, &exOffset);
    ParseHsExtPskBinder(&buffer[exOffset], bufLen - exOffset, &field->binders, field->binderSize.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtArrayKeyShare(const uint8_t *buffer, uint32_t bufLen, FRAME_HsArrayKeyShare *field,
    uint32_t fieldLen, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->state = INITIAL_FIELD;
    uint32_t size = 0;
    FRAME_Integer tmpIdentityLen = { 0 };
    while (exOffset < fieldLen) {
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &tmpIdentityLen, &exOffset); // group
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &tmpIdentityLen, &exOffset); // key_exchange len
        exOffset += tmpIdentityLen.data;
        if (exOffset <= fieldLen) {
            size++;
        }
    }
    if (size == 0) {
        return HITLS_SUCCESS;
    }
    field->data = BSL_SAL_Calloc(size, sizeof(FRAME_HsKeyShareEntry));
    if (field->data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    field->size = size;
    exOffset = 0;
    for (uint32_t i = 0; i < size; i++) {
        field->data[i].state = INITIAL_FIELD;
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data[i].group, &exOffset);
        ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data[i].keyExchangeLen, &exOffset);
        ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->data[i].keyExchange,
            field->data[i].keyExchangeLen.data, &exOffset);
    }
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtKeyShare(const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtKeyShare *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen - exOffset, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exKeyShareLen, &exOffset);
    ParseHsExtArrayKeyShare(&buffer[exOffset], bufLen - exOffset, &field->exKeyShares,
        field->exKeyShareLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsSupportedVersion(const uint8_t *buffer, uint32_t bufLen,
    FRAME_HsExtArray16 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen - exOffset, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger8(&buffer[exOffset], bufLen - exOffset, &field->exDataLen, &exOffset);
    ParseFieldArray16(&buffer[exOffset], bufLen - exOffset, &field->exData, field->exDataLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseHsExtUint16(const uint8_t *buffer, uint32_t bufLen, FRAME_HsExtUint16 *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseClientHelloMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_ClientHelloMsg *clientHello, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger16(&buffer[0], bufLen, &clientHello->version, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &clientHello->randomValue, HS_RANDOM_SIZE, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &clientHello->sessionIdSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &clientHello->sessionId,
                     clientHello->sessionIdSize.data, &offset);
    if (IS_TRANSTYPE_DATAGRAM(frameType->transportType)) {
        ParseFieldInteger8(&buffer[offset], bufLen - offset, &clientHello->cookiedLen, &offset);
        ParseFieldArray8(&buffer[offset], bufLen - offset, &clientHello->cookie, clientHello->cookiedLen.data, &offset);
    }
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &clientHello->cipherSuitesSize, &offset);
    ParseFieldArray16(&buffer[offset], bufLen - offset, &clientHello->cipherSuites,
                      clientHello->cipherSuitesSize.data, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &clientHello->compressionMethodsLen, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &clientHello->compressionMethods,
                     clientHello->compressionMethodsLen.data, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &clientHello->extensionLen, &offset);
    clientHello->extensionState = INITIAL_FIELD;

    /* Parsing extended fields */
    while (offset < bufLen) {
        FRAME_Integer tmpField = {0};
        uint32_t tmpOffset = offset;
        ParseFieldInteger16(&buffer[tmpOffset], bufLen - tmpOffset, &tmpField, &tmpOffset);
        switch (tmpField.data) {
            case HS_EX_TYPE_POINT_FORMATS:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &clientHello->pointFormats, &offset);
                break;
            case HS_EX_TYPE_SUPPORTED_GROUPS:
                ParseHsExtArray16(&buffer[offset], bufLen - offset, &clientHello->supportedGroups, &offset);
                break;
            case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
                ParseHsExtArray16(&buffer[offset], bufLen - offset, &clientHello->signatureAlgorithms, &offset);
                break;
            case HS_EX_TYPE_EXTENDED_MASTER_SECRET:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &clientHello->extendedMasterSecret, &offset);
                break;
            case HS_EX_TYPE_RENEGOTIATION_INFO:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &clientHello->secRenego, &offset);
                break;
            case HS_EX_TYPE_SESSION_TICKET:
                ParseHsSessionTicketExtArray8(&buffer[offset], bufLen - offset, &clientHello->sessionTicket, &offset);
                break;
            case HS_EX_TYPE_SERVER_NAME:
                ParseHsExtArrayForList(&buffer[offset], bufLen - offset, &clientHello->serverName, &offset);
                break;
            case HS_EX_TYPE_RECORD_SIZE_LIMIT:
                ParseHsExtUint16(&buffer[offset], bufLen - offset, &clientHello->recordSizeLimit, &offset);
                break;
            case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
                ParseHsExtArrayForList(&buffer[offset], bufLen - offset, &clientHello->alpn, &offset);
                break;
            case HS_EX_TYPE_KEY_SHARE:
                ParseHsExtKeyShare(&buffer[offset], bufLen - offset, &clientHello->keyshares, &offset);
                break;
            case HS_EX_TYPE_PRE_SHARED_KEY:
                ParseHsExtPsk(&buffer[offset], bufLen - offset, &clientHello->psks, &offset);
                break;
            case HS_EX_TYPE_PSK_KEY_EXCHANGE_MODES:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &clientHello->pskModes, &offset);
                break;
            case HS_EX_TYPE_SUPPORTED_VERSIONS:
                ParseHsSupportedVersion(&buffer[offset], bufLen - offset, &clientHello->supportedVersion, &offset);
                break;
            case HS_EX_TYPE_COOKIE:
                ParseHsExtArrayForList(&buffer[offset], bufLen - offset, &clientHello->tls13Cookie, &offset);
                break;
            case HS_EX_TYPE_ENCRYPT_THEN_MAC:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &clientHello->encryptThenMac, &offset);
                break;
            default: /* Unrecognized extension. Skip parsing the extension. */
                ParseFieldInteger16(&buffer[tmpOffset], bufLen - tmpOffset, &tmpField, &tmpOffset);
                tmpOffset += tmpField.data;
                offset = tmpOffset;
                break;
        }
        if (tmpOffset == offset) {
            break;
        }
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanClientHelloMsg(FRAME_ClientHelloMsg *clientHello)
{
    BSL_SAL_FREE(clientHello->randomValue.data);
    BSL_SAL_FREE(clientHello->sessionId.data);
    BSL_SAL_FREE(clientHello->cookie.data);
    BSL_SAL_FREE(clientHello->cipherSuites.data);
    BSL_SAL_FREE(clientHello->compressionMethods.data);
    BSL_SAL_FREE(clientHello->pointFormats.exData.data);
    BSL_SAL_FREE(clientHello->supportedGroups.exData.data);
    BSL_SAL_FREE(clientHello->signatureAlgorithms.exData.data);
    BSL_SAL_FREE(clientHello->extendedMasterSecret.exData.data);
    BSL_SAL_FREE(clientHello->secRenego.exData.data);
    BSL_SAL_FREE(clientHello->sessionTicket.exData.data);
    BSL_SAL_FREE(clientHello->serverName.exData.data);
    BSL_SAL_FREE(clientHello->alpn.exData.data);
    for (uint32_t i = 0; i < clientHello->keyshares.exKeyShares.size; i++) {
        BSL_SAL_FREE(clientHello->keyshares.exKeyShares.data[i].keyExchange.data);
    }
    for (uint32_t i = 0; i < clientHello->psks.identities.size; i++) {
        BSL_SAL_FREE(clientHello->psks.identities.data[i].identity.data);
    }
    for (uint32_t i = 0; i < clientHello->psks.binders.size; i++) {
        BSL_SAL_FREE(clientHello->psks.binders.data[i].binder.data);
    }
    BSL_SAL_FREE(clientHello->keyshares.exKeyShares.data);
    BSL_SAL_FREE(clientHello->psks.binders.data);
    BSL_SAL_FREE(clientHello->psks.identities.data);
    BSL_SAL_FREE(clientHello->supportedVersion.exData.data);
    BSL_SAL_FREE(clientHello->tls13Cookie.exData.data);
    BSL_SAL_FREE(clientHello->pskModes.exData.data);
    BSL_SAL_FREE(clientHello->caList.list.data);
    return;
}

static int32_t ParseHsExtServerKeyShare(const uint8_t *buffer, uint32_t bufLen,
    FRAME_HsExtServerKeyShare *field, uint32_t *offset)
{
    uint32_t exOffset = 0;
    field->exState = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[0], bufLen, &field->exType, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->exLen, &exOffset);
    if (field->exLen.data == 0u) {
        *offset += exOffset;
        return HITLS_SUCCESS;
    }
    field->data.state = INITIAL_FIELD;
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data.group, &exOffset);
    ParseFieldInteger16(&buffer[exOffset], bufLen - exOffset, &field->data.keyExchangeLen, &exOffset);
    ParseFieldArray8(&buffer[exOffset], bufLen - exOffset, &field->data.keyExchange,
        field->data.keyExchangeLen.data, &exOffset);
    *offset += exOffset;
    return HITLS_SUCCESS;
}

static int32_t ParseServerHelloMsg(const uint8_t *buffer, uint32_t bufLen, FRAME_ServerHelloMsg *serverHello,
                                   uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger16(&buffer[0], bufLen, &serverHello->version, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &serverHello->randomValue, HS_RANDOM_SIZE, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &serverHello->sessionIdSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &serverHello->sessionId,
                     serverHello->sessionIdSize.data, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &serverHello->cipherSuite, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &serverHello->compressionMethod, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &serverHello->extensionLen, &offset);

    /* Parsing extended fields */
    while (offset < bufLen) {
        FRAME_Integer tmpField = {0};
        uint32_t tmpOffset = offset;
        ParseFieldInteger16(&buffer[tmpOffset], bufLen - tmpOffset, &tmpField, &tmpOffset);
        switch (tmpField.data) {
            case HS_EX_TYPE_POINT_FORMATS:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &serverHello->pointFormats, &offset);
                break;
            case HS_EX_TYPE_EXTENDED_MASTER_SECRET:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &serverHello->extendedMasterSecret, &offset);
                break;
            case HS_EX_TYPE_RENEGOTIATION_INFO:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &serverHello->secRenego, &offset);
                break;
            case HS_EX_TYPE_SESSION_TICKET:
                ParseHsSessionTicketExtArray8(&buffer[offset], bufLen - offset, &serverHello->sessionTicket, &offset);
                break;
            case HS_EX_TYPE_SERVER_NAME:
                ParseHsExtArrayForList(&buffer[offset], bufLen - offset, &serverHello->serverName, &offset);
                break;
            case HS_EX_TYPE_RECORD_SIZE_LIMIT:
                ParseHsExtUint16(&buffer[offset], bufLen - offset, &serverHello->recordSizeLimit, &offset);
                break;
            case HS_EX_TYPE_APP_LAYER_PROTOCOLS:
                ParseHsExtArrayForList(&buffer[offset], bufLen - offset, &serverHello->alpn, &offset);
                break;
            case HS_EX_TYPE_SUPPORTED_VERSIONS:
                ParseHsExtUint16(&buffer[offset], bufLen - offset, &serverHello->supportedVersion, &offset);
                break;
            case HS_EX_TYPE_KEY_SHARE:
                ParseHsExtServerKeyShare(&buffer[offset], bufLen - offset, &serverHello->keyShare, &offset);
                break;
            case HS_EX_TYPE_PRE_SHARED_KEY:
                ParseHsExtUint16(&buffer[offset], bufLen - offset, &serverHello->pskSelectedIdentity, &offset);
                break;
            case HS_EX_TYPE_COOKIE:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &serverHello->tls13Cookie, &offset);
                break;
            case HS_EX_TYPE_ENCRYPT_THEN_MAC:
                ParseHsExtArray8(&buffer[offset], bufLen - offset, &serverHello->encryptThenMac, &offset);
                break;
            default: /* Unrecognized extension, return error */
                *parseLen += offset;
                return HITLS_PARSE_UNSUPPORTED_EXTENSION;
        }
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanServerHelloMsg(FRAME_ServerHelloMsg *serverHello)
{
    BSL_SAL_FREE(serverHello->randomValue.data);
    BSL_SAL_FREE(serverHello->sessionId.data);
    BSL_SAL_FREE(serverHello->pointFormats.exData.data);
    BSL_SAL_FREE(serverHello->extendedMasterSecret.exData.data);
    BSL_SAL_FREE(serverHello->secRenego.exData.data);
    BSL_SAL_FREE(serverHello->sessionTicket.exData.data);
    BSL_SAL_FREE(serverHello->serverName.exData.data);
    BSL_SAL_FREE(serverHello->alpn.exData.data);
    BSL_SAL_FREE(serverHello->keyShare.data.keyExchange.data);
    BSL_SAL_FREE(serverHello->tls13Cookie.exData.data);
    return;
}

static int32_t ParseCertificateMsg(
    FRAME_Type *type, const uint8_t *buffer, uint32_t bufLen, FRAME_CertificateMsg *certificate, uint32_t *parseLen)
{
    uint32_t offset = 0;
    if (type->versionType == HITLS_VERSION_TLS13) {
        ParseFieldInteger8(&buffer[0], bufLen, &certificate->certificateReqCtxSize, &offset);
        ParseFieldArray8(&buffer[offset], bufLen - offset, &certificate->certificateReqCtx,
                            certificate->certificateReqCtxSize.data, &offset);
    }
    ParseFieldInteger24(&buffer[offset], bufLen - offset, &certificate->certsLen, &offset);
    if (certificate->certsLen.data == 0) {
        *parseLen += offset;
        return HITLS_SUCCESS;
    }

    FrameCertItem *certItem = NULL;
    while (offset < bufLen) {
        uint32_t tmpOffset = offset;
        FrameCertItem *item = BSL_SAL_Calloc(1u, sizeof(FrameCertItem));
        if (item == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        item->state = INITIAL_FIELD;
        ParseFieldInteger24(&buffer[offset], bufLen - offset, &item->certLen, &offset);
        ParseFieldArray8(&buffer[offset], bufLen - offset, &item->cert, item->certLen.data, &offset);
        if (type->versionType == HITLS_VERSION_TLS13) {
            ParseFieldInteger16(&buffer[offset], bufLen - offset, &item->extensionLen, &offset);
            ParseFieldArray8(&buffer[offset], bufLen - offset, &item->extension, item->extensionLen.data, &offset);
        }
        if (certificate->certItem == NULL) {
            certificate->certItem = item;
        } else {
            certItem->next = item;
        }
        certItem = item;
        if (tmpOffset == offset) {
            break;
        }
    }
    *parseLen += offset;

    return HITLS_SUCCESS;
}

static void CleanCertificateMsg(FRAME_CertificateMsg *certificate)
{
    BSL_SAL_FREE(certificate->certificateReqCtx.data);
    FrameCertItem *certItem = certificate->certItem;
    while (certItem != NULL) {
        FrameCertItem *temp = certItem->next;
        BSL_SAL_FREE(certItem->cert.data);
        BSL_SAL_FREE(certItem->extension.data);
        BSL_SAL_FREE(certItem);
        certItem = temp;
    }
    certificate->certItem = NULL;
    return;
}

static int32_t ParseServerKxEcdhMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                    FRAME_ServerEcdh *ecdh, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger8(&buffer[0], bufLen, &ecdh->curveType, &offset);
    if (ecdh->curveType.data != HITLS_EC_CURVE_TYPE_NAMED_CURVE) {
        return HITLS_PARSE_UNSUPPORT_KX_ALG;
    }
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &ecdh->namedcurve, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &ecdh->pubKeySize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &ecdh->pubKey, ecdh->pubKeySize.data, &offset);
    if (((!IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType >= HITLS_VERSION_TLS12)) ||
        ((IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType <= HITLS_VERSION_DTLS12))) {
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &ecdh->signAlgorithm, &offset);
    }
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &ecdh->signSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &ecdh->signData, ecdh->signSize.data, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static int32_t ParseServerKxDhMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                  FRAME_ServerDh *dh, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger16(&buffer[0], bufLen, &dh->plen, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &dh->p, dh->plen.data, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &dh->glen, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &dh->g, dh->glen.data, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &dh->pubKeyLen, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &dh->pubKey, dh->pubKeyLen.data, &offset);
    if (((!IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType >= HITLS_VERSION_TLS12)) ||
        ((IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType <= HITLS_VERSION_DTLS12))) {
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &dh->signAlgorithm, &offset);
    }
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &dh->signSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &dh->signData, dh->signSize.data, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static int32_t ParseServerKxEccMsg(const uint8_t *buffer, uint32_t bufLen,
                                    FRAME_ServerEcdh *ecdh, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &ecdh->signSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &ecdh->signData, ecdh->signSize.data, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static int32_t ParseServerKxMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                FRAME_ServerKeyExchangeMsg *serverKx, uint32_t *parseLen)
{
    switch (frameType->keyExType) {
        case HITLS_KEY_EXCH_ECDHE:
            return ParseServerKxEcdhMsg(frameType, buffer, bufLen, &serverKx->keyEx.ecdh, parseLen);
        case HITLS_KEY_EXCH_DHE:
            return ParseServerKxDhMsg(frameType, buffer, bufLen, &serverKx->keyEx.dh, parseLen);
        case HITLS_KEY_EXCH_ECC:
            return ParseServerKxEccMsg(buffer, bufLen, &serverKx->keyEx.ecdh, parseLen);
        default:
            break;
    }
    return HITLS_PARSE_UNSUPPORT_KX_ALG;
}

static void CleanServerKxMsg(HITLS_KeyExchAlgo kexType, FRAME_ServerKeyExchangeMsg *serverKx)
{
    FRAME_ServerEcdh *ecdh = &serverKx->keyEx.ecdh;
    FRAME_ServerDh *dh = &serverKx->keyEx.dh;
    switch (kexType) {
        case HITLS_KEY_EXCH_ECDHE:
            BSL_SAL_FREE(ecdh->pubKey.data);
            BSL_SAL_FREE(ecdh->signData.data);
            break;
        case HITLS_KEY_EXCH_DHE:
            BSL_SAL_FREE(dh->p.data);
            BSL_SAL_FREE(dh->g.data);
            BSL_SAL_FREE(dh->pubKey.data);
            BSL_SAL_FREE(dh->signData.data);
            break;
        default:
            break;
    }
    return;
}

static int32_t ParseCertReqMsgExBody(uint16_t extMsgType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_CertificateRequestMsg *certReq, uint32_t *parseLen)
{
    uint32_t offset = 0;
    switch (extMsgType) {
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
            ParseFieldInteger16(&buffer[offset], bufLen - offset, &certReq->signatureAlgorithmsSize, &offset);
            ParseFieldArray16(&buffer[offset], bufLen - offset, &certReq->signatureAlgorithms,
                                certReq->signatureAlgorithmsSize.data, &offset);
            break;
        default:
            break;
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static int32_t ParseCertReqMsg(
    FRAME_Type *type, const uint8_t *buffer, uint32_t bufLen, FRAME_CertificateRequestMsg *certReq, uint32_t *parseLen)
{
    uint32_t offset = 0;
    certReq->state = INITIAL_FIELD;
    if (type->versionType != HITLS_VERSION_TLS13) {
        ParseFieldInteger8(&buffer[0], bufLen, &certReq->certTypesSize, &offset);
        ParseFieldArray8(&buffer[offset], bufLen - offset, &certReq->certTypes, certReq->certTypesSize.data, &offset);
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &certReq->signatureAlgorithmsSize, &offset);
        ParseFieldArray16(&buffer[offset], bufLen - offset, &certReq->signatureAlgorithms,
                        certReq->signatureAlgorithmsSize.data, &offset);
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &certReq->distinguishedNamesSize, &offset);
        if (certReq->distinguishedNamesSize.data != 0u) {
            ParseFieldArray8(&buffer[offset], bufLen - offset, &certReq->distinguishedNames,
                            certReq->distinguishedNamesSize.data, &offset);
        }
    } else {
        ParseFieldInteger8(&buffer[0], bufLen, &certReq->certificateReqCtxSize, &offset);
        ParseFieldArray8(&buffer[offset],
            bufLen - offset,
            &certReq->certificateReqCtx,
            certReq->certificateReqCtxSize.data,
            &offset);
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &certReq->exMsgLen, &offset);
        while (offset < bufLen) {
            uint32_t tmpOffset = offset;
            FRAME_Integer extMsgType ;
            FRAME_Integer extMsgLen ;
            ParseFieldInteger16(&buffer[offset], bufLen - offset, &extMsgType, &offset);
            ParseFieldInteger16(&buffer[offset], bufLen - offset, &extMsgLen, &offset);
            ParseCertReqMsgExBody(extMsgType.data, &buffer[offset], bufLen - offset, certReq, &offset);
            if (offset == tmpOffset) {
                break;
            }
        }
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanCertReqMsg(FRAME_CertificateRequestMsg *certReq)
{
    BSL_SAL_FREE(certReq->certTypes.data);
    BSL_SAL_FREE(certReq->signatureAlgorithms.data);
    BSL_SAL_FREE(certReq->distinguishedNames.data);
    BSL_SAL_FREE(certReq->certificateReqCtx.data);
    return;
}

static int32_t ParseServerHelloDoneMsg(uint32_t bufLen)
{
    if (bufLen != 0) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }
    return HITLS_SUCCESS;
}

static void CleanServerHelloDoneMsg(FRAME_ServerHelloDoneMsg *serverHelloDone)
{
    /* The ServerHelloDone packet is an empty packet. If there is any constructed data, release it. */
    BSL_SAL_FREE(serverHelloDone->extra.data);
    return;
}

static int32_t ParseClientKxMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                FRAME_ClientKeyExchangeMsg *clientKx, uint32_t *parseLen)
{
    uint32_t offset = 0;
    switch (frameType->keyExType) {
        case HITLS_KEY_EXCH_ECDHE:
            /* Three bytes are added to the client key exchange. */
#ifdef HITLS_TLS_PROTO_TLCP11
            if (frameType->versionType == HITLS_VERSION_TLCP_DTLCP11) {
                // Curve type + Curve ID + Public key length
                uint8_t minLen = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t);
                if (bufLen < minLen) {
                    return HITLS_PARSE_INVALID_MSG_LEN;
                }
                // Ignore the first three bytes.
                offset += sizeof(uint8_t) + sizeof(uint16_t);
            }
#endif
            ParseFieldInteger8(&buffer[offset], bufLen - offset, &clientKx->pubKeySize, &offset);
            ParseFieldArray8(&buffer[offset], bufLen - offset, &clientKx->pubKey, clientKx->pubKeySize.data, &offset);
            break;
        case HITLS_KEY_EXCH_DHE:
        case HITLS_KEY_EXCH_RSA:
            ParseFieldInteger16(&buffer[offset], bufLen - offset, &clientKx->pubKeySize, &offset);
            ParseFieldArray8(&buffer[offset], bufLen - offset, &clientKx->pubKey, clientKx->pubKeySize.data, &offset);
            break;
        default:
            return HITLS_PARSE_UNSUPPORT_KX_ALG;
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanClientKxMsg(FRAME_ClientKeyExchangeMsg *clientKx)
{
    BSL_SAL_FREE(clientKx->pubKey.data);
    return;
}

static int32_t ParseCertVerifyMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                  FRAME_CertificateVerifyMsg *certVerify, uint32_t *parseLen)
{
    uint32_t offset = 0;
    if (((!IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType >= HITLS_VERSION_TLS12)) ||
        ((IS_DTLS_VERSION(frameType->versionType)) && (frameType->versionType <= HITLS_VERSION_DTLS12))) {
        ParseFieldInteger16(&buffer[0], bufLen, &certVerify->signHashAlg, &offset);
    }
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &certVerify->signSize, &offset);
    ParseFieldArray8(&buffer[offset], bufLen - offset, &certVerify->sign, certVerify->signSize.data, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanCertVerifyMsg(FRAME_CertificateVerifyMsg *certVerify)
{
    BSL_SAL_FREE(certVerify->sign.data);
    return;
}

static int32_t ParseFinishedMsg(const uint8_t *buffer, uint32_t bufLen, FRAME_FinishedMsg *finished, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldArray8(buffer, bufLen, &finished->verifyData, bufLen, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanFinishedMsg(FRAME_FinishedMsg *finished)
{
    BSL_SAL_FREE(finished->verifyData.data);
    return;
}

static int32_t ParseNewSessionTicket(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                                     FRAME_NewSessionTicketMsg *sessionTicket, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger32(&buffer[0], bufLen, &sessionTicket->ticketLifetime, &offset);

    if (frameType->versionType != HITLS_VERSION_TLS13) {
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &sessionTicket->ticketSize, &offset);
        ParseFieldArray8(
            &buffer[offset], bufLen - offset, &sessionTicket->ticket, sessionTicket->ticketSize.data, &offset);
    } else {
        ParseFieldInteger32(&buffer[offset], bufLen - offset, &sessionTicket->ticketAgeAdd, &offset);
        ParseFieldInteger8(&buffer[offset], bufLen - offset, &sessionTicket->ticketNonceSize, &offset);
        ParseFieldArray8(&buffer[offset], bufLen - offset, &sessionTicket->ticketNonce,
            sessionTicket->ticketNonceSize.data, &offset);
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &sessionTicket->ticketSize, &offset);
        ParseFieldArray8(
            &buffer[offset], bufLen - offset, &sessionTicket->ticket, sessionTicket->ticketSize.data, &offset);
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &sessionTicket->extensionLen, &offset);
        while (offset < bufLen) {
            FRAME_Integer tmpField = {0};
            uint32_t tmpOffset = offset;
            ParseFieldInteger16(&buffer[tmpOffset], bufLen - tmpOffset, &tmpField, &tmpOffset);
            switch (tmpField.data) {
                default:
                    /* The extensions in the tls 1.3 new session ticket cannot be parsed currently. Skip this step. */
                    ParseFieldInteger16(&buffer[tmpOffset], bufLen - tmpOffset, &tmpField, &tmpOffset);
                    tmpOffset += tmpField.data;
                    offset = tmpOffset;
                    break;
            }
        }
    }
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanNewSessionTicket(FRAME_NewSessionTicketMsg *sessionTicket)
{
    BSL_SAL_FREE(sessionTicket->ticket.data);
    BSL_SAL_FREE(sessionTicket->ticketNonce.data);
    return;
}

static int32_t ParseHsMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
    FRAME_HsMsg *hsMsg, uint32_t *parseLen)
{
    uint32_t offset = 0;
    ParseFieldInteger8(&buffer[0], bufLen, &hsMsg->type, &offset);
    ParseFieldInteger24(&buffer[offset], bufLen - offset, &hsMsg->length, &offset);

    if (IS_TRANSTYPE_DATAGRAM(frameType->transportType)) {
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &hsMsg->sequence, &offset);
        ParseFieldInteger24(&buffer[offset], bufLen - offset, &hsMsg->fragmentOffset, &offset);
        ParseFieldInteger24(&buffer[offset], bufLen - offset, &hsMsg->fragmentLength, &offset);
    }
    *parseLen += offset;

    /* To ensure that the memory can be normally released after users modify hsMsg->type.data,
     * assign a value to frameType. */
    frameType->handshakeType = hsMsg->type.data;
    switch (hsMsg->type.data) {
        case CLIENT_HELLO:
            return ParseClientHelloMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.clientHello, parseLen);
        case SERVER_HELLO:
            return ParseServerHelloMsg(&buffer[offset], bufLen - offset, &hsMsg->body.serverHello, parseLen);
        case CERTIFICATE:
            return ParseCertificateMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.certificate, parseLen);
        case SERVER_KEY_EXCHANGE:
            return ParseServerKxMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.serverKeyExchange,
                                    parseLen);
        case CERTIFICATE_REQUEST:
            return ParseCertReqMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.certificateReq, parseLen);
        case CLIENT_KEY_EXCHANGE:
            return ParseClientKxMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.clientKeyExchange,
                                    parseLen);
        case CERTIFICATE_VERIFY:
            return ParseCertVerifyMsg(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.certificateVerify,
                                      parseLen);
        case FINISHED:
            return ParseFinishedMsg(&buffer[offset], bufLen - offset, &hsMsg->body.finished, parseLen);
        case SERVER_HELLO_DONE:
            return ParseServerHelloDoneMsg(bufLen - offset);
        case NEW_SESSION_TICKET:
            return ParseNewSessionTicket(frameType, &buffer[offset], bufLen - offset, &hsMsg->body.newSessionTicket,
                                    parseLen);
        default:
            break;
    }
    return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
}

static int32_t ParseCcsMsg(const uint8_t *buffer, uint32_t bufLen, FRAME_CcsMsg *ccsMsg, uint32_t *parseLen)
{
    /* The length of the CCS message is 1 byte. */
    if (bufLen != 1u) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t offset = 0;
    ParseFieldInteger8(buffer, bufLen, &ccsMsg->ccsType, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanCcsMsg(FRAME_CcsMsg *ccsMsg)
{
    /* This field is used to construct abnormal packets. Data is not written during parsing. However,
     * users may apply for memory. Therefore, this field needs to be released. */
    BSL_SAL_FREE(ccsMsg->extra.data);
    return;
}

static int32_t ParseAlertMsg(const uint8_t *buffer, uint32_t bufLen, FRAME_AlertMsg *alertMsg, uint32_t *parseLen)
{
    /* The length of the alert message is 2 bytes. */
    if (bufLen != 2u) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t offset = 0;
    ParseFieldInteger8(&buffer[0], bufLen, &alertMsg->alertLevel, &offset);
    ParseFieldInteger8(&buffer[offset], bufLen - offset, &alertMsg->alertDescription, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanAlertMsg(FRAME_AlertMsg *alertMsg)
{
    /* This field is used to construct abnormal packets. Data is not written during parsing.
     * However, users may apply for memory. Therefore, this field needs to be released. */
    BSL_SAL_FREE(alertMsg->extra.data);
    return;
}

static int32_t ParseAppMsg(const uint8_t *buffer, uint32_t bufLen, FRAME_AppMsg *appMsg, uint32_t *parseLen)
{
    if (bufLen == 0u) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    uint32_t offset = 0;
    ParseFieldArray8(buffer, bufLen, &appMsg->appData, bufLen, &offset);
    *parseLen += offset;
    return HITLS_SUCCESS;
}

static void CleanAppMsg(FRAME_AppMsg *appMsg)
{
    BSL_SAL_FREE(appMsg->appData.data);
    return;
}

int32_t FRAME_ParseMsgHeader(
    FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen, FRAME_Msg *msg, uint32_t *parseLen)
{
    if ((frameType == NULL) || (buffer == NULL) || (msg == NULL) || (parseLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t offset = 0;
    ParseFieldInteger8(&buffer[0], bufLen, &msg->recType, &offset);
    ParseFieldInteger16(&buffer[offset], bufLen - offset, &msg->recVersion, &offset);

    if (IS_TRANSTYPE_DATAGRAM(frameType->transportType)) {
        ParseFieldInteger16(&buffer[offset], bufLen - offset, &msg->epoch, &offset);
        ParseFieldInteger48(&buffer[offset], bufLen - offset, &msg->sequence, &offset);
    }

    ParseFieldInteger16(&buffer[offset], bufLen - offset, &msg->length, &offset);
    if ((msg->length.data + offset) > bufLen) {
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    *parseLen = offset;
    return HITLS_SUCCESS;
}

int32_t FRAME_ParseTLSRecordHeader(const uint8_t *buffer, uint32_t bufferLen, FRAME_Msg *msg, uint32_t *parsedLen)
{
    if ((buffer == NULL) || (msg == NULL) || (parsedLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t offset = 0;
    // Parse the 0th byte of the buffer. The parsing result is stored in msg->recType, offset = 1.
    ParseFieldInteger8(buffer, bufferLen, &msg->recType, &offset);
    // Parse the first and second bytes of the buffer. The parsing result is stored in msg->recVersion, offset = 3.
    ParseFieldInteger16(buffer + offset, bufferLen - offset, &msg->recVersion, &offset);
    // Parse the third to fourth bytes of the buffer. The parsing result is stored in msg->length, and offset = 5.
    ParseFieldInteger16(buffer + offset, bufferLen - offset, &msg->length, &offset);
    // msg->length.data indicates the length of the parsed record body.
    // In this case, the value of offset is the header length.
    if ((msg->length.data + offset) > bufferLen) {
        // The length of the entire message cannot be greater than bufLen.
        return HITLS_PARSE_INVALID_MSG_LEN;
    }

    *parsedLen = offset;
    return HITLS_SUCCESS;
}

// Parse the body of a non-handshake record.
int32_t FRAME_ParseTLSNonHsRecordBody(const uint8_t *buffer, uint32_t bufferLen, FRAME_Msg *msg, uint32_t *parseLen)
{
    if ((buffer == NULL) || (msg == NULL) || (parseLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    switch (msg->recType.data) {
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            return ParseCcsMsg(buffer, bufferLen, &msg->body.ccsMsg, parseLen);
        case REC_TYPE_ALERT:
            return ParseAlertMsg(buffer, bufferLen, &msg->body.alertMsg, parseLen);
        case REC_TYPE_APP:
            return ParseAppMsg(buffer, bufferLen, &msg->body.appMsg, parseLen);
        default:
            break;
    }
    return HITLS_INTERNAL_EXCEPTION;
}

int32_t FRAME_ParseMsgBody(
    FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen, FRAME_Msg *msg, uint32_t *parseLen)
{
    if ((frameType == NULL) || (buffer == NULL) || (msg == NULL) || (parseLen == NULL)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    /* To ensure that the memory can be normally released after users modify msg->recType.data,
     * assign a value to frameType. */
    frameType->recordType = msg->recType.data;
    switch (msg->recType.data) {
        case REC_TYPE_HANDSHAKE:
            return ParseHsMsg(frameType, buffer, bufLen, &msg->body.hsMsg, parseLen);
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            return ParseCcsMsg(buffer, bufLen, &msg->body.ccsMsg, parseLen);
        case REC_TYPE_ALERT:
            return ParseAlertMsg(buffer, bufLen, &msg->body.alertMsg, parseLen);
        case REC_TYPE_APP:
            return ParseAppMsg(buffer, bufLen, &msg->body.appMsg, parseLen);
        default:
            break;
    }

    return HITLS_INTERNAL_EXCEPTION;
}

int32_t FRAME_ParseMsg(FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufLen,
                       FRAME_Msg *msg, uint32_t *parseLen)
{
    int32_t ret;
    ret = FRAME_ParseMsgHeader(frameType, buffer, bufLen, msg, parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    return FRAME_ParseMsgBody(frameType, &buffer[*parseLen], msg->length.data, msg, parseLen);
}

int32_t FRAME_ParseTLSNonHsRecord(const uint8_t *buffer, uint32_t bufLen, FRAME_Msg *msg, uint32_t *parseLen)
{
    int32_t ret;
    uint32_t headerLen;
    ret = FRAME_ParseTLSRecordHeader(buffer, bufLen, msg, parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    headerLen = *parseLen;
    return FRAME_ParseTLSNonHsRecordBody(buffer + headerLen, msg->length.data, msg, parseLen);
}

int32_t FRAME_ParseHsRecord(
    FRAME_Type *frameType, const uint8_t *buffer, uint32_t bufferLen, FRAME_Msg *msg, uint32_t *parseLen)
{
    int32_t ret;
    uint32_t headerLen;
    ret = FRAME_ParseMsgHeader(frameType, buffer, bufferLen, msg, parseLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    headerLen = *parseLen;
    /* To ensure that the memory can be normally released after users modify msg->recType.data,
     * assign a value to frameType. */
    frameType->recordType = msg->recType.data;
    if (msg->recType.data == REC_TYPE_HANDSHAKE) {
        return ParseHsMsg(frameType, buffer + headerLen, msg->length.data, &msg->body.hsMsg, parseLen);
    }
    return HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG;
}

static void CleanParsedHsMsg(HS_MsgType handshakeType, HITLS_KeyExchAlgo kexType, FRAME_HsMsg *hsMsg)
{
    switch (handshakeType) {
        case CLIENT_HELLO:
            return CleanClientHelloMsg(&hsMsg->body.clientHello);
        case SERVER_HELLO:
            return CleanServerHelloMsg(&hsMsg->body.serverHello);
        case CERTIFICATE:
            return CleanCertificateMsg(&hsMsg->body.certificate);
        case SERVER_KEY_EXCHANGE:
            return CleanServerKxMsg(kexType, &hsMsg->body.serverKeyExchange);
        case CERTIFICATE_REQUEST:
            return CleanCertReqMsg(&hsMsg->body.certificateReq);
        case CLIENT_KEY_EXCHANGE:
            return CleanClientKxMsg(&hsMsg->body.clientKeyExchange);
        case CERTIFICATE_VERIFY:
            return CleanCertVerifyMsg(&hsMsg->body.certificateVerify);
        case FINISHED:
            return CleanFinishedMsg(&hsMsg->body.finished);
        case SERVER_HELLO_DONE:
            return CleanServerHelloDoneMsg(&hsMsg->body.serverHelloDone);
        case NEW_SESSION_TICKET:
            return CleanNewSessionTicket(&hsMsg->body.newSessionTicket);
        default:
            break;
    }
    return;
}

static void CleanHsMsg(FRAME_Type *frameType, FRAME_HsMsg *hsMsg)
{
    return CleanParsedHsMsg(frameType->handshakeType, frameType->keyExType, hsMsg);
}

void FRAME_CleanMsg(FRAME_Type *frameType, FRAME_Msg *msg)
{
    if ((frameType == NULL) || (msg == NULL)) {
        return;
    }

    switch (frameType->recordType) {
        case REC_TYPE_HANDSHAKE:
            CleanHsMsg(frameType, &msg->body.hsMsg);
            break;
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            CleanCcsMsg(&msg->body.ccsMsg);
            break;
        case REC_TYPE_ALERT:
            CleanAlertMsg(&msg->body.alertMsg);
            break;
        case REC_TYPE_APP:
            CleanAppMsg(&msg->body.appMsg);
            break;
        default:
            break;
    }
    memset_s(msg, sizeof(FRAME_Msg), 0, sizeof(FRAME_Msg));
    return;
}

void FRAME_CleanNonHsRecord(REC_Type recType, FRAME_Msg *msg)
{
    if (msg == NULL) {
        return;
    }
    switch (recType) {
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            CleanCcsMsg(&msg->body.ccsMsg);
            break;
        case REC_TYPE_ALERT:
            CleanAlertMsg(&msg->body.alertMsg);
            break;
        case REC_TYPE_APP:
            CleanAppMsg(&msg->body.appMsg);
            break;
        default:
            break;
    }
    memset_s(msg, sizeof(FRAME_Msg), 0, sizeof(FRAME_Msg));
}