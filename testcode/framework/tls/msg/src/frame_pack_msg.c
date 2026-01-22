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
#include "hitls_error.h"
#include "hitls.h"
#include "tls.h"
#include "hs_ctx.h"
#include "frame_msg.h"
#include "hs_extensions.h"

#define TLS_RECORD_HEADER_LEN  5
#define DTLS_RECORD_HEADER_LEN 13

#define SIZE_OF_UINT24 3
#define SIZE_OF_UINT32 4
#define SIZE_OF_UINT48 6

#define ONE_TIME 1
#define TWO_TIMES 2

// Assemble 8-bit data(1 byte)
static int32_t PackInteger8(const FRAME_Integer *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    uint32_t bufOffset = 0;

    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Repeated assembly
    if (field->state == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Not enough to assemble
    if (bufLen < (sizeof(uint8_t) * repeats)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    for (uint32_t i = 0; i < repeats; i++) {
        uint8_t data = (uint8_t)(field->data);
        buf[bufOffset] = data;
        bufOffset += sizeof(uint8_t);
        *offset += sizeof(uint8_t);
    }
    return HITLS_SUCCESS;
}

// Assemble 16-bit data(2 bytes)
static int32_t PackInteger16(const FRAME_Integer *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    uint32_t bufOffset = 0;

    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Repeated assembly
    if (field->state == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Not enough to assemble
    if (bufLen < (sizeof(uint16_t) * repeats)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (field->state == SET_LEN_TO_ONE_BYTE) {
        uint8_t data = (uint8_t)field->data;
        buf[0] = data;
        *offset += sizeof(uint8_t);
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < repeats; i++) {
        uint16_t data = (uint16_t)(field->data);
        BSL_Uint16ToByte(data, &buf[bufOffset]);
        bufOffset += sizeof(uint16_t);
        *offset += sizeof(uint16_t);
    }
    return HITLS_SUCCESS;
}

// Assemble 24-bit data(3 bytes)
static int32_t PackInteger24(const FRAME_Integer *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    uint32_t bufOffset = 0;

    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Repeated assembly
    if (field->state == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Not enough to assemble
    if (bufLen < (SIZE_OF_UINT24 * repeats)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (field->state == SET_LEN_TO_ONE_BYTE) {
        uint8_t data = (uint8_t)field->data;
        buf[0] = data;
        *offset += sizeof(uint8_t);
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < repeats; i++) {
        uint32_t data = (uint32_t)field->data;
        BSL_Uint24ToByte(data, &buf[bufOffset]);
        bufOffset += SIZE_OF_UINT24;
        *offset += SIZE_OF_UINT24;
    }
    return HITLS_SUCCESS;
}


// Assemble 32-bit data(8 bytes)
static int32_t PackInteger32(const FRAME_Integer *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    uint32_t bufOffset = 0;

    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Repeated assembly
    if (field->state == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Not enough to assemble
    if (bufLen < (SIZE_OF_UINT32 * repeats)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (field->state == SET_LEN_TO_ONE_BYTE) {
        uint8_t data = (uint8_t)field->data;
        buf[0] = data;
        *offset += sizeof(uint8_t);
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < repeats; i++) {
        uint32_t data = (uint32_t)field->data;
        BSL_Uint32ToByte(data, &buf[bufOffset]);
        bufOffset += SIZE_OF_UINT32;
        *offset += SIZE_OF_UINT32;
    }
    return HITLS_SUCCESS;
}

// Assemble 48-bit data(8 bytes)
static int32_t PackInteger48(const FRAME_Integer *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    uint32_t bufOffset = 0;

    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Repeated assembly
    if (field->state == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Not enough to assemble
    if (bufLen < (SIZE_OF_UINT48 * repeats)) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (field->state == SET_LEN_TO_ONE_BYTE) {
        uint8_t data = (uint8_t)field->data;
        buf[0] = data;
        *offset += sizeof(uint8_t);
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < repeats; i++) {
        uint64_t data = (uint64_t)field->data;
        BSL_Uint48ToByte(data, &buf[bufOffset]);
        bufOffset += SIZE_OF_UINT48;
        *offset += SIZE_OF_UINT48;
    }
    return HITLS_SUCCESS;
}

// Assembles the buffer of 8-bit data.(1 byte * n)
static int32_t PackArray8(const FRAME_Array8 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Total length to be assembled
    uint32_t length = field->size;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (memcpy_s(buf, bufLen, field->data, field->size) != EOK) {
        return HITLS_MEMCPY_FAIL;
    }

    *offset += length;
    return HITLS_SUCCESS;
}

// Assemble the buffer of 16-bit data.(2 bytes * n)
static int32_t PackArray16(const FRAME_Array16 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    // No assembly required
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

   // Total length to be assembled
    uint32_t length = field->size * sizeof(uint16_t);

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t bufoffset = 0;
    for (uint32_t i = 0; i < field->size; i++) {
        BSL_Uint16ToByte(field->data[i], &buf[bufoffset]);
        bufoffset += sizeof(uint16_t);
    }

    *offset += length;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtArray8(const FRAME_HsExtArray8 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exDataLen.state == MISSING_FIELD) ? 0 : sizeof(uint8_t));
    length += ((field->exData.state == MISSING_FIELD) ? 0 : sizeof(uint8_t) * field->exData.size);
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger8(&field->exDataLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackArray8(&field->exData, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtArrayForList(const FRAME_HsExtArray8 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exDataLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exData.state == MISSING_FIELD) ? 0 : sizeof(uint8_t) * field->exData.size);
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->exDataLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackArray8(&field->exData, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}


static int32_t PackHsExtArrayForTicket(const FRAME_HsExtArray8 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exDataLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exData.state == MISSING_FIELD) ? 0 : sizeof(uint8_t) * field->exData.size);
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exDataLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackArray8(&field->exData, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exDataLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtArray16(const FRAME_HsExtArray16 *field, uint8_t *buf,
    uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exDataLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exData.state == MISSING_FIELD) ? 0 : sizeof(uint16_t) * field->exData.size);
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->exDataLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackArray16(&field->exData, &buf[bufoffset], bufLen - bufoffset, &bufoffset);

        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }

    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackPskIdentity(const FRAME_HsArrayPskIdentity *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    // This extension does not need to be assembled.
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }
    // Duplicate identity arrays are meaningless. The configuration value can be duplicated.

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    for (uint32_t j = 0; j < field->size; j++) {
        uint32_t innerRepeat = ONE_TIME;
        if (field->data[j].state == MISSING_FIELD) {
            continue;
        }
        if (field->data[j].state == DUPLICATE_FIELD) {
            innerRepeat = TWO_TIMES;
        }
        for (uint32_t k = 0; k < innerRepeat; k++) {
            tmpOffset = bufoffset;
            PackInteger16(&field->data[j].identityLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            PackArray8(&field->data[j].identity, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            if (field->data[j].identityLen.state == INITIAL_FIELD) {
                BSL_Uint16ToByte(field->data[j].identity.size, &buf[tmpOffset]);
            }
            PackInteger32(&field->data[j].obfuscatedTicketAge, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackPskBinder(const FRAME_HsArrayPskBinder *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    // This extension does not need to be assembled.
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }
    // Duplicate identity arrays are meaningless. The configuration value can be duplicated.

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    for (uint32_t j = 0; j < field->size; j++) {
        uint32_t innerRepeat = ONE_TIME;
        if (field->data[j].state == MISSING_FIELD) {
            continue;
        }
        if (field->data[j].state == DUPLICATE_FIELD) {
            innerRepeat = TWO_TIMES;
        }
        for (uint32_t k = 0; k < innerRepeat; k++) {
            tmpOffset = bufoffset;
            PackInteger8(&field->data[j].binderLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            PackArray8(&field->data[j].binder, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            if (field->data[j].binderLen.state == INITIAL_FIELD) {
                buf[tmpOffset] = field->data[j].binder.size;
            }
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}
static int32_t PackHsExtCaList(const FRAME_HsExtCaList *field, uint8_t *buf,
    uint32_t bufLen, uint32_t *offset)
{
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->listSize.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->list.state == MISSING_FIELD) ? 0 : sizeof(uint8_t) * field->list.size);

    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
    tmpOffset = bufoffset;
    PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
    PackInteger16(&field->listSize, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
    PackArray8(&field->list, &buf[bufoffset], bufLen - bufoffset, &bufoffset);

    if (field->exLen.state == INITIAL_FIELD) {
        uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
        BSL_Uint16ToByte(len, &buf[tmpOffset]);
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}
static int32_t PackHsExtOfferedPsks(const FRAME_HsExtOfferedPsks *field, uint8_t *buf,
    uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += field->exLen.data;
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->identitySize, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        // identity len INITIAL_FIELD Not supported currently
        PackPskIdentity(&field->identities, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->binderSize, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        // binder len INITIAL_FIELD Not supported currently
        PackPskBinder(&field->binders, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}
static int32_t PackKeyShareArray(const FRAME_HsArrayKeyShare *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    // This extension does not need to be assembled.
    if (field->state == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }
    // Duplicate key share arrays are meaningless. The configuration value can be duplicated.

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    for (uint32_t j = 0; j < field->size; j++) {
        uint32_t innerRepeat = ONE_TIME;
        if (field->data[j].state == MISSING_FIELD) {
            continue;
        }
        if (field->data[j].state == DUPLICATE_FIELD) {
            innerRepeat = TWO_TIMES;
        }
        for (uint32_t k = 0; k < innerRepeat; k++) {
            PackInteger16(&field->data[j].group, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            tmpOffset = bufoffset;
            PackInteger16(&field->data[j].keyExchangeLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            PackArray8(&field->data[j].keyExchange, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            if (field->data[j].keyExchangeLen.state == INITIAL_FIELD) {
                BSL_Uint16ToByte(field->data[j].keyExchange.size, &buf[tmpOffset]);
            }
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;

}
static int32_t PackHsExtKeyShare(const FRAME_HsExtKeyShare *field, uint8_t *buf,
    uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += field->exLen.data;
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    uint32_t bufoffset = 0;
    uint32_t tmpOffset = 0;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->exKeyShareLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        // exKeyShareLen INITIAL_FIELD Not supported currently
        PackKeyShareArray(&field->exKeyShares, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtSupportedVersion(const FRAME_HsExtArray16 *field, uint8_t *buf,
    uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;

    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }

    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }

    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exDataLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exData.state == MISSING_FIELD) ? 0 : sizeof(uint16_t) * field->exData.size);
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger8(&field->exDataLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackArray16(&field->exData, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }

    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtUint16(const FRAME_HsExtUint16 *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }
    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }
    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += field->exLen.data;
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->data, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }

    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackClientHelloMsg(const FRAME_ClientHelloMsg *clientHello, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    uint32_t bufOffset;

    PackInteger16(&clientHello->version, &buf[offset], bufLen, &offset);
    PackArray8(&clientHello->randomValue, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&clientHello->sessionIdSize, &buf[offset], bufLen - offset, &offset);
    PackArray8(&clientHello->sessionId, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&clientHello->cookiedLen, &buf[offset], bufLen - offset, &offset);
    PackArray8(&clientHello->cookie, &buf[offset], bufLen - offset, &offset);
    PackInteger16(&clientHello->cipherSuitesSize, &buf[offset], bufLen - offset, &offset);
    PackArray16(&clientHello->cipherSuites, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&clientHello->compressionMethodsLen, &buf[offset], bufLen - offset, &offset);
    PackArray8(&clientHello->compressionMethods, &buf[offset], bufLen - offset, &offset);

    bufOffset = offset;
    if (clientHello->extensionState != MISSING_FIELD) {
        PackInteger16(&clientHello->extensionLen, &buf[offset], bufLen - offset, &offset);
        if (clientHello->extensionLen.state == SET_LEN_TO_ONE_BYTE) {
            goto EXIT;
        }
        PackHsExtArrayForList(&clientHello->serverName, &buf[offset], bufLen - offset, &offset);
        PackHsExtUint16(&clientHello->recordSizeLimit, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray16(&clientHello->signatureAlgorithms, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray16(&clientHello->supportedGroups, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray8(&clientHello->pointFormats, &buf[offset], bufLen - offset, &offset);
        PackHsExtSupportedVersion(&clientHello->supportedVersion, &buf[offset], bufLen - offset, &offset);
        PackHsExtArrayForList(&clientHello->tls13Cookie, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray8(&clientHello->extendedMasterSecret, &buf[offset], bufLen - offset, &offset);
        PackHsExtArrayForList(&clientHello->alpn, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray8(&clientHello->pskModes, &buf[offset], bufLen - offset, &offset);
        PackHsExtKeyShare(&clientHello->keyshares, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray8(&clientHello->secRenego, &buf[offset], bufLen - offset, &offset);
        PackHsExtArrayForTicket(&clientHello->sessionTicket, &buf[offset], bufLen - offset, &offset);
        PackHsExtArray8(&clientHello->encryptThenMac, &buf[offset], bufLen - offset, &offset);
        PackHsExtOfferedPsks(&clientHello->psks, &buf[offset], bufLen - offset, &offset);
        PackHsExtCaList(&clientHello->caList, &buf[offset], bufLen - offset, &offset);
        if (clientHello->extensionLen.state == INITIAL_FIELD) {
            uint32_t extensionLen = offset - sizeof(uint16_t) - bufOffset;
            BSL_Uint16ToByte(extensionLen, &buf[bufOffset]);
        }
    }

EXIT:
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackHsExtServerKeyShare(
    const FRAME_HsExtServerKeyShare *field, uint8_t *buf, uint32_t bufLen, uint32_t *offset)
{
    uint32_t repeats = ONE_TIME;
    // This extension does not need to be assembled.
    if (field->exState == MISSING_FIELD) {
        return HITLS_SUCCESS;
    }
    // Currently, duplicate extension types can be assembled. Only one extension type can be assembled.
    if (field->exState == DUPLICATE_FIELD) {
        repeats = TWO_TIMES;
    }
    // Calculate the total length to be assembled
    uint32_t length = 0;
    length += ((field->exType.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += ((field->exLen.state == MISSING_FIELD) ? 0 : sizeof(uint16_t));
    length += field->exLen.data;
    length *= repeats;

    // Not enough to assemble
    if (bufLen < length) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    // Assembly extension type. Duplicate extensions exist. Currently, assembly is performed twice consecutively.
    uint32_t bufoffset = 0;
    uint32_t tmpOffset;
    for (uint32_t i = 0; i < repeats; i++) {
        PackInteger16(&field->exType, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        tmpOffset = bufoffset;
        PackInteger16(&field->exLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->data.group, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        PackInteger16(&field->data.keyExchangeLen, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
            PackArray8(&field->data.keyExchange, &buf[bufoffset], bufLen - bufoffset, &bufoffset);
        if (field->exLen.state == INITIAL_FIELD) {
            uint32_t len = bufoffset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }
    *offset += bufoffset;
    return HITLS_SUCCESS;
}

static int32_t PackServerHelloMsg(const FRAME_ServerHelloMsg *serverHello, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    uint32_t bufOffset;

    PackInteger16(&serverHello->version, &buf[offset], bufLen, &offset);
    PackArray8(&serverHello->randomValue, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&serverHello->sessionIdSize, &buf[offset], bufLen - offset, &offset);
    PackArray8(&serverHello->sessionId, &buf[offset], bufLen - offset, &offset);
    PackInteger16(&serverHello->cipherSuite, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&serverHello->compressionMethod, &buf[offset], bufLen - offset, &offset);

    bufOffset = offset;
    PackInteger16(&serverHello->extensionLen, &buf[offset], bufLen - offset, &offset);
    PackHsExtArrayForList(&serverHello->serverName, &buf[offset], bufLen - offset, &offset);
    PackHsExtUint16(&serverHello->recordSizeLimit, &buf[offset], bufLen - offset, &offset);
    PackHsExtArrayForList(&serverHello->tls13Cookie, &buf[offset], bufLen - offset, &offset);
    PackHsExtArrayForTicket(&serverHello->sessionTicket, &buf[offset], bufLen - offset, &offset);
    PackHsExtUint16(&serverHello->supportedVersion, &buf[offset], bufLen - offset, &offset);
    PackHsExtArray8(&serverHello->extendedMasterSecret, &buf[offset], bufLen - offset, &offset);
    PackHsExtArrayForList(&serverHello->alpn, &buf[offset], bufLen - offset, &offset);
    PackHsExtServerKeyShare(&serverHello->keyShare, &buf[offset], bufLen - offset, &offset);
    // hello retry request key share
    PackHsExtArray8(&serverHello->secRenego, &buf[offset], bufLen - offset, &offset);
    PackHsExtArray8(&serverHello->pointFormats, &buf[offset], bufLen - offset, &offset);
    PackHsExtUint16(&serverHello->pskSelectedIdentity, &buf[offset], bufLen - offset, &offset);
    // encrypt then mac
    PackHsExtArray8(&serverHello->encryptThenMac, &buf[offset], bufLen - offset, &offset);

	if (serverHello->extensionLen.state == INITIAL_FIELD) {
        uint32_t extensionLen = offset - sizeof(uint16_t) - bufOffset;
        BSL_Uint16ToByte(extensionLen, &buf[bufOffset]);
    }
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackCertificateMsg(FRAME_Type *type, const FRAME_CertificateMsg *certificate, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    uint32_t bufOffset;

    if (type->versionType == HITLS_VERSION_TLS13) {
        PackInteger8(&certificate->certificateReqCtxSize, &buf[offset], bufLen - offset, &offset);
        PackArray8(&certificate->certificateReqCtx, &buf[offset], bufLen - offset, &offset);
    }
    bufOffset = offset;
    PackInteger24(&certificate->certsLen, &buf[offset], bufLen - offset, &offset);
    const FrameCertItem *next = certificate->certItem;
    while (next != NULL) {
        if (next->state == MISSING_FIELD) {
            break;
        }
        PackInteger24(&next->certLen, &buf[offset], bufLen - offset, &offset);
        PackArray8(&next->cert, &buf[offset], bufLen - offset, &offset);
        if (type->versionType == HITLS_VERSION_TLS13) {
            PackInteger16(&next->extensionLen, &buf[offset], bufLen - offset, &offset);
            PackArray8(&next->extension, &buf[offset], bufLen - offset, &offset);
        }
        next = next->next;
    }

    if (certificate->certsLen.state == INITIAL_FIELD) {
        uint32_t certsLen = offset - SIZE_OF_UINT24 - bufOffset;
        BSL_Uint24ToByte(certsLen, &buf[bufOffset]);
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackServerEcdheMsg(FRAME_Type *type, const FRAME_ServerKeyExchangeMsg *serverKeyExchange, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    // Fill in the following values in sequence: curve type, curve ID, pubkeylen, pubkey value, signature algorithm,
    // signature len, and signature value.
    PackInteger8(&serverKeyExchange->keyEx.ecdh.curveType, &buf[offset], bufLen, &offset);
    PackInteger16(&serverKeyExchange->keyEx.ecdh.namedcurve, &buf[offset], bufLen - offset, &offset);
    PackInteger8(&serverKeyExchange->keyEx.ecdh.pubKeySize, &buf[offset], bufLen- offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.ecdh.pubKey, &buf[offset], bufLen- offset, &offset);
    if (((IS_DTLS_VERSION(type->versionType)) && (type->versionType <= HITLS_VERSION_DTLS12)) ||
        ((!IS_DTLS_VERSION(type->versionType)) && (type->versionType >= HITLS_VERSION_TLS12))) {
        // DTLS1.2, TLS1.2, and later versions
        PackInteger16(&serverKeyExchange->keyEx.ecdh.signAlgorithm, &buf[offset], bufLen- offset, &offset);
    }

    PackInteger16(&serverKeyExchange->keyEx.ecdh.signSize, &buf[offset], bufLen- offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.ecdh.signData, &buf[offset], bufLen- offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackServerDheMsg(FRAME_Type *type, const FRAME_ServerKeyExchangeMsg *serverKeyExchange, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    // Fill in the following values in sequence: plen, p value, glen, g value, pubkeylen, pubkey value,
    // signature algorithm, signature len, and signature value.
    PackInteger16(&serverKeyExchange->keyEx.dh.plen, &buf[offset], bufLen, &offset);
    PackArray8(&serverKeyExchange->keyEx.dh.p, &buf[offset], bufLen - offset, &offset);
    PackInteger16(&serverKeyExchange->keyEx.dh.glen, &buf[offset], bufLen - offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.dh.g, &buf[offset], bufLen - offset, &offset);
    PackInteger16(&serverKeyExchange->keyEx.dh.pubKeyLen, &buf[offset], bufLen- offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.dh.pubKey, &buf[offset], bufLen- offset, &offset);
    if (((IS_DTLS_VERSION(type->versionType)) && (type->versionType <= HITLS_VERSION_DTLS12)) ||
        ((!IS_DTLS_VERSION(type->versionType)) && (type->versionType >= HITLS_VERSION_TLS12))) {
        // DTLS1.2, TLS1.2, and later versions
        PackInteger16(&serverKeyExchange->keyEx.dh.signAlgorithm, &buf[offset], bufLen- offset, &offset);
    }
    PackInteger16(&serverKeyExchange->keyEx.dh.signSize, &buf[offset], bufLen- offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.dh.signData, &buf[offset], bufLen- offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackServerEccMsg(const FRAME_ServerKeyExchangeMsg *serverKeyExchange, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    PackInteger16(&serverKeyExchange->keyEx.ecdh.signSize, &buf[offset], bufLen- offset, &offset);
    PackArray8(&serverKeyExchange->keyEx.ecdh.signData, &buf[offset], bufLen- offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackServerKeyExchangeMsg(FRAME_Type *type, const FRAME_ServerKeyExchangeMsg *serverKeyExchange,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    // Currently, ECDHE and DHE key exchange packets can be assembled.
    if (type->keyExType == HITLS_KEY_EXCH_ECDHE) {
        return PackServerEcdheMsg(type, serverKeyExchange, buf, bufLen, usedLen);
    } else if (type->keyExType == HITLS_KEY_EXCH_DHE) {
        return PackServerDheMsg(type, serverKeyExchange, buf, bufLen, usedLen);
    } else if (type->keyExType == HITLS_KEY_EXCH_ECC) {
        return PackServerEccMsg(serverKeyExchange, buf, bufLen, usedLen);
    }

    return HITLS_PACK_UNSUPPORT_KX_ALG;
}

static int32_t PackCertificateRequestExt(uint32_t type, const FRAME_CertificateRequestMsg *certificateRequest,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    FRAME_Integer exType;
    FRAME_Integer size;
    switch (type) {
        case HS_EX_TYPE_SIGNATURE_ALGORITHMS:
            exType.data = HS_EX_TYPE_SIGNATURE_ALGORITHMS;
            exType.state = INITIAL_FIELD;
            PackInteger16(&exType, &buf[offset], bufLen, &offset);
            size.data = certificateRequest->signatureAlgorithmsSize.data + sizeof(uint16_t);
            size.state = INITIAL_FIELD;
            PackInteger16(&size, &buf[offset], bufLen, &offset);

            PackInteger16(&certificateRequest->signatureAlgorithmsSize, &buf[offset], bufLen, &offset);
            PackArray16(&certificateRequest->signatureAlgorithms, &buf[offset], bufLen - offset, &offset);

            break;
        default:
            break;
    }

    *usedLen += offset;
    return HITLS_SUCCESS;
}

static int32_t PackCertificateRequestMsg(FRAME_Type *type, const FRAME_CertificateRequestMsg *certificateRequest,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    if (certificateRequest->state == MISSING_FIELD){
        return HITLS_SUCCESS;
    }
    if (type->versionType != HITLS_VERSION_TLS13) {
        PackInteger8(&certificateRequest->certTypesSize, &buf[offset], bufLen, &offset);
        PackArray8(&certificateRequest->certTypes, &buf[offset], bufLen - offset, &offset);
        PackInteger16(&certificateRequest->signatureAlgorithmsSize, &buf[offset], bufLen, &offset);
        PackArray16(&certificateRequest->signatureAlgorithms, &buf[offset], bufLen - offset, &offset);
        PackInteger16(&certificateRequest->distinguishedNamesSize, &buf[offset], bufLen, &offset);
        PackArray8(&certificateRequest->distinguishedNames, &buf[offset], bufLen - offset, &offset);
    } else {
        PackInteger8(&certificateRequest->certificateReqCtxSize, &buf[offset], bufLen, &offset);
        PackArray8(&certificateRequest->certificateReqCtx, &buf[offset], bufLen - offset, &offset);
        // Packaged extension
        uint32_t tmpOffset = offset;
        PackInteger16(&certificateRequest->exMsgLen, &buf[offset], bufLen, &offset);

        bool ifPackSign = (certificateRequest->signatureAlgorithmsSize.state != MISSING_FIELD);

        // Package HS_EX_TYPE_SIGNATURE_ALGORITHMS Extensions
        if(ifPackSign) {
            PackCertificateRequestExt(HS_EX_TYPE_SIGNATURE_ALGORITHMS, certificateRequest, &buf[offset],
                                        bufLen - offset, &offset);
        }
        if(certificateRequest->signatureAlgorithmsSize.state == DUPLICATE_FIELD) {
            PackCertificateRequestExt(HS_EX_TYPE_SIGNATURE_ALGORITHMS, certificateRequest, &buf[offset],
                                        bufLen - offset, &offset);
        }
        if (certificateRequest->exMsgLen.state == INITIAL_FIELD) {
            uint32_t len = offset - sizeof(uint16_t) - tmpOffset;
            BSL_Uint16ToByte(len, &buf[tmpOffset]);
        }
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackServerHelloDoneMsg(const FRAME_ServerHelloDoneMsg *serverHelloDone, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    /* The ServerHelloDone packet is an empty packet. Extra data is assembled here to construct abnormal packets. */
    PackArray8(&serverHelloDone->extra, &buf[offset], bufLen, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackClientEcdheMsg(FRAME_Type *type, const FRAME_ClientKeyExchangeMsg *clientKeyExchange, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    if (type->versionType == HITLS_VERSION_TLCP_DTLCP11) { /* Three bytes are added to the client key exchange. */
        buf[offset] = HITLS_EC_CURVE_TYPE_NAMED_CURVE;
        offset += sizeof(uint8_t);
        BSL_Uint16ToByte(HITLS_EC_GROUP_SM2, &buf[offset]);
        offset += sizeof(uint16_t);
    }
    PackInteger8(&clientKeyExchange->pubKeySize, &buf[offset], bufLen, &offset);
    PackArray8(&clientKeyExchange->pubKey, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackClientDheMsg(const FRAME_ClientKeyExchangeMsg *clientKeyExchange, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    PackInteger16(&clientKeyExchange->pubKeySize, &buf[offset], bufLen, &offset);
    PackArray8(&clientKeyExchange->pubKey, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackClientKeyExchangeMsg(FRAME_Type *type, const FRAME_ClientKeyExchangeMsg *clientKeyExchange,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    // Currently, ECDHE and DHE key exchange packets can be assembled.
    if (type->keyExType == HITLS_KEY_EXCH_ECDHE) {
        return PackClientEcdheMsg(type, clientKeyExchange, buf, bufLen, usedLen);
    } else if (type->keyExType == HITLS_KEY_EXCH_DHE || type->keyExType == HITLS_KEY_EXCH_RSA) {
        return PackClientDheMsg(clientKeyExchange, buf, bufLen, usedLen);
    }

    return HITLS_PACK_UNSUPPORT_KX_ALG;
}

static int32_t PackCertificateVerifyMsg(FRAME_Type *type, const FRAME_CertificateVerifyMsg *certificateVerify,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    if (((IS_DTLS_VERSION(type->versionType)) && (type->versionType <= HITLS_VERSION_DTLS12)) ||
        ((!IS_DTLS_VERSION(type->versionType)) && (type->versionType >= HITLS_VERSION_TLS12))) {
        // DTLS1.2, TLS1.2, and later versions
        PackInteger16(&certificateVerify->signHashAlg, &buf[offset], bufLen, &offset);
    }
    PackInteger16(&certificateVerify->signSize, &buf[offset], bufLen - offset, &offset);
    PackArray8(&certificateVerify->sign, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackFinishedMsg(const FRAME_FinishedMsg *finished, uint8_t *buf,
    uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    PackArray8(&finished->verifyData, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static void PackHsMsgHeader(uint16_t version, const FRAME_HsMsg *hsMsg, uint32_t bodyLen,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen, BSL_UIO_TransportType transportType)
{
    (void)version;
    uint32_t offset = 0;
    uint32_t bufOffset;

    PackInteger8(&hsMsg->type, &buf[offset], bufLen, &offset);

    bufOffset = offset;
    PackInteger24(&hsMsg->length, &buf[offset], bufLen - offset, &offset);
    if (IS_TRANSTYPE_DATAGRAM(transportType)) {
        PackInteger16(&hsMsg->sequence, &buf[offset], bufLen - offset, &offset);
        PackInteger24(&hsMsg->fragmentOffset, &buf[offset], bufLen - offset, &offset);
        if (hsMsg->fragmentLength.state == INITIAL_FIELD) {
            BSL_Uint24ToByte(bodyLen, &buf[offset]);
            offset += SIZE_OF_UINT24;
        } else {
            PackInteger24(&hsMsg->fragmentLength, &buf[offset], bufLen - offset, &offset);
        }
    }

    if (hsMsg->length.state == INITIAL_FIELD) {
        BSL_Uint24ToByte(bodyLen, &buf[bufOffset]);
    }

    *usedLen = offset;
}

static int32_t PackNewSessionTicketMsg(FRAME_Type *type, const FRAME_NewSessionTicketMsg *newSessionTicket,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;
    PackInteger32(&newSessionTicket->ticketLifetime, &buf[offset], bufLen - offset, &offset);
    if (type->versionType != HITLS_VERSION_TLS13) {
        PackInteger16(&newSessionTicket->ticketSize, &buf[offset], bufLen - offset, &offset);
        PackArray8(&newSessionTicket->ticket, &buf[offset], bufLen - offset, &offset);
    } else {
        PackInteger32(&newSessionTicket->ticketAgeAdd, &buf[offset], bufLen - offset, &offset);
        PackInteger8(&newSessionTicket->ticketNonceSize, &buf[offset], bufLen - offset, &offset);
        PackArray8(&newSessionTicket->ticketNonce, &buf[offset], bufLen - offset, &offset);
        PackInteger16(&newSessionTicket->ticketSize, &buf[offset], bufLen - offset, &offset);
        PackArray8(&newSessionTicket->ticket, &buf[offset], bufLen - offset, &offset);
        PackInteger16(&newSessionTicket->extensionLen, &buf[offset], bufLen - offset, &offset);
    }
    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackHsMsgBody(FRAME_Type *type, const FRAME_Msg *msg,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    const FRAME_HsMsg *hsMsg = &(msg->body.hsMsg);

    switch (type->handshakeType) {
        case CLIENT_HELLO:
            return PackClientHelloMsg(&(hsMsg->body.clientHello), buf, bufLen, usedLen);
        case SERVER_HELLO:
            return PackServerHelloMsg(&(hsMsg->body.serverHello), buf, bufLen, usedLen);
        case CERTIFICATE:
            return PackCertificateMsg(type, &(hsMsg->body.certificate), buf, bufLen, usedLen);
        case SERVER_KEY_EXCHANGE:
            return PackServerKeyExchangeMsg(type, &(hsMsg->body.serverKeyExchange), buf, bufLen, usedLen);
        case CERTIFICATE_REQUEST:
            return PackCertificateRequestMsg(type, &(hsMsg->body.certificateReq), buf, bufLen, usedLen);
        case SERVER_HELLO_DONE:
            return PackServerHelloDoneMsg(&(hsMsg->body.serverHelloDone), buf, bufLen, usedLen);
        case CLIENT_KEY_EXCHANGE:
            return PackClientKeyExchangeMsg(type, &(hsMsg->body.clientKeyExchange), buf, bufLen, usedLen);
        case CERTIFICATE_VERIFY:
            return PackCertificateVerifyMsg(type, &(hsMsg->body.certificateVerify), buf, bufLen, usedLen);
        case FINISHED:
            return PackFinishedMsg(&(hsMsg->body.finished), buf, bufLen, usedLen);
        case NEW_SESSION_TICKET:
            return PackNewSessionTicketMsg(type, &(hsMsg->body.newSessionTicket), buf, bufLen, usedLen);
        default:
            return HITLS_PACK_UNSUPPORT_HANDSHAKE_MSG;
    }
}

static int32_t PackHandShakeMsg(FRAME_Type *type, const FRAME_Msg *msg,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    const FRAME_HsMsg *hsMsg = &(msg->body.hsMsg);
    uint32_t ret;
    uint32_t offset;
    uint32_t bodyMaxLen;
    uint32_t headerLen;
    uint32_t bodyLen = 0;

    if (IS_TRANSTYPE_DATAGRAM(type->transportType)) { // DTLS
        if (bufLen < DTLS_HS_MSG_HEADER_SIZE) {
            return HITLS_INTERNAL_EXCEPTION;
        }

        bodyMaxLen = bufLen - DTLS_HS_MSG_HEADER_SIZE;
        offset = DTLS_HS_MSG_HEADER_SIZE;
        headerLen = DTLS_HS_MSG_HEADER_SIZE;
    } else {                                      // TLS
        if (bufLen < HS_MSG_HEADER_SIZE) {
            return HITLS_INTERNAL_EXCEPTION;
        }

        bodyMaxLen = bufLen - HS_MSG_HEADER_SIZE;
        offset = HS_MSG_HEADER_SIZE;
        headerLen = HS_MSG_HEADER_SIZE;
    }

    // Assemble the body of the handshake message.
    ret = PackHsMsgBody(type, msg, &buf[offset], bodyMaxLen, &bodyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    // Assemble the handshake packet header.
    PackHsMsgHeader(type->versionType, hsMsg, bodyLen, buf, headerLen, &headerLen, type->transportType);

    // Splicing body and head
    // If some fields are missing in the header, the packet body is filled with an offset forward.
    if (headerLen != offset) {
        ret = memmove_s(&buf[headerLen], bufLen - headerLen, &buf[offset], bodyLen);
        if (ret != EOK) {
            return ret;
        }
    }
    *usedLen = headerLen + bodyLen;
    return ret;
}

static int32_t PackCcsMsg(const FRAME_Msg *msg, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    PackInteger8(&msg->body.ccsMsg.ccsType, &buf[offset], bufLen, &offset);
    /* Extra data is used to construct abnormal packets. */
    PackArray8(&msg->body.ccsMsg.extra, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackAlertMsg(const FRAME_Msg *msg, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    PackInteger8(&msg->body.alertMsg.alertLevel, &buf[offset], bufLen, &offset);
    PackInteger8(&msg->body.alertMsg.alertDescription, &buf[offset], bufLen - offset, &offset);
    /* Extra data is used to construct abnormal packets. */
    PackArray8(&msg->body.alertMsg.extra, &buf[offset], bufLen - offset, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackAppMsg(const FRAME_Msg *msg, uint8_t *buf, uint32_t bufLen, uint32_t *usedLen)
{
    uint32_t offset = 0;

    PackArray8(&msg->body.appMsg.appData, &buf[offset], bufLen, &offset);

    *usedLen = offset;
    return HITLS_SUCCESS;
}

static int32_t PackRecordHeader(uint16_t version, const FRAME_Msg *msg, uint32_t bodyLen,
    uint8_t *buf, uint32_t bufLen, uint32_t *usedLen, BSL_UIO_TransportType transportType)
{
    (void)version;
    uint32_t offset = 0;

    PackInteger8(&msg->recType, &buf[offset], bufLen, &offset);
    PackInteger16(&msg->recVersion, &buf[offset], bufLen - offset, &offset);
    if (IS_TRANSTYPE_DATAGRAM(transportType)) {
        PackInteger16(&msg->epoch, &buf[offset], bufLen - offset, &offset);
        PackInteger48(&msg->sequence, &buf[offset], bufLen - offset, &offset);
    }

    if (msg->length.state == INITIAL_FIELD) {
        BSL_Uint16ToByte(bodyLen, &buf[offset]);
        offset += sizeof(uint16_t);
    } else {
        PackInteger16(&msg->length, &buf[offset], bufLen - offset, &offset);
    }

    *usedLen = offset;
    return HITLS_SUCCESS;
}

int32_t FRAME_PackRecordBody(FRAME_Type *frameType, const FRAME_Msg *msg,
    uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret;

    // pack Body
    switch (frameType->recordType) {
        case REC_TYPE_HANDSHAKE:
            ret = PackHandShakeMsg(frameType, msg, buffer, bufLen, usedLen);
            break;
        case REC_TYPE_CHANGE_CIPHER_SPEC:
            ret = PackCcsMsg(msg, buffer, bufLen, usedLen);
            break;
        case REC_TYPE_ALERT:
            ret = PackAlertMsg(msg, buffer, bufLen, usedLen);
            break;
        case REC_TYPE_APP:
            ret = PackAppMsg(msg, buffer, bufLen, usedLen);
            break;
        default:
            ret = HITLS_INTERNAL_EXCEPTION;
            break;
    }

    return ret;
}

int32_t FRAME_PackMsg(FRAME_Type *frameType, const FRAME_Msg *msg, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen)
{
    int32_t ret;
    uint32_t offset;
    uint32_t bodyMaxLen;
    uint32_t headerLen;
    uint32_t bodyLen = 0;

    if (msg == NULL || buffer == NULL || usedLen == NULL) {
        return HITLS_INTERNAL_EXCEPTION;
    }

    if (IS_TRANSTYPE_DATAGRAM(frameType->transportType)) { // DTLS
        if (bufLen < DTLS_RECORD_HEADER_LEN) {
            return HITLS_INTERNAL_EXCEPTION;
        }

        bodyMaxLen = bufLen - DTLS_RECORD_HEADER_LEN;
        offset = DTLS_RECORD_HEADER_LEN;
        headerLen = DTLS_RECORD_HEADER_LEN;
    } else {                                      // TLS
        if (bufLen < TLS_RECORD_HEADER_LEN) {
            return HITLS_INTERNAL_EXCEPTION;
        }

        bodyMaxLen = bufLen - TLS_RECORD_HEADER_LEN;
        offset = TLS_RECORD_HEADER_LEN;
        headerLen = TLS_RECORD_HEADER_LEN;
    }

    // Assemble the message body.
    ret = FRAME_PackRecordBody(frameType, msg, &buffer[offset], bodyMaxLen, &bodyLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    // Assemble the packet header.
    PackRecordHeader(frameType->versionType, msg, bodyLen, buffer, headerLen, &headerLen, frameType->transportType);

    // Splicing body and head
    // If some fields are missing in the header, the packet body is filled with an offset forward.
    if (headerLen != offset) {
        ret = memmove_s(&buffer[headerLen], bufLen - headerLen, &buffer[offset], bodyLen);
        if (ret != EOK) {
            return ret;
        }
    }
    *usedLen = headerLen + bodyLen;
    return ret;
}

int32_t FRAME_GetTls13DisorderHsMsg(HS_MsgType type, uint8_t *buffer, uint32_t bufLen, uint32_t *usedLen)
{
    if (bufLen < 5) {
        return HITLS_INTERNAL_EXCEPTION;
    }
    buffer[0] = type;
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 1;
    buffer[4] = 0;
    *usedLen = 5;
    return HITLS_SUCCESS;
}