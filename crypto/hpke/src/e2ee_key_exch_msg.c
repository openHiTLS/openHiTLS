
#include <stdint.h>
#include <stddef.h>
#include "securec.h"
#include "e2ee_key_exch_err.h"
#include "e2ee_key_exch_msg.h"


// TLS big-endian
#define E2EE_MSG_VERSION_SIZE 1    //uint8_t
#define E2EE_MSG_TYPE_SIZE 1       //uint8_t
#define E2EE_MSG_TOTAL_LEN_SIZE 8  //uint64_t

#define E2EE_MSG_HEADER_SIZE 10    // E2EE_MSG_VERSION_SIZE + E2EE_MSG_TYPE_SIZE + E2EE_MSG_TOTAL_LEN_SIZE

#define E2EE_MSG_TLV_TAG_SIZE 1    // uint8_t
#define E2EE_MSG_TLV_LEN_SIZE 4    // uint32_t

#define E2EE_MSG_MAX_BODY_SIZE 0xFFFFFFF5

static inline uint32_t Uint32ToBigEndian(uint32_t value) // 大部分是小端机器，可以考虑使用小端序？
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    uint8_t *data = (uint8_t *)&value;
    if (p[0] == 0x13) { // little-endian
        return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | ((uint32_t)data[3]);
    } else {
        return value;
    }
}

static inline uint64_t Uint64ToBigEndian(uint64_t value) // 大部分是小端机器，可以考虑使用小端序？
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    uint32_t *data = (uint32_t *)&value;
    if (p[0] == 0x13) { // little-endian
        return (uint64_t)Uint32ToBigEndian(data[0]) << 32 | (uint64_t)Uint32ToBigEndian(data[1]);
    } else {
        return value;
    }
}

static inline uint64_t BigEndianToUint64(uint64_t value)
{
    return Uint64ToBigEndian(value);
}

int32_t E2EE_SerializeMsg(uint8_t version, uint8_t type, E2EE_Tlv tlvs[], uint32_t tlvNum, uint8_t *out,
    uint32_t *outLen)
{
    uint64_t totalLen = E2EE_MSG_HEADER_SIZE;
    uint32_t i;
    for (i = 0; i < tlvNum; i++) {
        totalLen += tlvs[i].len;
    }

    totalLen += (tlvNum * (E2EE_MSG_TLV_TAG_SIZE + E2EE_MSG_TLV_LEN_SIZE));

    if (out == NULL) {
        *outLen = totalLen;
        return E2EE_SUCCESS;
    }

    if (*outLen < totalLen) {
        return E2EE_ERR_NVALID_ARG;
    }

    uint8_t *p = out;
    *p = version;
    p += E2EE_MSG_VERSION_SIZE;
    *p = type;
    p += E2EE_MSG_TYPE_SIZE;
    *(uint64_t *)p = Uint64ToBigEndian(totalLen - E2EE_MSG_HEADER_SIZE);
    p += E2EE_MSG_TOTAL_LEN_SIZE;

    for (i = 0; i < tlvNum; i++) {
        *p = tlvs[i].tag;
        p += E2EE_MSG_TLV_TAG_SIZE;
        *(uint32_t *)p = Uint32ToBigEndian(tlvs[i].len);
        p += E2EE_MSG_TLV_LEN_SIZE;

        if (p != tlvs[i].value) {
            (void)memcpy_s(p, tlvs[i].len, tlvs[i].value, tlvs[i].len);
        }
        p += tlvs[i].len;
    }
    return E2EE_SUCCESS;
}

uint64_t E2EE_GetTagValueOffset(uint8_t version, E2EE_Tlv tlvs[], uint32_t tlvNum, uint8_t tag)
{
    (void)version;
    uint64_t len = E2EE_MSG_HEADER_SIZE;
    uint32_t i;
    for (i = 0; i < tlvNum; i++) {
        len += (E2EE_MSG_TLV_TAG_SIZE + E2EE_MSG_TLV_LEN_SIZE);
        if (tlvs[i].tag == tag) {
            break;
        }
        len += tlvs[i].len;
    }
    return len;
}

int32_t E2EE_CheckMsgBaseInfo(uint8_t *in, uint32_t inLen, uint8_t version, uint8_t type)
{
    if (inLen < E2EE_MSG_HEADER_SIZE) {
        return E2EE_ERR_MSG_LEN;
    }
    if (in[0] != version) {
        return E2EE_ERR_MSG_VERSION;
    }
    if (in[E2EE_MSG_VERSION_SIZE] != type) {
        return E2EE_ERR_MSG_TYPE;
    }
    return E2EE_SUCCESS;
}

int32_t E2EE_DeserializeMsg(uint8_t *in, uint32_t inLen, E2EE_Tlv tlvs[], uint32_t *tlvNum)
{
    if (inLen < E2EE_MSG_HEADER_SIZE) {
        return E2EE_ERR_MSG_LEN;
    }

    uint8_t *p = in;
    p += (E2EE_MSG_VERSION_SIZE + E2EE_MSG_TYPE_SIZE);
    uint64_t bodyLen = Uint64ToBigEndian(*(uint64_t *)p);
    p += E2EE_MSG_TOTAL_LEN_SIZE;
    
    if (bodyLen > E2EE_MSG_MAX_BODY_SIZE) {
        return E2EE_ERR_MSG_LEN;
    }

    if ((bodyLen + E2EE_MSG_HEADER_SIZE) != inLen) {
        return E2EE_ERR_MSG_LEN;
    }

    uint8_t tag;
    uint32_t len;
    uint32_t i = 0;
    while (bodyLen > 0) {
        if (bodyLen < (E2EE_MSG_TLV_TAG_SIZE + E2EE_MSG_TLV_LEN_SIZE)) {
            return E2EE_ERR_MSG_LEN;
        }

        tag = *p;
        p += E2EE_MSG_TLV_TAG_SIZE;
        len = Uint32ToBigEndian(*(uint32_t *)p);
        p += E2EE_MSG_TLV_LEN_SIZE;
        bodyLen -= (E2EE_MSG_TLV_LEN_SIZE + E2EE_MSG_TLV_TAG_SIZE);
        if (len > bodyLen) {
            return E2EE_ERR_MSG_LEN;
        }

        tlvs[i].tag = tag;
        tlvs[i].len = len;
        tlvs[i].value = p;
        i++;

        p += len;
        bodyLen -= len;

        if (i >= *tlvNum) {
            break;
        }
    }

    if (bodyLen != 0) {
        return E2EE_ERR_MSG_LEN;
    }

    *tlvNum = i;
    return E2EE_SUCCESS;
}

int32_t ParseAppDataMsg(uint8_t *cipherText, uint32_t cipherTextLen, uint8_t **realCipherText,
    uint32_t *realCipherTextLen)
{
    uint32_t ret = E2EE_CheckMsgBaseInfo(cipherText, cipherTextLen, E2EE_MSG_VERSION, E2EE_MSG_APP_DATA_TYPE);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    E2EE_Tlv tlvs[E2EE_MSG_APP_DATA_TLV_NUM] = {0};
    uint32_t tlvsLen = E2EE_MSG_APP_DATA_TLV_NUM;
    ret = E2EE_DeserializeMsg(cipherText, cipherTextLen, tlvs, &tlvsLen);
    if (ret != E2EE_SUCCESS) {
        return ret;
    }

    if (tlvsLen != E2EE_MSG_APP_DATA_TLV_NUM) {
        return E2EE_ERR_MSG_LEN;
    }

    if (tlvs[0].tag == E2EE_MSG_CIPHER_TEXT_TAG) {
        *realCipherText = tlvs[0].value;
        *realCipherTextLen = tlvs[0].len;
        return E2EE_SUCCESS;
    }
    return E2EE_ERR_INVALID_MSG;
}
