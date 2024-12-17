#ifndef E2EE_KEY_EXCH_MSG_H
#define E2EE_KEY_EXCH_MSG_H

typedef struct {
    uint8_t *data;
    uint32_t len;
} E2EE_Data;

typedef enum {
    E2EE_MSG_C2S_KEY_EXCH_TYPE = 0x01,
    E2EE_MSG_S2C_KEY_EXCH_TYPE = 0x02,
    E2EE_MSG_APP_DATA_TYPE = 0x03
} E2EE_MsgType;

typedef enum {
    E2EE_MSG_CIPHER_CUITE_TAG = 0x01,
    E2EE_MSG_ENCAPSULATED_KEY_TAG = 0x02,
    E2EE_MSG_PUBKEY_ID_TAG = 0x03,
    E2EE_MSG_RESPONSE_NONCE_TAG = 0x04,
    E2EE_MSG_CIPHER_TEXT_TAG = 0x05
} E2EE_MsgTag;

#define E2EE_RESPONSE_NONCE_LEN 32

#define E2EE_MSG_VERSION 1
#define E2EE_MSG_C2S_KEY_EXCH_TLV_NUM 4 // cipherSuite, encapsulatedKey, cipherText
#define E2EE_MSG_S2C_KEY_EXCH_TLV_NUM 2 // responseNonce, cipherText
#define E2EE_MSG_APP_DATA_TLV_NUM 1 // cipherText

#define E2EE_MSG_PUBKEY_ID_SIZE 32

// 1MB of space is reserved for storing the ciphertext header and TLV information
#define E2EE_MAX_PLIANTEXT_LEN 0xFFEFFFFF

int32_t ParseAppDataMsg(uint8_t *cipherText, uint32_t cipherTextLen, uint8_t **realCipherText,
    uint32_t *realCipherTextLen);

typedef struct {
    uint8_t tag;
    uint32_t len;
    uint8_t *value;
} E2EE_Tlv;

uint64_t E2EE_GetTagValueOffset(uint8_t version, E2EE_Tlv tlvs[], uint32_t tlvNum, uint8_t tag);

int32_t E2EE_SerializeMsg(uint8_t version, uint8_t type, E2EE_Tlv tlvs[], uint32_t tlvNum, uint8_t *out,
    uint32_t *outLen);

int32_t E2EE_CheckMsgBaseInfo(uint8_t *in, uint32_t inLen, uint8_t version, uint8_t type);

int32_t E2EE_DeserializeMsg(uint8_t *in, uint32_t inLen, E2EE_Tlv tlvs[], uint32_t *tlvNum);

#endif