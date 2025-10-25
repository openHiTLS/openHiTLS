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
#include "hitls_build.h"
#ifdef HITLS_TLS_FEATURE_SESSION_TICKET
#include <stdbool.h>
#include <string.h>
#include "securec.h"
#include "tlv.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_bytes.h"
#include "bsl_sal.h"
#include "crypt.h"
#include "hitls_error.h"
#include "session_type.h"
#include "session_enc.h"

typedef struct {
    uint8_t keyName[HITLS_TICKET_KEY_NAME_SIZE];
    uint8_t iv[HITLS_TICKET_IV_SIZE];
    uint32_t encryptedStateSize;
    uint8_t *encryptedState;
    uint8_t mac[HITLS_TICKET_KEY_SIZE];
} Ticket;

#define DEFAULT_SESSION_ENCRYPT_TYPE HITLS_AEAD_CIPHER
#define DEFAULT_SESSION_ENCRYPT_ALGO HITLS_CIPHER_AES_256_GCM
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
#define AES_CBC_BLOCK_LEN 16u
#endif

static void SetCipherInfo(const TLS_SessionMgr *sessMgr, Ticket *ticket, HITLS_CipherParameters *cipher)
{
    cipher->type = DEFAULT_SESSION_ENCRYPT_TYPE;
    cipher->algo = DEFAULT_SESSION_ENCRYPT_ALGO;
    cipher->key = sessMgr->ticketAesKey;
    cipher->keyLen = HITLS_TICKET_KEY_SIZE;
    cipher->iv = ticket->iv;
    cipher->ivLen = HITLS_TICKET_IV_SIZE;
    cipher->aad = ticket->iv;
    cipher->aadLen = HITLS_TICKET_IV_SIZE;
    return;
}

static int32_t GetSessEncryptInfo(TLS_Ctx *ctx, const TLS_SessionMgr *sessMgr, Ticket *ticket, HITLS_CipherParameters *cipher)
{
    int32_t ret;
#ifdef HITLS_TLS_FEATURE_SESSION
    HITLS_TicketKeyCb cb = sessMgr->ticketKeyCb;
    if (cb != NULL) {
        ret = cb(ticket->keyName, HITLS_TICKET_KEY_NAME_SIZE, cipher, true);
        if (memcpy_s(ticket->iv, HITLS_TICKET_IV_SIZE, cipher->iv, cipher->ivLen) != EOK) {
            BSL_ERR_PUSH_ERROR(HITLS_TICKET_KEY_RET_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16069, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "iv copy fail when GetSessEncryptInfo.", 0, 0, 0, 0);
            return HITLS_TICKET_KEY_RET_FAIL;
        }
        return ret;
    }
#endif
    /* The user does not register the callback. The default ticket key is used. */
    (void)memcpy_s(ticket->keyName, HITLS_TICKET_KEY_NAME_SIZE, sessMgr->ticketKeyName, HITLS_TICKET_KEY_NAME_SIZE);

    ret = SAL_CRYPT_Rand(LIBCTX_FROM_CTX(ctx), ticket->iv, HITLS_TICKET_IV_SIZE);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(HITLS_TICKET_KEY_RET_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16021, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Rand fail", 0, 0, 0, 0);
        return HITLS_TICKET_KEY_RET_FAIL;
    }

    SetCipherInfo(sessMgr, ticket, cipher);

    return HITLS_TICKET_KEY_RET_SUCCESS;
}

static int32_t PackKeyNameAndIv(const Ticket *ticket, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    uint32_t offset = 0;
    if (memcpy_s(&data[0], len, ticket->keyName, HITLS_TICKET_KEY_NAME_SIZE) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16022, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy keyName fail when encrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HITLS_TICKET_KEY_NAME_SIZE;

    if (memcpy_s(&data[offset], len - offset, ticket->iv, HITLS_TICKET_IV_SIZE) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16023, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy iv fail when encrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    offset += HITLS_TICKET_IV_SIZE;

    *usedLen = offset;
    return HITLS_SUCCESS;
}
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
static uint32_t GetCbcPendingLen(uint32_t encodeLen, uint8_t *paddingLen)
{
    *paddingLen = (encodeLen + sizeof(uint8_t)) % AES_CBC_BLOCK_LEN;
    if (*paddingLen != 0) {
        *paddingLen = AES_CBC_BLOCK_LEN - *paddingLen;
    }
    return *paddingLen + sizeof(uint8_t);
}
#endif
static int32_t PackEncryptTicket(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const HITLS_Session *sess, HITLS_CipherParameters *cipher, uint8_t *data, uint32_t len, uint32_t *usedLen)
{
    int32_t ret = 0;
    /* Encode the session. */
    uint32_t encodeLen = SESS_GetTotalEncodeSize(sess);
    uint32_t plaintextLen = encodeLen;
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    uint8_t paddingLen = 0;
    if (cipher->type == HITLS_CBC_CIPHER) {
        /* In CBC mode, the padding needs to be calculated. */
        /* Plain text length plus padding length */
        plaintextLen += GetCbcPendingLen(encodeLen, &paddingLen);
    }
#endif

    uint8_t *plaintext = BSL_SAL_Calloc(1u, plaintextLen);
    if (plaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16024, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encData malloc fail when encrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    ret = SESS_Encode(sess, plaintext, plaintextLen, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_CleanseData(plaintext, plaintextLen);
        BSL_SAL_FREE(plaintext);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16025, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Encode fail when encrypt session ticket.", 0, 0, 0, 0);
        return ret;
    }

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    /* Padding is required in CBC mode. */
    if (cipher->type == HITLS_CBC_CIPHER) {
        /* The last byte is the padding length field, and the padding content is the length value. */
        uint32_t count = paddingLen + sizeof(uint8_t);
        /* The calculation is accurate when the memory is applied for the plaintext. Therefore, the
         * return value does not need to be checked. */
        (void)memset_s(&plaintext[encodeLen], count, paddingLen, count);
        plaintextLen += count;
    }
#endif
    uint32_t offset = 0;
    /* reserved length field */
    offset += sizeof(uint32_t);
    /* Encrypt and fill the ticket. */
    uint32_t encryptLen = len - offset;
    ret = SAL_CRYPT_Encrypt(libCtx, attrName, cipher, plaintext, plaintextLen, &data[offset], &encryptLen);
    BSL_SAL_CleanseData(plaintext, plaintextLen);
    BSL_SAL_FREE(plaintext);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16026, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_Encrypt fail when encrypt session ticket.", 0, 0, 0, 0);
        return ret;
    }
    /* padding length */
    BSL_Uint32ToByte(encryptLen, &data[offset - sizeof(uint32_t)]);
    offset += encryptLen;

    *usedLen = offset;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
static int32_t PackTicketHmac(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CipherParameters *cipher, uint8_t *data, uint32_t len, uint32_t offset,
    uint32_t *usedLen)
{
    /* The HMAC field is filled only in CBC mode. In other modes, the HMAC field is returned. */
    if (cipher->type != HITLS_CBC_CIPHER) {
        *usedLen = 0;
        return HITLS_SUCCESS;
    }

    int32_t ret;
    uint8_t mac[HITLS_TICKET_KEY_SIZE] = {0};
    uint32_t macLen = HITLS_TICKET_KEY_SIZE;
    ret = SAL_CRYPT_Hmac(libCtx, attrName,
        HITLS_HASH_SHA_256, cipher->hmacKey, cipher->hmacKeyLen, data, offset, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16027, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TicketHmac fail when encrypt session ticket.", 0, 0, 0, 0);
        return ret;
    }
    if (memcpy_s(&data[offset], len - offset, mac, macLen) != EOK) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMCPY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16028, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "copy mac fail when encrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMCPY_FAIL;
    }
    *usedLen = macLen;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_CIPHER_CBC */

static uint8_t *NewTicketBuf(const HITLS_Session *sess, HITLS_CipherParameters *cipher, uint32_t *ticketBufSize)
{
    (void)cipher;
    uint32_t encodeLen = SESS_GetTotalEncodeSize(sess);
    uint32_t plaintextLen = encodeLen;
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    if (cipher->type == HITLS_CBC_CIPHER) {
        /* In CBC mode, the padding needs to be calculated. */
        uint8_t paddingLen = (encodeLen + sizeof(uint8_t)) % AES_CBC_BLOCK_LEN;
        if (paddingLen != 0) {
            paddingLen = AES_CBC_BLOCK_LEN - paddingLen;
        }
        /* Plain text length plus padding length */
        plaintextLen += paddingLen + sizeof(uint8_t);
    }
#endif
    /* Plain text length plus key name, iv, encrypted data length, and MAC length. */
    plaintextLen += HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_IV_SIZE + sizeof(uint32_t) + HITLS_TICKET_KEY_SIZE;

    uint8_t *ticketBuf = BSL_SAL_Calloc(1u, plaintextLen);
    if (ticketBuf == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16029, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ticketBuf malloc fail when encrypt session ticket.", 0, 0, 0, 0);
        return NULL;
    }

    *ticketBufSize = plaintextLen;
    return ticketBuf;
}

int32_t SESSMGR_EncryptSessionTicket(TLS_Ctx *ctx,
    const TLS_SessionMgr *sessMgr, const HITLS_Session *sess, uint8_t **ticketBuf, uint32_t *ticketBufSize)
{
    if (sessMgr == NULL || sess == NULL || ticketBuf == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_INTERNAL_EXCEPTION, BINLOG_ID16713, "input null");
    }

    Ticket ticket = {0};
    HITLS_CipherParameters cipher = {0};
    int32_t retVal = GetSessEncryptInfo(ctx, sessMgr, &ticket, &cipher);
    if (retVal < 0) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_TICKET_KEY_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_SESS_ERR_SESSION_TICKET_KEY_FAIL, BINLOG_ID16030,
            "GetSessEncryptInfo fail");
    }
    if (retVal == HITLS_TICKET_KEY_RET_FAIL) {
        /* Failed to obtain the encryption information. An empty ticket is returned. */
        *ticketBufSize = 0;
        return HITLS_SUCCESS;
    }

    uint32_t dataLen = 0;
    uint8_t *data = NewTicketBuf(sess, &cipher, &dataLen);
    if (data == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    /* Fill in the key name and iv. */
    uint32_t packLen = 0;
    uint32_t offset = 0;
    int32_t ret = PackKeyNameAndIv(&ticket, &data[0], dataLen, &packLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        return ret;
    }
    offset += packLen;
    /* Encrypt and fill the ticket. */
    ret = PackEncryptTicket(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        sess, &cipher, &data[offset], dataLen - offset, &packLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        return ret;
    }
    offset += packLen;

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    /* fill HMAC */
    ret = PackTicketHmac(LIBCTX_FROM_CTX(ctx), ATTRIBUTE_FROM_CTX(ctx),
        &cipher, data, dataLen, offset, &packLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        return ret;
    }
    offset += packLen;
#endif
    *ticketBufSize = offset;
    *ticketBuf = data;
    return HITLS_SUCCESS;
}
static int32_t ParseSessionTicket(Ticket *ticket, const uint8_t *ticketBuf, uint32_t ticketBufSize)
{
    uint32_t offset = 0;
    if (ticketBufSize < HITLS_TICKET_KEY_NAME_SIZE + HITLS_TICKET_IV_SIZE + sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16044, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ticketBufSize is incorrect when parse session ticket.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT;
    }

    (void)memcpy_s(ticket->keyName, HITLS_TICKET_KEY_NAME_SIZE, ticketBuf, HITLS_TICKET_KEY_NAME_SIZE);
    offset += HITLS_TICKET_KEY_NAME_SIZE;

    (void)memcpy_s(ticket->iv, HITLS_TICKET_IV_SIZE, &ticketBuf[offset], HITLS_TICKET_IV_SIZE);
    offset += HITLS_TICKET_IV_SIZE;

    ticket->encryptedStateSize = BSL_ByteToUint32(&ticketBuf[offset]);
    offset += sizeof(uint32_t);

    if ((ticketBufSize - offset) < ticket->encryptedStateSize) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16032, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ticketBufSize is incorrect when parse session ticket encryptedStateSize.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT;
    }

    ticket->encryptedState = (uint8_t *)(uintptr_t)&ticketBuf[offset];
    offset += ticket->encryptedStateSize;

    if (ticketBufSize != offset) {
        if ((ticketBufSize - offset) != HITLS_TICKET_KEY_SIZE) {
            BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16033, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "ticketBufSize is incorrect when parse session ticket hmac.", 0, 0, 0, 0);
            return HITLS_SESS_ERR_SESSION_TICKET_SIZE_INCORRECT;
        }
        (void)memcpy_s(ticket->mac, HITLS_TICKET_KEY_SIZE, &ticketBuf[offset], HITLS_TICKET_KEY_SIZE);
    }

    return HITLS_SUCCESS;
}

static int32_t GetSessDecryptInfo(const TLS_SessionMgr *sessMgr, Ticket *ticket, HITLS_CipherParameters *cipher)
{
#ifdef HITLS_TLS_FEATURE_SESSION
    HITLS_TicketKeyCb cb = sessMgr->ticketKeyCb;
    if (cb != NULL) {
        return cb(ticket->keyName, HITLS_TICKET_KEY_NAME_SIZE, cipher, false);
    }
#endif
    /* The user does not register the callback. Use the default ticket key. */
    if (memcmp(ticket->keyName, sessMgr->ticketKeyName, HITLS_TICKET_KEY_NAME_SIZE) != 0) {
        /* Failed to match the key name. */
        return HITLS_TICKET_KEY_RET_FAIL;
    }
    SetCipherInfo(sessMgr, ticket, cipher);
    return HITLS_TICKET_KEY_RET_SUCCESS;
}

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
static int32_t CheckTicketHmac(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CipherParameters *cipher, Ticket *ticket, const uint8_t *data, uint32_t len, bool *isPass)
{
    /* The HMAC check is required only in CBC mode. In other modes, the HMAC check is returned. */
    if (cipher->type != HITLS_CBC_CIPHER) {
        *isPass = true;
        return HITLS_SUCCESS;
    }

    int32_t ret;
    uint8_t mac[HITLS_TICKET_KEY_SIZE] = {0};
    uint32_t macLen = HITLS_TICKET_KEY_SIZE;
    ret = SAL_CRYPT_Hmac(libCtx, attrName,
        HITLS_HASH_SHA_256, cipher->hmacKey, cipher->hmacKeyLen, data, len - HITLS_TICKET_KEY_SIZE, mac, &macLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16035, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "TicketHmac fail when decrypt session ticket.", 0, 0, 0, 0);
        return ret;
    }

    if (memcmp(ticket->mac, mac, macLen) != 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16036, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "compare mac fail when decrypt session ticket.", 0, 0, 0, 0);
        /* The HMAC check fails, but the complete link establishment can be continued. Therefore, HITLS_SUCCESS is
         * returned. */
        *isPass = false;
        return HITLS_SUCCESS;
    }
    *isPass = true;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_SUITE_CIPHER_CBC */

static int32_t GenerateSessFromTicket(HITLS_Lib_Ctx *libCtx, const char *attrName,
    HITLS_CipherParameters *cipher, Ticket *ticket, uint32_t ticketBufSize, HITLS_Session **sess)
{
    /* Decrypt the ticket. */
    uint32_t plaintextLen = ticketBufSize;
    uint8_t *plaintext = BSL_SAL_Calloc(1u, ticketBufSize);
    if (plaintext == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16037, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "plaintext malloc fail when decrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    int32_t ret = SAL_CRYPT_Decrypt(libCtx, attrName,
        cipher, ticket->encryptedState, ticket->encryptedStateSize, plaintext, &plaintextLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(plaintext);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16038, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "SAL_CRYPT_Decrypt fail when decrypt session ticket.", 0, 0, 0, 0);
        /* The ticket fails to be decrypted, but the complete connection can be established. Therefore, HITLS_SUCCESS is
         * returned. */
        return HITLS_SUCCESS;
    }

#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    /* Padding needs to be verified in CBC mode. */
    if (cipher->type == HITLS_CBC_CIPHER) {
        /* The last byte is the padding length field, and the padding content is the length value. */
        uint8_t paddingLen = plaintext[plaintextLen - 1];
        for (uint32_t i = 1; i <= paddingLen; i++) {
            if (plaintext[plaintextLen - 1 - i] != paddingLen) {
                BSL_SAL_FREE(plaintext);
                return HITLS_SUCCESS;
            }
        }
        plaintextLen -= paddingLen + sizeof(uint8_t);
    }
#endif

    /* Parse the ticket content to the SESS. */
    HITLS_Session *session = HITLS_SESS_New();
    if (session == NULL) {
        BSL_SAL_FREE(plaintext);
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16039, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "HITLS_SESS_New fail when decrypt session ticket.", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    ret = SESS_Decode(session, plaintext, plaintextLen);
    BSL_SAL_FREE(plaintext);
    if (ret != HITLS_SUCCESS) {
        HITLS_SESS_Free(session);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16040, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "SESS_Decode fail when decrypt session ticket.", 0, 0, 0, 0);
        /* The ticket content fails to be parsed, but the complete connection can be established. Therefore,
         * HITLS_SUCCESS is returned. */
        return HITLS_SUCCESS;
    }

    *sess = session;
    return HITLS_SUCCESS;
}

int32_t SESSMGR_DecryptSessionTicket(HITLS_Lib_Ctx *libCtx, const char *attrName,
    const TLS_SessionMgr *sessMgr, HITLS_Session **sess, const uint8_t *ticketBuf,
    uint32_t ticketBufSize, bool *isTicketExpect)
{
    if (sessMgr == NULL || sess == NULL || ticketBuf == NULL || isTicketExpect == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16041, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SESSMGR_DecryptSessionTicket input parameter is NULL.", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret;
    Ticket ticket = {0};
    /* Parse the data into the ticket structure. */
    ret = ParseSessionTicket(&ticket, ticketBuf, ticketBufSize);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16042, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "ParseSessionTicket fail when decrypt session ticket.", 0, 0, 0, 0);
        /* If the ticket fails to be parsed, the session is not resumption and the complete connection is established.
         * Therefore, HITLS_SUCCESS is returned. */
        *isTicketExpect = true;
        return HITLS_SUCCESS;
    }

    /* Obtain decryption information. */
    HITLS_CipherParameters cipher = {0};
    int32_t retVal = GetSessDecryptInfo(sessMgr, &ticket, &cipher);
    if (retVal < 0) {
        BSL_ERR_PUSH_ERROR(HITLS_SESS_ERR_SESSION_TICKET_KEY_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16043, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "GetSessDecryptInfo fail when decrypt session ticket.", 0, 0, 0, 0);
        return HITLS_SESS_ERR_SESSION_TICKET_KEY_FAIL;
    }
    switch (retVal) {
        case HITLS_TICKET_KEY_RET_FAIL:
            /* If no corresponding key is found, the system directly returns a message and complete link establishment
             * is performed. */
            *isTicketExpect = true;
            return HITLS_SUCCESS;
        case HITLS_TICKET_KEY_RET_SUCCESS_RENEW:
            *isTicketExpect = true;
            break;
        case HITLS_TICKET_KEY_RET_SUCCESS:
        default:
            *isTicketExpect = false;
            break;
    }
#ifdef HITLS_TLS_SUITE_CIPHER_CBC
    /* Verify the MAC address. */
    bool isPass = true;
    ret = CheckTicketHmac(libCtx, attrName, &cipher, &ticket, ticketBuf, ticketBufSize, &isPass);
    if ((ret != HITLS_SUCCESS) || (!isPass)) {
        /* If the HMAC check fails, the session is not restored and complete link establishment is performed. */
        return ret;
    }
#endif
    /* Parse the ticket content to the SESS. */
    return GenerateSessFromTicket(libCtx, attrName, &cipher, &ticket, ticketBufSize, sess);
}
#endif /* HITLS_TLS_FEATURE_SESSION_TICKET */