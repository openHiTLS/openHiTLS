/*
 * ECDH key delivery demo.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bsl_err.h"
#include "crypt_algid.h"
#include "crypt_eal_init.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"

static void EcdhPrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    uint32_t i;

    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int32_t EcdhCreateKeyPair(CRYPT_EAL_PkeyCtx **ctx)
{
    CRYPT_EAL_PkeyCtx *tmp = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, NULL);
    int32_t ret;

    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, CRYPT_ECC_NISTP256);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmp);
        return ret;
    }
    ret = CRYPT_EAL_PkeyGen(tmp);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmp);
        return ret;
    }

    *ctx = tmp;
    return CRYPT_SUCCESS;
}

static int32_t EcdhExportPeer(CRYPT_EAL_PkeyCtx *src, CRYPT_EAL_PkeyCtx **peer)
{
    CRYPT_EAL_PkeyCtx *tmp = NULL;
    CRYPT_EAL_PkeyPub pub = {0};
    uint8_t pubData[133] = {0};
    int32_t ret;

    tmp = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ECDH, CRYPT_EAL_PKEY_EXCH_OPERATE, NULL);
    if (tmp == NULL) {
        return -1;
    }
    ret = CRYPT_EAL_PkeySetParaById(tmp, CRYPT_ECC_NISTP256);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    pub.id = CRYPT_PKEY_ECDH;
    pub.key.eccPub.data = pubData;
    pub.key.eccPub.len = sizeof(pubData);
    ret = CRYPT_EAL_PkeyGetPub(src, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeySetPub(tmp, &pub);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    *peer = tmp;
    return CRYPT_SUCCESS;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(tmp);
    return ret;
}

int main(void)
{
    CRYPT_EAL_PkeyCtx *alice = NULL;
    CRYPT_EAL_PkeyCtx *bob = NULL;
    CRYPT_EAL_PkeyCtx *alicePeer = NULL;
    CRYPT_EAL_PkeyCtx *bobPeer = NULL;
    uint8_t aliceSecret[66] = {0};
    uint8_t bobSecret[66] = {0};
    uint32_t aliceSecretLen;
    uint32_t bobSecretLen;
    int32_t ret;

    printf("=== ECDH Key Delivery Example ===\n\n");

    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        printf("CRYPT_EAL_Init failed: 0x%x\n", ret);
        return -1;
    }

    ret = EcdhCreateKeyPair(&alice);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = EcdhCreateKeyPair(&bob);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = EcdhExportPeer(alice, &alicePeer);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = EcdhExportPeer(bob, &bobPeer);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }

    aliceSecretLen = CRYPT_EAL_PkeyGetKeyLen(alice) / 2;
    bobSecretLen = CRYPT_EAL_PkeyGetKeyLen(bob) / 2;
    ret = CRYPT_EAL_PkeyComputeShareKey(alice, bobPeer, aliceSecret, &aliceSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    ret = CRYPT_EAL_PkeyComputeShareKey(bob, alicePeer, bobSecret, &bobSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto cleanup;
    }
    if (aliceSecretLen != bobSecretLen || memcmp(aliceSecret, bobSecret, aliceSecretLen) != 0) {
        printf("shared secret mismatch\n");
        ret = -1;
        goto cleanup;
    }

    printf("ECDH shared secret generated successfully.\n");
    EcdhPrintHex("Shared secret", aliceSecret, aliceSecretLen);
    ret = 0;

cleanup:
    CRYPT_EAL_PkeyFreeCtx(alicePeer);
    CRYPT_EAL_PkeyFreeCtx(bobPeer);
    CRYPT_EAL_PkeyFreeCtx(alice);
    CRYPT_EAL_PkeyFreeCtx(bob);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return ret;
}
