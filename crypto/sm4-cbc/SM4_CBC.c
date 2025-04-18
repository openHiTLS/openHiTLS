#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#define DATA_SIZE (10 * 1024 * 1024) 

#define BLOCK_SIZE 16
#define ROUNDS 32


static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};


static uint32_t SM4_T[4][256];
static int tables_initialized = 0;


#define rol(x, n) (((x) << (n)) | ((x) >> (32 - (n))))


void init_sm4_table() {
    if (tables_initialized) return;

    for (int i = 0; i < 256; i++) {
        const uint8_t b = SBOX[i];


        const uint32_t t0 = (uint32_t)b << 24;
        SM4_T[0][i] = t0 ^ rol(t0, 2) ^ rol(t0, 10) ^ rol(t0, 18) ^ rol(t0, 24);

        const uint32_t t1 = (uint32_t)b << 16;
        SM4_T[1][i] = t1 ^ rol(t1, 2) ^ rol(t1, 10) ^ rol(t1, 18) ^ rol(t1, 24);

        const uint32_t t2 = (uint32_t)b << 8;
        SM4_T[2][i] = t2 ^ rol(t2, 2) ^ rol(t2, 10) ^ rol(t2, 18) ^ rol(t2, 24);

        const uint32_t t3 = (uint32_t)b;
        SM4_T[3][i] = t3 ^ rol(t3, 2) ^ rol(t3, 10) ^ rol(t3, 18) ^ rol(t3, 24);
    }
    tables_initialized = 1;
}


void sm4_key_expansion(const uint8_t key[16], uint32_t rk[ROUNDS]) {
    const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
    const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[36];


    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            key[4 * i + 3];
        K[i] ^= FK[i];
    }


    for (int i = 0; i < ROUNDS; i++) {
        const uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        K[i + 4] = K[i] ^ (SM4_T[0][(tmp >> 24) & 0xFF] ^
            SM4_T[1][(tmp >> 16) & 0xFF] ^
            SM4_T[2][(tmp >> 8) & 0xFF] ^
            SM4_T[3][tmp & 0xFF]);
        rk[i] = K[i + 4];
    }
}


void sm4_encrypt_block(const uint32_t rk[ROUNDS], const uint8_t plain[16], uint8_t cipher[16]) {
    uint32_t X[36];


    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)plain[4 * i] << 24) |
            ((uint32_t)plain[4 * i + 1] << 16) |
            ((uint32_t)plain[4 * i + 2] << 8) |
            plain[4 * i + 3];
    }


    for (int i = 0; i < ROUNDS; i++) {
        const uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        X[i + 4] = X[i] ^ (SM4_T[0][(tmp >> 24) & 0xFF] ^
            SM4_T[1][(tmp >> 16) & 0xFF] ^
            SM4_T[2][(tmp >> 8) & 0xFF] ^
            SM4_T[3][tmp & 0xFF]);
    }


    const uint32_t result[4] = { X[35], X[34], X[33], X[32] };
    for (int i = 0; i < 4; i++) {
        cipher[4 * i] = (result[i] >> 24) & 0xFF;
        cipher[4 * i + 1] = (result[i] >> 16) & 0xFF;
        cipher[4 * i + 2] = (result[i] >> 8) & 0xFF;
        cipher[4 * i + 3] = result[i] & 0xFF;
    }
}


void sm4_decrypt_block(const uint32_t rk[ROUNDS], const uint8_t cipher[16], uint8_t plain[16]) {
    uint32_t X[36];


    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)cipher[4 * i] << 24) |
            ((uint32_t)cipher[4 * i + 1] << 16) |
            ((uint32_t)cipher[4 * i + 2] << 8) |
            cipher[4 * i + 3];
    }


    for (int i = 0; i < ROUNDS; i++) {
        const uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[ROUNDS - 1 - i];
        X[i + 4] = X[i] ^ (SM4_T[0][(tmp >> 24) & 0xFF] ^
            SM4_T[1][(tmp >> 16) & 0xFF] ^
            SM4_T[2][(tmp >> 8) & 0xFF] ^
            SM4_T[3][tmp & 0xFF]);
    }


    const uint32_t result[4] = { X[35], X[34], X[33], X[32] };
    for (int i = 0; i < 4; i++) {
        plain[4 * i] = (result[i] >> 24) & 0xFF;
        plain[4 * i + 1] = (result[i] >> 16) & 0xFF;
        plain[4 * i + 2] = (result[i] >> 8) & 0xFF;
        plain[4 * i + 3] = result[i] & 0xFF;
    }
}


void sm4_cbc_encrypt(const uint32_t rk[ROUNDS], const uint8_t iv[BLOCK_SIZE],
    const uint8_t* plain, size_t len, uint8_t* cipher) {
    uint8_t block[BLOCK_SIZE];
    memcpy(block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {

        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= plain[i + j];
        }


        sm4_encrypt_block(rk, block, cipher + i);


        memcpy(block, cipher + i, BLOCK_SIZE);
    }
}


typedef struct {
    const uint32_t* rk;
    const uint8_t* ciphertext;
    uint8_t* plaintext;
    const uint8_t* iv;
    size_t start_block;
    size_t num_blocks;
} thread_args_t;


void* thread_cbc_decrypt_worker(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    uint8_t prev[BLOCK_SIZE], curr[BLOCK_SIZE], temp[BLOCK_SIZE];

    for (size_t i = 0; i < args->num_blocks; i++) {
        size_t block_offset = (args->start_block + i) * BLOCK_SIZE;

        memcpy(curr, args->ciphertext + block_offset, BLOCK_SIZE);
        sm4_decrypt_block(args->rk, curr, temp);


        const uint8_t* prev_block = (args->start_block + i == 0)
            ? args->iv
            : args->ciphertext + block_offset - BLOCK_SIZE;

        for (int j = 0; j < BLOCK_SIZE; j++) {
            args->plaintext[block_offset + j] = temp[j] ^ prev_block[j];
        }
    }
    return NULL;
}


void sm4_cbc_decrypt_parallel(const uint32_t rk[ROUNDS], const uint8_t iv[BLOCK_SIZE],
    const uint8_t* in, size_t len, uint8_t* out, size_t threads) {

    size_t num_blocks = len / BLOCK_SIZE;
    size_t blocks_per_thread = num_blocks / threads;
    size_t remaining_blocks = num_blocks % threads;

    pthread_t thread_ids[threads];
    thread_args_t thread_args[threads];

    size_t block_index = 0;

    for (size_t i = 0; i < threads; i++) {
        size_t blocks = blocks_per_thread + (i < remaining_blocks ? 1 : 0);
        thread_args[i].rk = rk;
        thread_args[i].ciphertext = in;
        thread_args[i].plaintext = out;
        thread_args[i].iv = iv;
        thread_args[i].start_block = block_index;
        thread_args[i].num_blocks = blocks;
        pthread_create(&thread_ids[i], NULL, thread_cbc_decrypt_worker, &thread_args[i]);
        block_index += blocks;
    }

    for (size_t i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }
}


static inline uint64_t get_cycles() {
    uint64_t cycles;
    asm volatile ("rdcycle %0" : "=r" (cycles));
    return cycles;
}
int main() {
    init_sm4_table();
    uint8_t key[16];
    uint8_t iv[16];

    for (int i = 0; i < 16; i++) {
        key[i] = rand() % 256;
        iv[i] = rand() % 256;
    }

    uint8_t* plaintext = (uint8_t*)malloc(DATA_SIZE);
    uint8_t* ciphertext = (uint8_t*)malloc(DATA_SIZE);
    uint8_t* decrypted = (uint8_t*)malloc(DATA_SIZE);

    if (plaintext == NULL || ciphertext == NULL || decrypted == NULL) {
        printf("Memory allocation failed!\n");
        return -1;
    }


    for (size_t i = 0; i < DATA_SIZE; i++) {
        plaintext[i] = rand() % 256;
    }

    uint32_t rk[ROUNDS];
    uint64_t start_cycles = get_cycles();
    sm4_key_expansion(key, rk);

    sm4_cbc_encrypt(rk, iv, plaintext, DATA_SIZE, ciphertext);
    sm4_cbc_decrypt_parallel(rk, iv, ciphertext, DATA_SIZE, decrypted, 4);

    uint64_t end_cycles = get_cycles();
    double total_time_sec = (double)(end_cycles - start_cycles) / (3.187199 * 1000000000.0);
    printf("Total time: %.3f seconds\n", total_time_sec);

    printf("Ciphertext: ");
    for (int i = 0; i < 64; i++) printf("%02X", ciphertext[i]);
    printf("\n");

    printf("Decrypted : ");
    for (int i = 0; i < 64; i++) printf("%02X", decrypted[i]);
    printf("\n");

    return 0;
}
