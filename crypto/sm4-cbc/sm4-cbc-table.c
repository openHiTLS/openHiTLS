/**
 * SM4-CBC Implementation with Table Optimization
 *
 * This file implements the SM4 block cipher in CBC mode with table-based
 * optimization for improved performance.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

 /* SM4 Constants */
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32

/* Rotates a 32-bit word left by n bits */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* S-box for SM4 */
static const uint8_t SM4_SBOX[256] = {
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

/* System parameters (FK) */
static const uint32_t SM4_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

/* Fixed parameters (CK) */
static const uint32_t SM4_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/* Pre-computed T-tables for optimization */
static uint32_t T0[256], T1[256], T2[256], T3[256];

/* Build the T-tables for optimization */
void sm4_init_tables(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t a = SM4_SBOX[i];
        uint32_t b = a;

        /* T0 = S-Box(x) */
        T0[i] = b;

        /* T1 = S-Box(x) ^ ROTL(S-Box(x), 2) */
        T1[i] = b ^ ROTL32(b, 2);

        /* T2 = S-Box(x) ^ ROTL(S-Box(x), 10) */
        T2[i] = b ^ ROTL32(b, 10);

        /* T3 = S-Box(x) ^ ROTL(S-Box(x), 18) ^ ROTL(S-Box(x), 24) */
        T3[i] = b ^ ROTL32(b, 18) ^ ROTL32(b, 24);
    }
}

/* Non-optimized SM4 T-transform */
uint32_t sm4_t_non_optimized(uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8) & 0xFF;
    uint8_t d = x & 0xFF;

    a = SM4_SBOX[a];
    b = SM4_SBOX[b];
    c = SM4_SBOX[c];
    d = SM4_SBOX[d];

    uint32_t result = (a << 24) | (b << 16) | (c << 8) | d;
    return result ^ ROTL32(result, 2) ^ ROTL32(result, 10) ^ ROTL32(result, 18) ^ ROTL32(result, 24);
}

/* Optimized SM4 T-transform using table lookups */
uint32_t sm4_t_optimized(uint32_t x) {
    return (T0[(x >> 24) & 0xFF] << 24) |
        (T1[(x >> 16) & 0xFF] << 16) |
        (T2[(x >> 8) & 0xFF] << 8) |
        T3[x & 0xFF];
}

/* Key expansion routine */
void sm4_key_schedule(const uint8_t* key, uint32_t* rk, int optimize) {
    uint32_t K[4];

    /* Convert key bytes to 32-bit words */
    for (int i = 0; i < 4; i++) {
        K[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        K[i] ^= SM4_FK[i];  // XOR with system parameters
    }

    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t tmp = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ SM4_CK[i];

        if (optimize) {
            K[i % 4] ^= sm4_t_optimized(tmp);
        }
        else {
            K[i % 4] ^= sm4_t_non_optimized(tmp);
        }

        rk[i] = K[i % 4];
    }
}

/* Standard implementation of SM4 single block encryption */
void sm4_encrypt_block(const uint32_t* rk, const uint8_t* input, uint8_t* output, int optimize) {
    uint32_t X[4];

    /* Convert input bytes to 32-bit words */
    for (int i = 0; i < 4; i++) {
        X[i] = (input[i * 4] << 24) | (input[i * 4 + 1] << 16) | (input[i * 4 + 2] << 8) | input[i * 4 + 3];
    }

    /* Encryption rounds */
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t tmp = X[(i + 1) % 4] ^ X[(i + 2) % 4] ^ X[(i + 3) % 4] ^ rk[i];

        if (optimize) {
            X[i % 4] ^= sm4_t_optimized(tmp);
        }
        else {
            X[i % 4] ^= sm4_t_non_optimized(tmp);
        }
    }

    /* Convert 32-bit words to output bytes (with byte order reversed) */
    for (int i = 0; i < 4; i++) {
        int j = 3 - i;  // Reverse order
        output[i * 4] = (X[j] >> 24) & 0xFF;
        output[i * 4 + 1] = (X[j] >> 16) & 0xFF;
        output[i * 4 + 2] = (X[j] >> 8) & 0xFF;
        output[i * 4 + 3] = X[j] & 0xFF;
    }
}

/* Standard implementation of SM4 single block decryption */
void sm4_decrypt_block(const uint32_t* rk, const uint8_t* input, uint8_t* output, int optimize) {
    uint32_t X[4];

    /* Convert input bytes to 32-bit words */
    for (int i = 0; i < 4; i++) {
        X[i] = (input[i * 4] << 24) | (input[i * 4 + 1] << 16) | (input[i * 4 + 2] << 8) | input[i * 4 + 3];
    }

    /* Decryption rounds (same as encryption but using rk in reverse) */
    for (int i = 0; i < SM4_ROUNDS; i++) {
        uint32_t tmp = X[(i + 1) % 4] ^ X[(i + 2) % 4] ^ X[(i + 3) % 4] ^ rk[SM4_ROUNDS - 1 - i];

        if (optimize) {
            X[i % 4] ^= sm4_t_optimized(tmp);
        }
        else {
            X[i % 4] ^= sm4_t_non_optimized(tmp);
        }
    }

    /* Convert 32-bit words to output bytes (with byte order reversed) */
    for (int i = 0; i < 4; i++) {
        int j = 3 - i;  // Reverse order
        output[i * 4] = (X[j] >> 24) & 0xFF;
        output[i * 4 + 1] = (X[j] >> 16) & 0xFF;
        output[i * 4 + 2] = (X[j] >> 8) & 0xFF;
        output[i * 4 + 3] = X[j] & 0xFF;
    }
}

/* SM4-CBC Encryption */
void sm4_cbc_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input,
    uint8_t* output, size_t length, int optimize) {

    if (length % SM4_BLOCK_SIZE != 0) {
        fprintf(stderr, "Input length must be a multiple of %d bytes\n", SM4_BLOCK_SIZE);
        return;
    }

    /* Initialize T-tables if using optimization */
    if (optimize) {
        sm4_init_tables();
    }

    /* Key expansion */
    uint32_t rk[SM4_ROUNDS];
    sm4_key_schedule(key, rk, optimize);

    /* Initialize IV */
    uint8_t iv_block[SM4_BLOCK_SIZE];
    memcpy(iv_block, iv, SM4_BLOCK_SIZE);

    /* Process each block in CBC mode */
    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        /* XOR input block with IV or previous ciphertext block */
        uint8_t block[SM4_BLOCK_SIZE];
        for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
            block[j] = input[i + j] ^ iv_block[j];
        }

        /* Encrypt the block */
        sm4_encrypt_block(rk, block, output + i, optimize);

        /* Update IV for next block */
        memcpy(iv_block, output + i, SM4_BLOCK_SIZE);
    }
}

/* SM4-CBC Decryption */
void sm4_cbc_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input,
    uint8_t* output, size_t length, int optimize) {

    if (length % SM4_BLOCK_SIZE != 0) {
        fprintf(stderr, "Input length must be a multiple of %d bytes\n", SM4_BLOCK_SIZE);
        return;
    }

    /* Initialize T-tables if using optimization */
    if (optimize) {
        sm4_init_tables();
    }

    /* Key expansion */
    uint32_t rk[SM4_ROUNDS];
    sm4_key_schedule(key, rk, optimize);

    /* Initialize IV */
    uint8_t iv_block[SM4_BLOCK_SIZE];
    memcpy(iv_block, iv, SM4_BLOCK_SIZE);

    /* Process each block in CBC mode */
    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        /* Decrypt the ciphertext block */
        uint8_t block[SM4_BLOCK_SIZE];
        sm4_decrypt_block(rk, input + i, block, optimize);

        /* XOR with IV or previous ciphertext block */
        for (int j = 0; j < SM4_BLOCK_SIZE; j++) {
            output[i + j] = block[j] ^ iv_block[j];
        }

        /* Update IV for next block */
        memcpy(iv_block, input + i, SM4_BLOCK_SIZE);
    }
}

/* Print bytes in hexadecimal format */
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* SM4-CBC test function */
void sm4_cbc_test(size_t data_size, int optimize) {
    printf("\n---- SM4-CBC Test with %s (%zu bytes) ----\n",
        optimize ? "Table Optimization" : "Standard Implementation", data_size);

    /* Generate random key and IV */
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];

    srand((unsigned int)time(NULL));
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
        key[i] = rand() % 256;
    }
    for (int i = 0; i < SM4_BLOCK_SIZE; i++) {
        iv[i] = rand() % 256;
    }

    /* Generate random input data (padded to block size) */
    size_t padded_size = (data_size + SM4_BLOCK_SIZE - 1) / SM4_BLOCK_SIZE * SM4_BLOCK_SIZE;
    uint8_t* input = (uint8_t*)malloc(padded_size);
    uint8_t* encrypted = (uint8_t*)malloc(padded_size);
    uint8_t* decrypted = (uint8_t*)malloc(padded_size);

    if (!input || !encrypted || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    for (size_t i = 0; i < data_size; i++) {
        input[i] = rand() % 256;
    }
    /* PKCS#7 padding */
    uint8_t padding = padded_size - data_size;
    for (size_t i = data_size; i < padded_size; i++) {
        input[i] = padding;
    }

    /* Print test data */
    print_hex("Key", key, SM4_KEY_SIZE);
    print_hex("IV", iv, SM4_BLOCK_SIZE);
    if (data_size <= 32) {
        print_hex("Input", input, padded_size);
    }
    else {
        print_hex("Input (first 32 bytes)", input, 32);
    }

    /* Measure encryption time */
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    sm4_cbc_encrypt(key, iv, input, encrypted, padded_size, optimize);
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    /* Print encryption results */
    if (data_size <= 32) {
        print_hex("Encrypted", encrypted, padded_size);
    }
    else {
        print_hex("Encrypted (first 32 bytes)", encrypted, 32);
    }
    printf("Encryption time: %f seconds\n", cpu_time_used);
    printf("Encryption throughput: %f MB/s\n", (padded_size / 1048576.0) / cpu_time_used);

    /* Measure decryption time */
    start = clock();
    sm4_cbc_decrypt(key, iv, encrypted, decrypted, padded_size, optimize);
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

    /* Print decryption results */
    if (data_size <= 32) {
        print_hex("Decrypted", decrypted, padded_size);
    }
    else {
        print_hex("Decrypted (first 32 bytes)", decrypted, 32);
    }
    printf("Decryption time: %f seconds\n", cpu_time_used);
    printf("Decryption throughput: %f MB/s\n", (padded_size / 1048576.0) / cpu_time_used);

    /* Verify decryption */
    int match = memcmp(input, decrypted, padded_size) == 0;
    printf("Decryption verification: %s\n", match ? "PASSED" : "FAILED");

    free(input);
    free(encrypted);
    free(decrypted);
}

/* Performance comparison benchmark */
void sm4_performance_benchmark() {
    printf("\n---- SM4-CBC Performance Benchmark ----\n");

    /* Test with different data sizes */
    size_t sizes[] = { 1024, 1024 * 1024, 10 * 1024 * 1024 };
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    for (int i = 0; i < num_sizes; i++) {
        /* Test standard implementation */
        sm4_cbc_test(sizes[i], 0);

        /* Test table-optimized implementation */
        sm4_cbc_test(sizes[i], 1);

        printf("\n");
    }
}

/* Main function for testing */
int main() {
    printf("SM4-CBC Implementation with Table Optimization\n");
    printf("=============================================\n");

    /* Single block test */
    uint8_t test_key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                           0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t test_iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    uint8_t test_data[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };

    uint8_t encrypted[16], decrypted[16];

    /* Initialize T-tables */
    sm4_init_tables();

    /* Test standard implementation */
    printf("\n== Standard Implementation Test ==\n");

    sm4_cbc_encrypt(test_key, test_iv, test_data, encrypted, sizeof(test_data), 0);
    print_hex("Plaintext", test_data, sizeof(test_data));
    print_hex("Ciphertext", encrypted, sizeof(encrypted));

    sm4_cbc_decrypt(test_key, test_iv, encrypted, decrypted, sizeof(encrypted), 0);
    print_hex("Decrypted", decrypted, sizeof(decrypted));

    printf("Decryption verification: %s\n",
        memcmp(test_data, decrypted, sizeof(test_data)) == 0 ? "PASSED" : "FAILED");

    /* Test table-optimized implementation */
    printf("\n== Table-Optimized Implementation Test ==\n");

    sm4_cbc_encrypt(test_key, test_iv, test_data, encrypted, sizeof(test_data), 1);
    print_hex("Plaintext", test_data, sizeof(test_data));
    print_hex("Ciphertext", encrypted, sizeof(encrypted));

    sm4_cbc_decrypt(test_key, test_iv, encrypted, decrypted, sizeof(encrypted), 1);
    print_hex("Decrypted", decrypted, sizeof(decrypted));

    printf("Decryption verification: %s\n",
        memcmp(test_data, decrypted, sizeof(test_data)) == 0 ? "PASSED" : "FAILED");

    /* Run performance benchmark */
    sm4_performance_benchmark();

    return 0;
}