#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// 预定义宏
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define BLOCK_SIZE 16
#define ROUNDS 32

// 预计算查表优化表
static uint32_t T[4][256]; // 4个8bit输入->32bit输出的查找表

// S盒定义（保持不变）
static const uint8_t SM4_SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// 初始化预计算表
void init_sm4_tables() {
    for (int i = 0; i < 256; i++) {
        const uint8_t a = SM4_SBOX[i];
        // 合并tau和L变换：L(tau(x))
        const uint32_t l = a ^ ROTL(a, 2) ^ ROTL(a, 10) ^ ROTL(a, 18) ^ ROTL(a, 24);

        // 填充四个位置的查表值
        T[0][i] = l << 24;  // 字节位置0（最高位字节）
        T[1][i] = l << 16;  // 字节位置1
        T[2][i] = l << 8;   // 字节位置2
        T[3][i] = l;        // 字节位置3（最低位字节）
    }
}

// 密钥扩展（优化版）
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[ROUNDS]) {
    const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
    uint32_t K[36];

    // 加载主密钥
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
        K[i] ^= FK[i];
    }

    // 轮密钥生成
    for (int i = 0; i < ROUNDS; i++) {
        static const uint32_t CK[32] = {
           0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
           0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
           0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
           0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
           0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
           0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
           0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
           0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };



        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        // 使用查表优化S盒和线性变换
        tmp = T[0][(tmp >> 24) & 0xFF] ^ T[1][(tmp >> 16) & 0xFF] ^
            T[2][(tmp >> 8) & 0xFF] ^ T[3][tmp & 0xFF];

        K[i + 4] = K[i] ^ tmp;
        rk[i] = K[i + 4];
    }
}

// 优化后的加密块处理
static inline void sm4_encrypt_block(const uint32_t rk[ROUNDS],
    const uint8_t in[BLOCK_SIZE],
    uint8_t out[BLOCK_SIZE]) {
    uint32_t X[36];

    // 输入加载（小端序处理）
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4 * i] << 24) | (in[4 * i + 1] << 16) |
            (in[4 * i + 2] << 8) | in[4 * i + 3];
    }

    // 轮函数（使用预计算表）
    for (int i = 0; i < ROUNDS; i++) {
        const uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        X[i + 4] = X[i] ^ (T[0][(tmp >> 24) & 0xFF] ^ T[1][(tmp >> 16) & 0xFF] ^
            T[2][(tmp >> 8) & 0xFF] ^ T[3][tmp & 0xFF]);
    }

    // 输出处理（小端序转换）
    for (int i = 0; i < 4; i++) {
        const uint32_t val = X[35 - i];
        *out++ = (val >> 24) & 0xFF;
        *out++ = (val >> 16) & 0xFF;
        *out++ = (val >> 8) & 0xFF;
        *out++ = val & 0xFF;
    }
}

// CBC加密模式（优化循环展开）
void sm4_cbc_encrypt(const uint32_t rk[ROUNDS], const uint8_t iv[BLOCK_SIZE],
    const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    // 手动展开异或操作
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        uint8_t block[BLOCK_SIZE];
        const uint8_t* in_blk = in + i;
        uint8_t* out_blk = out + i;

        // 手动展开16字节异或
        block[0] = in_blk[0] ^ feedback[0];
        block[1] = in_blk[1] ^ feedback[1];
        block[2] = in_blk[2] ^ feedback[2];
        block[3] = in_blk[3] ^ feedback[3];
        block[4] = in_blk[4] ^ feedback[4];
        block[5] = in_blk[5] ^ feedback[5];
        block[6] = in_blk[6] ^ feedback[6];
        block[7] = in_blk[7] ^ feedback[7];
        block[8] = in_blk[8] ^ feedback[8];
        block[9] = in_blk[9] ^ feedback[9];
        block[10] = in_blk[10] ^ feedback[10];
        block[11] = in_blk[11] ^ feedback[11];
        block[12] = in_blk[12] ^ feedback[12];
        block[13] = in_blk[13] ^ feedback[13];
        block[14] = in_blk[14] ^ feedback[14];
        block[15] = in_blk[15] ^ feedback[15];

        sm4_encrypt_block(rk, block, out_blk);
        memcpy(feedback, out_blk, BLOCK_SIZE);
    }
}

// PKCS#7填充（保持不变）
size_t pkcs7_pad(const uint8_t* in, size_t len, uint8_t** out) {
    size_t pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    size_t new_len = len + pad_len;
    *out = malloc(new_len);
    if (!*out) return 0;

    memcpy(*out, in, len);
    memset(*out + len, pad_len, pad_len);
    return new_len;
}

int main() {
    init_sm4_tables(); // 初始化查表

    // 测试向量
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                       0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };
    uint8_t iv[16] = { 0 };
    const char* plaintext = "Hello, SM4-CBC encryption test!";

    // 数据填充
    size_t len = strlen(plaintext);
    uint8_t* padded_data = NULL;
    size_t padded_len = pkcs7_pad((const uint8_t*)plaintext, len, &padded_data);

    // 生成轮密钥
    uint32_t rk[ROUNDS];
    sm4_key_schedule(key, rk);

    // 执行加密
    uint8_t* ciphertext = malloc(padded_len);
    clock_t start = clock();
    sm4_cbc_encrypt(rk, iv, padded_data, padded_len, ciphertext);
    double encrypt_time = (double)(clock() - start) / CLOCKS_PER_SEC * 1000;

    // 输出结果
    printf("Original Plaintext: %s\n", plaintext);
    printf("Encryption time: %.2f ms\n", encrypt_time);
    printf("Ciphertext (hex):\n");

    for (size_t i = 0; i < padded_len; i++) {
        printf("%02X", ciphertext[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    printf("\n");

    free(padded_data);
    free(ciphertext);
    return 0;
}
