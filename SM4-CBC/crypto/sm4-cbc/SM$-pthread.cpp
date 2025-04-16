#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

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

static const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
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

void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t MK[4];
    for (int i = 0; i < 4; i++) {
        MK[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    }
    uint32_t K[36];
    K[0] = MK[0] ^ FK[0];
    K[1] = MK[1] ^ FK[1];
    K[2] = MK[2] ^ FK[2];
    K[3] = MK[3] ^ FK[3];

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        uint32_t after_sbox = 0;
        after_sbox |= SM4_SBOX[(tmp >> 24) & 0xFF] << 24;
        after_sbox |= SM4_SBOX[(tmp >> 16) & 0xFF] << 16;
        after_sbox |= SM4_SBOX[(tmp >> 8) & 0xFF] << 8;
        after_sbox |= SM4_SBOX[tmp & 0xFF];
        tmp = after_sbox ^ ROTL(after_sbox, 13) ^ ROTL(after_sbox, 23);
        K[i + 4] = K[i] ^ tmp;
        rk[i] = K[i + 4];
    }
}

void sm4_encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = (in[4 * i] << 24) | (in[4 * i + 1] << 16) | (in[4 * i + 2] << 8) | in[4 * i + 3];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
        uint32_t after_sbox = 0;
        after_sbox |= SM4_SBOX[(tmp >> 24) & 0xFF] << 24;
        after_sbox |= SM4_SBOX[(tmp >> 16) & 0xFF] << 16;
        after_sbox |= SM4_SBOX[(tmp >> 8) & 0xFF] << 8;
        after_sbox |= SM4_SBOX[tmp & 0xFF];
        tmp = after_sbox ^ ROTL(after_sbox, 2) ^ ROTL(after_sbox, 10) ^ ROTL(after_sbox, 18) ^ ROTL(after_sbox, 24);
        X[i + 4] = X[i] ^ tmp;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[35 - i];
        out[4 * i] = (val >> 24) & 0xFF;
        out[4 * i + 1] = (val >> 16) & 0xFF;
        out[4 * i + 2] = (val >> 8) & 0xFF;
        out[4 * i + 3] = val & 0xFF;
    }
}

void sm4_cbc_encrypt(const uint32_t rk[32], const uint8_t iv[16], const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);
    for (size_t i = 0; i < len; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = in[i + j] ^ feedback[j];
        }
        sm4_encrypt_block(rk, block, out + i);
        memcpy(feedback, out + i, 16);
    }
}

size_t pkcs7_pad(const uint8_t* in, size_t len, uint8_t** out) {
    size_t pad_len = 16 - (len % 16);
    size_t new_len = len + pad_len;
    *out = malloc(new_len);
    if (*out == NULL) return 0;
    memcpy(*out, in, len);
    memset(*out + len, pad_len, pad_len);
    return new_len;
}


#include <pthread.h>

// 新增结构体用于线程间传递数据块
typedef struct {
    uint8_t block[16];          // 待加密块
    size_t index;               // 块在输出中的偏移位置
} BlockData;

// 全局共享数据与同步变量
typedef struct {
    const uint8_t* in;          // 输入数据指针
    uint8_t* out;               // 输出数据指针
    const uint32_t* rk;         // 轮密钥指针
    uint8_t feedback[16];       // CBC反馈值
    size_t len;                 // 数据总长度
    size_t current_idx;         // 当前处理块索引

    pthread_mutex_t mutex;      // 互斥锁
    pthread_cond_t cond_producer;// 生产者条件变量
    pthread_cond_t cond_consumer;// 消费者条件变量
    BlockData shared_block;     // 共享数据块
    int data_ready;             // 数据是否就绪
    int encryption_done;        // 加密是否完成
} ThreadData;

// 生产者线程函数：执行异或操作
void* producer_thread_func(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    size_t num_blocks = data->len / 16;

    for (size_t i = 0; i < num_blocks; i++) {
        pthread_mutex_lock(&data->mutex);

        // 等待上一块加密完成（首次除外）
        if (i > 0) {
            while (!data->encryption_done) {
                pthread_cond_wait(&data->cond_producer, &data->mutex);
            }
        }

        // 执行异或操作
        uint8_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = data->in[i * 16 + j] ^ data->feedback[j];
        }

        // 传递数据到共享区域
        memcpy(data->shared_block.block, block, 16);
        data->shared_block.index = i * 16;
        data->data_ready = 1;
        data->encryption_done = 0;

        // 通知消费者
        pthread_cond_signal(&data->cond_consumer);
        pthread_mutex_unlock(&data->mutex);
    }
    return NULL;
}

// 消费者线程函数：执行加密并更新反馈
void* consumer_thread_func(void* arg) {
    ThreadData* data = (ThreadData*)arg;
    size_t num_blocks = data->len / 16;

    for (size_t i = 0; i < num_blocks; i++) {
        pthread_mutex_lock(&data->mutex);
        while (!data->data_ready) {
            pthread_cond_wait(&data->cond_consumer, &data->mutex);
        }

        // 加密数据块
        sm4_encrypt_block(data->rk, data->shared_block.block,
            data->out + data->shared_block.index);

        // 更新反馈值
        memcpy(data->feedback, data->out + data->shared_block.index, 16);
        data->data_ready = 0;
        data->encryption_done = 1;

        // 通知生产者
        pthread_cond_signal(&data->cond_producer);
        pthread_mutex_unlock(&data->mutex);
    }
    return NULL;
}

// 多线程CBC加密函数
void sm4_cbc_encrypt_mt(const uint32_t rk[32], const uint8_t iv[16],
    const uint8_t* in, size_t len, uint8_t* out) {
    ThreadData data;
    memset(&data, 0, sizeof(data));
    memcpy(data.feedback, iv, 16);
    data.in = in;
    data.out = out;
    data.rk = rk;
    data.len = len;

    // 初始化同步原语
    pthread_mutex_init(&data.mutex, NULL);
    pthread_cond_init(&data.cond_producer, NULL);
    pthread_cond_init(&data.cond_consumer, NULL);

    // 创建线程
    pthread_t producer, consumer;
    pthread_create(&producer, NULL, producer_thread_func, &data);
    pthread_create(&consumer, NULL, consumer_thread_func, &data);

    // 等待线程完成
    pthread_join(producer, NULL);
    pthread_join(consumer, NULL);

    // 清理资源
    pthread_mutex_destroy(&data.mutex);
    pthread_cond_destroy(&data.cond_producer);
    pthread_cond_destroy(&data.cond_consumer);
}
int main() {
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10 };
    uint8_t iv[16] = { 0 };
    const char* plaintext = "Hello, SM4-CBC encryption test!";
    size_t len = strlen(plaintext);

    uint8_t* padded_plain = NULL;
    size_t padded_len = pkcs7_pad((const uint8_t*)plaintext, len, &padded_plain);
    printf("Original Plaintext: %s\n", plaintext);
    printf("Padded Plaintext (hex): ");
    for (size_t i = 0; i < padded_len; i++) {
        printf("%02X", padded_plain[i]);
        if ((i + 1) % 16 == 0) printf(" ");
    }
    printf("\n");

    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    uint8_t* ciphertext = malloc(padded_len);
    clock_t start = clock();
    sm4_cbc_encrypt_mt(rk, iv, padded_plain, padded_len, ciphertext);
    clock_t end = clock();
    double enc_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;

    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < padded_len; i++) {
        printf("%02X", ciphertext[i]);
        if ((i + 1) % 16 == 0) printf(" ");
    }
    printf("\n");
    printf("Encryption Time: %.2f ms\n", enc_time);

    free(padded_plain);
    free(ciphertext);
    return 0;
}