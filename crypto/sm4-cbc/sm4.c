#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>   
#include <string.h>
#include <pthread.h>
#include <time.h>

/* 预计算T表（查表优化） */
/* SM4 标准 S 盒（8位输入 → 8位输出） */
static const uint8_t SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

/* 32位循环左移 */
static inline uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static uint32_t T[256];    // 加密T表
alignas(64) static uint32_t T_prime[256]; // 密钥扩展T'表

/* 生成 T 表（输出32位数据） */
void generate_T_table(uint32_t T[256]) {
    for (int x = 0; x < 256; x++) {
        // 1. 通过S盒得到8位输出
        uint8_t s = SBOX[x];
        // 2. 构造32位数据：s << 24（高8位为s，低24位为0）
        uint32_t B = (uint32_t)s << 24;
        // 3. 应用线性变换 L：B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
        T[x] = B ^ rotate_left(B, 2) ^ rotate_left(B, 10) ^ rotate_left(B, 18) ^ rotate_left(B, 24);
    }
}

void generate_T_prime_table(uint32_t T_prime[256]) {
    for (int x = 0; x < 256; x++) {
        uint8_t s = SBOX[x];
        uint32_t B = (uint32_t)s << 24;
        T_prime[x] = B ^ rotate_left(B, 2) ^ rotate_left(B, 10) ^
                     rotate_left(B, 18) ^ rotate_left(B, 24);
    }
}

void init_sm4_tables() {
    generate_T_table(T);
    generate_T_prime_table(T_prime);
}
/* ===================== 函数前置声明 ===================== */
void sm4_key_schedule(uint32_t rk[32], const uint8_t key[16]);
void sm4_cbc_encrypt(const uint32_t rk[32], uint8_t iv[16], const uint8_t *input, uint8_t *output, size_t length);
void parallel_encrypt(const uint32_t rk[32], uint8_t ivs[][16], const uint8_t **inputs, uint8_t **outputs, size_t *lengths, int num_tasks);
/* ===================== 核心算法实现 ===================== */
// SM4标准FK常量
static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// SM4标准CK常量
 static const uint32_t CK[32] = {
    0x00070F15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
void sm4_key_schedule(uint32_t rk[32], const uint8_t key[16]) {
     uint32_t K[4];
    // 初始异或FK常量
    static const uint32_t FK[4] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };
    
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4*i]<<24) | ((uint32_t)key[4*i+1]<<16) | 
               ((uint32_t)key[4*i+2]<<8) | (uint32_t)key[4*i+3];
        K[i] ^= FK[i]; // 异或FK
    }

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ CK[i];
        // 使用T'表进行非线性变换
        tmp = T_prime[(tmp >> 24)] ^ T_prime[(tmp >> 16) & 0xFF] ^ 
              T_prime[(tmp >> 8) & 0xFF] ^ T_prime[tmp & 0xFF];
        rk[i] = tmp;
        K[i%4] = rk[i];
    }
}
/* CBC模式加密（单线程） */
static inline void sm4_encrypt_block(const uint32_t rk[32], const uint8_t plain[16], uint8_t cipher[16]) {
     uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)plain[4*i]<<24) | ((uint32_t)plain[4*i+1]<<16) | 
               ((uint32_t)plain[4*i+2]<<8) | (uint32_t)plain[4*i+3];
    }

    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        tmp = T[tmp >> 24] ^ T[(tmp >> 16) & 0xFF] ^ 
              T[(tmp >> 8) & 0xFF] ^ T[tmp & 0xFF];
        X[0] ^= tmp;
        // 轮换寄存器
        uint32_t temp = X[0]; 
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = temp;
    }

    // 逆序输出
    for (int i = 0; i < 4; i++) {
        cipher[4*i]   = (X[3-i] >> 24) & 0xFF;
        cipher[4*i+1] = (X[3-i] >> 16) & 0xFF;
        cipher[4*i+2] = (X[3-i] >> 8)  & 0xFF;
        cipher[4*i+3] = X[3-i] & 0xFF;
    }
}
/* CBC模式加密（单线程） */
void sm4_cbc_encrypt(const uint32_t rk[32], uint8_t iv[16], const uint8_t *input, uint8_t *output, size_t length) {
     uint8_t block[16];
    for (size_t i = 0; i < length; i += 16) {
        // 异或IV与明文块
        for (int j = 0; j < 16; j++) 
            block[j] = input[i + j] ^ iv[j];
        // 加密块
        sm4_encrypt_block(rk, block, output + i);
        // 更新IV为当前密文
        memcpy(iv, output + i, 16);
    }
}

/* ===================== 多线程部分 ===================== */
typedef struct {
    const uint32_t *rk;
    uint8_t iv[16];
    const uint8_t *input;
    uint8_t *output;
    size_t length;
} ThreadTask;

static void* encrypt_thread(void *arg) {
    ThreadTask *task = (ThreadTask*)arg;
    sm4_cbc_encrypt(task->rk, task->iv, task->input, task->output, task->length);
    return NULL;
}

void parallel_encrypt(const uint32_t rk[32], uint8_t ivs[][16], const uint8_t **inputs, uint8_t **outputs, size_t *lengths, int num_tasks) {
    pthread_t threads[num_tasks];
    ThreadTask tasks[num_tasks];

    // 创建线程
    for (int i = 0; i < num_tasks; i++) {
        memcpy(tasks[i].iv, ivs[i], 16);
        tasks[i].rk = rk;
        tasks[i].input = inputs[i];
        tasks[i].output = outputs[i];
        tasks[i].length = lengths[i];
        pthread_create(&threads[i], NULL, encrypt_thread, &tasks[i]);
    }

    // 等待线程完成
    for (int i = 0; i < num_tasks; i++) {
        pthread_join(threads[i], NULL);
    }
}

/* ===================== 性能测试部分 ===================== */
static void generate_test_data(uint8_t *data, size_t size) {
      for (size_t i = 0; i < size; i++) {
        data[i] = rand() % 256;
    }
}

static void benchmark(size_t data_size, int num_threads) {
    // 保证数据大小是16字节的倍数
    data_size = (data_size + 15) & ~0x0F;
    // 初始化密钥
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                       0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    uint32_t rk[32];
    sm4_key_schedule(rk, key);

    // 分配内存
    uint8_t *input = malloc(data_size);
    uint8_t *output = malloc(data_size);
    generate_test_data(input, data_size);

    // 准备多线程参数
    uint8_t ivs[16][16] = {0}; // 最多支持8线程
    const uint8_t *inputs[16];
    uint8_t *outputs[16];
    size_t lengths[16];
    // 分割时保证每个线程处理16字节对齐
    size_t block_size = data_size / num_threads;
    block_size = block_size - (block_size % 16);

    for (int i = 0; i < num_threads; i++) {
        inputs[i] = input + i * block_size;
        outputs[i] = output + i * block_size;
        lengths[i] = (i == num_threads-1) ? (data_size - i*block_size) : block_size;
        memcpy(ivs[i], key, 16); 
    }

    // 计时
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (num_threads > 1) {
        parallel_encrypt(rk, ivs, inputs, outputs, lengths, num_threads);
    } else {
        uint8_t iv[16] = {0};  
        sm4_cbc_encrypt(rk, iv, input, output, data_size);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_sec = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Threads=%d, Size=%.2fMB, Time=%.4fs, Throughput=%.2f MB/s\n",
           num_threads, data_size/(1024.0*1024), time_sec, data_size/(time_sec*1024*1024));

    free(input);
    free(output);
}

/* ===================== 主函数 ===================== */
int main(int argc, char *argv[]) {
        init_sm4_tables();//初始化T表
    	if (argc != 3) {
        printf("Usage: %s <num_threads(1-16)> <data_size_KB>\n", argv[0]); 
        return 1;
    }

    int num_threads = atoi(argv[1]);    
    size_t data_size = atoi(argv[2]) * 1024;  

    if (num_threads < 1 || num_threads > 16) {
        printf("Threads must be 1-16\n");
        return 1;
    }

    srand(time(NULL));
    benchmark(data_size, num_threads);
    return 0;
}
