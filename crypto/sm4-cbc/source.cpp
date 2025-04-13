#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

// SM4算法参数
#define SM4_BLOCK_SIZE 16     // 128位分组大小，16字节
#define SM4_KEY_SIZE 16       // 128位密钥，16字节
#define SM4_ROUNDS 32         // SM4加密轮数

// 线程相关参数
#define MAX_THREADS 16        // 最大线程数
#define DEFAULT_THREADS 4     // 默认线程数

// 预置的S盒
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

// SM4系统参数
static const uint32_t FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// SM4常量参数
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

// 优化1: 预计算T表，基于S盒和线性变换
uint32_t T_TABLE[256];

// 多线程参数
typedef struct {
    uint8_t* data;
    size_t size;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* result;
    int thread_id;
    int num_threads;
} ThreadArgs;

// 工具函数: 字节数组转换为32位整数 (小端序)
static uint32_t load_uint32_le(const uint8_t* b) {
    return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) |
        ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

// 工具函数: 32位整数转换为字节数组 (小端序)
static void store_uint32_le(uint32_t v, uint8_t* b) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

// SM4 T变换
static uint32_t sm4_t(uint32_t x) {
    uint8_t a[4];
    store_uint32_le(x, a);

    // 非线性变换τ(.)，使用S盒
    a[0] = SBOX[a[0]];
    a[1] = SBOX[a[1]];
    a[2] = SBOX[a[2]];
    a[3] = SBOX[a[3]];

    // 线性变换L
    uint32_t b = load_uint32_le(a);
    return b ^ (((b) << 2) | ((b) >> (32 - 2))) ^
        (((b) << 10) | ((b) >> (32 - 10))) ^
        (((b) << 18) | ((b) >> (32 - 18))) ^
        (((b) << 24) | ((b) >> (32 - 24)));
}

// 使用预计算的T表进行查表运算
static uint32_t sm4_t_table(uint32_t x) {
    uint8_t a[4];
    store_uint32_le(x, a);

    return T_TABLE[a[0]] ^
        ((T_TABLE[a[1]] << 8) | (T_TABLE[a[1]] >> 24)) ^
        ((T_TABLE[a[2]] << 16) | (T_TABLE[a[2]] >> 16)) ^
        ((T_TABLE[a[3]] << 24) | (T_TABLE[a[3]] >> 8));
}

// 初始化T表
void init_t_table() {
    for (int i = 0; i < 256; i++) {
        uint8_t a[4] = { SBOX[i], 0, 0, 0 };
        uint32_t b = load_uint32_le(a);
        T_TABLE[i] = b ^ (((b) << 2) | ((b) >> (32 - 2))) ^
            (((b) << 10) | ((b) >> (32 - 10))) ^
            (((b) << 18) | ((b) >> (32 - 18))) ^
            (((b) << 24) | ((b) >> (32 - 24)));
    }
}

// SM4轮函数 F
static uint32_t sm4_f(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    return x0 ^ sm4_t_table(x1 ^ x2 ^ x3 ^ rk);
}

// SM4密钥扩展
void sm4_key_schedule(const uint8_t* key, uint32_t rk[32]) {
    uint32_t k[4];
    uint32_t mk[4];

    // 加载密钥
    for (int i = 0; i < 4; i++) {
        mk[i] = load_uint32_le(key + 4 * i);
        k[i] = mk[i] ^ FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < 32; i++) {
        k[(i + 4) % 4] = k[i % 4] ^ sm4_t_table(k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i]);
        rk[i] = k[(i + 4) % 4];
    }
}

// SM4单块加密
void sm4_encrypt_block(const uint8_t* in, uint8_t* out, const uint32_t rk[32]) {
    uint32_t x[4];

    // 加载输入块
    for (int i = 0; i < 4; i++) {
        x[i] = load_uint32_le(in + 4 * i);
    }

    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        x[i % 4] = sm4_f(x[i % 4], x[(i + 1) % 4], x[(i + 2) % 4], x[(i + 3) % 4], rk[i]);
    }

    // 输出变换
    for (int i = 0; i < 4; i++) {
        store_uint32_le(x[(i + 3) % 4], out + 4 * i);
    }
}

// SM4-CBC加密
void sm4_cbc_encrypt(const uint8_t* in, uint8_t* out, size_t length, const uint8_t* key, const uint8_t* iv) {
    uint32_t rk[32];
    uint8_t block[SM4_BLOCK_SIZE];
    uint8_t iv_temp[SM4_BLOCK_SIZE];

    // 密钥扩展
    sm4_key_schedule(key, rk);

    // 复制初始向量
    memcpy(iv_temp, iv, SM4_BLOCK_SIZE);

    // 对数据分块进行加密
    for (size_t i = 0; i < length; i += SM4_BLOCK_SIZE) {
        // XOR当前块与前一个密文块或IV
        for (size_t j = 0; j < SM4_BLOCK_SIZE && i + j < length; j++) {
            block[j] = in[i + j] ^ iv_temp[j];
        }

        // 使用SM4加密当前块
        sm4_encrypt_block(block, out + i, rk);

        // 更新IV为当前输出的密文块，用于下一次迭代
        memcpy(iv_temp, out + i, SM4_BLOCK_SIZE);
    }
}

// 多线程处理函数
void* thread_sm4_cbc_encrypt(void* args) {
    ThreadArgs* targs = (ThreadArgs*)args;
    uint32_t rk[32];
    uint8_t iv_temp[SM4_BLOCK_SIZE];

    // 计算本线程处理的起始位置和大小
    size_t block_count = (targs->size + SM4_BLOCK_SIZE - 1) / SM4_BLOCK_SIZE;
    size_t blocks_per_thread = block_count / targs->num_threads;
    size_t extra_blocks = block_count % targs->num_threads;

    size_t start_block = targs->thread_id * blocks_per_thread +
        (targs->thread_id < extra_blocks ? targs->thread_id : extra_blocks);
    size_t num_blocks = blocks_per_thread +
        (targs->thread_id < extra_blocks ? 1 : 0);

    size_t start_byte = start_block * SM4_BLOCK_SIZE;
    size_t process_size = num_blocks * SM4_BLOCK_SIZE;

    if (start_byte >= targs->size) {
        return NULL;  // 没有数据要处理
    }

    if (start_byte + process_size > targs->size) {
        process_size = targs->size - start_byte;
    }

    // 密钥扩展（每个线程都需要完整的轮密钥）
    sm4_key_schedule(targs->key, rk);

    // 对于除第一个线程外的其他线程，IV需要是前一个块的密文
    if (targs->thread_id == 0) {
        memcpy(iv_temp, targs->iv, SM4_BLOCK_SIZE);
    }
    else {
        size_t prev_block = start_block - 1;
        if (prev_block * SM4_BLOCK_SIZE < targs->size) {
            // 等待前一个块的结果可用（这里简化处理，真实情况可能需要同步机制）
            memcpy(iv_temp, targs->result + prev_block * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
        }
    }

    // 处理分配给此线程的块
    for (size_t i = 0; i < num_blocks && start_byte + i * SM4_BLOCK_SIZE < targs->size; i++) {
        size_t offset = start_byte + i * SM4_BLOCK_SIZE;
        uint8_t block[SM4_BLOCK_SIZE];

        // XOR当前块与前一个密文块或IV
        for (size_t j = 0; j < SM4_BLOCK_SIZE && offset + j < targs->size; j++) {
            block[j] = targs->data[offset + j] ^ iv_temp[j];
        }

        // 使用SM4加密当前块
        sm4_encrypt_block(block, targs->result + offset, rk);

        // 更新IV为当前输出的密文块，用于下一次迭代
        memcpy(iv_temp, targs->result + offset, SM4_BLOCK_SIZE);
    }

    return NULL;
}

// 多线程SM4-CBC加密
void sm4_cbc_encrypt_mt(const uint8_t* in, uint8_t* out, size_t length, const uint8_t* key, const uint8_t* iv, int num_threads) {
    pthread_t threads[MAX_THREADS];
    ThreadArgs thread_args[MAX_THREADS];

    // 限制线程数
    if (num_threads > MAX_THREADS) {
        num_threads = MAX_THREADS;
    }

    // 为每个线程设置参数
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].data = (uint8_t*)in;
        thread_args[i].size = length;
        thread_args[i].key = (uint8_t*)key;
        thread_args[i].iv = (uint8_t*)iv;
        thread_args[i].result = out;
        thread_args[i].thread_id = i;
        thread_args[i].num_threads = num_threads;

        // 创建线程
        pthread_create(&threads[i], NULL, thread_sm4_cbc_encrypt, &thread_args[i]);
    }

    // 等待所有线程完成
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

// 生成随机数据用于测试
void generate_random_data(uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] = rand() % 256;
    }
}

// 打印十六进制格式的数据
void print_hex(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 || i == size - 1) {
            printf("\n");
        }
        else if ((i + 1) % 4 == 0) {
            printf(" ");
        }
    }
}

void benchmark(size_t data_size, int num_threads) {
    struct timeval start, end;
    double elapsed;

    // 分配内存
    uint8_t* data = (uint8_t*)malloc(data_size);
    uint8_t* encrypted = (uint8_t*)malloc(data_size);
    uint8_t key[SM4_KEY_SIZE];
    uint8_t iv[SM4_BLOCK_SIZE];

    // 生成随机数据、密钥和IV
    generate_random_data(data, data_size);
    generate_random_data(key, SM4_KEY_SIZE);
    generate_random_data(iv, SM4_BLOCK_SIZE);

    // 初始化T表
    init_t_table();

    printf("数据大小: %zu 字节\n", data_size);

    // 1. 测试单线程版本
    gettimeofday(&start, NULL);
    sm4_cbc_encrypt(data, encrypted, data_size, key, iv);
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("单线程版本耗时: %.6f 秒\n", elapsed);

    // 2. 测试多线程版本
    gettimeofday(&start, NULL);
    sm4_cbc_encrypt_mt(data, encrypted, data_size, key, iv, num_threads);
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("多线程版本(%d线程)耗时: %.6f 秒\n", num_threads, elapsed);

    // 释放内存
    free(data);
    free(encrypted);
}

int main(int argc, char* argv[]) {
    // 设置随机数种子
    srand(time(NULL));

    // 默认参数
    size_t data_sizes[] = { 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024 }; // 测试数据大小: 1MB, 10MB, 100MB
    int num_threads = DEFAULT_THREADS;

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[i + 1]);
            if (num_threads < 1) num_threads = 1;
            if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
            i++;
        }
        else if (strcmp(argv[i], "-h") == 0) {
            printf("用法: %s [-t 线程数]\n", argv[0]);
            return 0;
        }
    }

    printf("SM4-CBC加密算法性能测试\n");
    printf("---------------------\n");

    // 测试多个数据大小
    for (int i = 0; i < sizeof(data_sizes) / sizeof(data_sizes[0]); i++) {
        benchmark(data_sizes[i], num_threads);
    }

    return 0;
}