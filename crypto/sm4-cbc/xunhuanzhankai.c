#include <stdio.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif


static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5f, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
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


static const uint32_t FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};


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

/* 循环左移 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* S盒变换 */
static uint32_t tau(uint32_t x) {
    uint32_t b0 = SBOX[(x >> 24) & 0xFF];
    uint32_t b1 = SBOX[(x >> 16) & 0xFF];
    uint32_t b2 = SBOX[(x >> 8) & 0xFF];
    uint32_t b3 = SBOX[x & 0xFF];
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

/* 线性变换L */
static uint32_t L(uint32_t x) {
    return x ^ ROTL(x, 2) ^ ROTL(x, 10) ^ ROTL(x, 18) ^ ROTL(x, 24);
}

/* 密钥扩展线性变换L' */
static uint32_t L_prime(uint32_t x) {
    return x ^ ROTL(x, 13) ^ ROTL(x, 23);
}

/* 密钥扩展 */
void sm4_key_schedule(uint32_t* key, uint32_t* rk) {
    uint32_t k[36];
    for (int i = 0; i < 4; ++i) k[i] = key[i] ^ FK[i];

    for (int i = 0; i < 32; ++i) {
        k[i + 4] = k[i] ^ L_prime(tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
        rk[i] = k[i + 4];
    }
}

/* 原始加密函数 */
void sm4_encrypt_original(uint32_t* plain, uint32_t* cipher, uint32_t* rk) {
    uint32_t x[36];
    for (int i = 0; i < 4; ++i) x[i] = plain[i];

    for (int i = 0; i < 32; ++i) {
        x[i + 4] = x[i] ^ L(tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]));
    }

    for (int i = 0; i < 4; ++i) {
        cipher[i] = x[35 - i];
    }
}

/* 优化版本（4轮展开） */
void sm4_encrypt_unrolled(uint32_t* plain, uint32_t* cipher, uint32_t* rk) {
    uint32_t x[36];
    for (int i = 0; i < 4; ++i) x[i] = plain[i];

    for (int i = 0; i < 32; i += 4) {
        x[i + 4] = x[i] ^ L(tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]));
        x[i + 5] = x[i + 1] ^ L(tau(x[i + 2] ^ x[i + 3] ^ x[i + 4] ^ rk[i + 1]));
        x[i + 6] = x[i + 2] ^ L(tau(x[i + 3] ^ x[i + 4] ^ x[i + 5] ^ rk[i + 2]));
        x[i + 7] = x[i + 3] ^ L(tau(x[i + 4] ^ x[i + 5] ^ x[i + 6] ^ rk[i + 3]));
    }

    for (int i = 0; i < 4; ++i) {
        cipher[i] = x[35 - i];
    }
}

/* 高精度计时函数 */
double get_highres_time() {
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    if (!initialized) {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#endif
}

/* 性能测试函数 */
void test_performance(const char* name,
    void (*encrypt_func)(uint32_t*, uint32_t*, uint32_t*),
    uint32_t* plain,
    uint32_t* cipher,
    uint32_t* round_keys,
    size_t block_count,
    int base_iterations) {
    double start, end;
    double total_time;
    uint32_t dummy = 0;
    int actual_iterations = base_iterations;
    size_t block_size = 16; // SM4块大小为16字节

    // 动态调整迭代次数确保可测量
    while (1) {
        start = get_highres_time();
        for (int i = 0; i < actual_iterations; ++i) {
            for (size_t j = 0; j < block_count; ++j) {
                encrypt_func(plain, cipher, round_keys);
                dummy += cipher[0]; // 强制使用结果
            }
        }
        end = get_highres_time();

        total_time = end - start;
        if (total_time > 0.001 || actual_iterations > 1000000) break;
        actual_iterations *= 10;
    }

    size_t total_bytes = block_count * actual_iterations * block_size;
    double throughput = (total_time > 0) ? (total_bytes / (total_time * 1024 * 1024)) : 0;

    printf("【%s】\n", name);
    printf("数据块数: %zu | 迭代次数: %d\n", block_count, actual_iterations);
    printf("总数据量: %.2f MB\n", (double)total_bytes / (1024.0 * 1024));
    printf("耗时: %.6f 秒\n", total_time);
    if (total_time > 0) {
        printf("吞吐量: %.2f MB/秒\n\n", throughput);
    }
    else {
        printf("吞吐量: 无法测量（时间过短）\n\n");
    }
}

int main() {
    // 测试密钥和明文
    uint32_t key[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    uint32_t plain[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    uint32_t cipher[4] = { 0 };
    uint32_t round_keys[32];

    // 生成轮密钥
    sm4_key_schedule(key, round_keys);

    printf("=== SM4加密性能测试 ===\n");
    printf("测试平台: ");
#if defined(_WIN32)
    printf("Windows\n");
#else
    printf("Linux/Unix\n");
#endif
    printf("计时精度: ");
#if defined(_WIN32)
    printf("QueryPerformanceCounter\n");
#else
    printf("clock_gettime(CLOCK_MONOTONIC)\n");
#endif

    // 测试场景配置
    size_t test_blocks[] = { 64, 640, 6400, 64000, 640000 };
    int test_iterations[] = { 10000, 1000, 100, 10, 1 };

    for (int i = 0; i < 5; i++) {
        printf("\n===== 测试场景 %d/5 =====\n", i + 1);
        test_performance("原始版本", sm4_encrypt_original, plain, cipher, round_keys,
            test_blocks[i], test_iterations[i]);
        test_performance("优化版本", sm4_encrypt_unrolled, plain, cipher, round_keys,
            test_blocks[i], test_iterations[i]);
    }

    // 验证加解密正确性
    printf("\n=== 加密验证 ===\n");
    sm4_encrypt_unrolled(plain, cipher, round_keys);
    printf("加密结果: %08X %08X %08X %08X\n", cipher[0], cipher[1], cipher[2], cipher[3]);

    // 标准测试向量验证
    uint32_t test_key[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    uint32_t test_plain[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    uint32_t test_cipher[4] = { 0 };
    uint32_t test_rk[32];

    sm4_key_schedule(test_key, test_rk);
    sm4_encrypt_unrolled(test_plain, test_cipher, test_rk);
    printf("标准测试向量结果: %08X %08X %08X %08X\n",
        test_cipher[0], test_cipher[1], test_cipher[2], test_cipher[3]);

    return 0;
}

