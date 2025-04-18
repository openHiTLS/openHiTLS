#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include <sched.h>
#include <assert.h>          // 新增头文件

// 配置参数
#define BLOCK_SIZE          16
#define CACHE_LINE_SIZE     64
#define MAX_THREADS         8
#define ALIGNMENT           CACHE_LINE_SIZE

// 内存屏障宏（RISC-V兼容）
#define COMPILER_BARRIER()  __asm__ __volatile__("" ::: "memory")
#define FULL_MEMORY_BARRIER() __sync_synchronize()

// 预计算加速表（缓存行对齐）
__attribute__((aligned(ALIGNMENT))) 
static uint32_t T_table[256];
static int tables_initialized = 0;

// SM4常量（对齐到缓存行）
__attribute__((aligned(ALIGNMENT))) static const uint32_t FK[4] = { 
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc 
};

__attribute__((aligned(ALIGNMENT))) static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

__attribute__((aligned(ALIGNMENT))) static const uint8_t Sbox[256] = {
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

/* 内存分配封装（强制对齐） */
void* aligned_alloc_wrapper(size_t size) {
    void *ptr;
    if(posix_memalign(&ptr, ALIGNMENT, size) != 0) {
        perror("posix_memalign failed");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/* 缓存预热 */
void cache_warmup() {
    uint8_t dummy = 0;
    for(int i=0; i<sizeof(T_table); i+=CACHE_LINE_SIZE) {
        dummy += ((volatile uint8_t*)T_table)[i];
    }
    (void)dummy;
}

/* 初始化预计算表 */
void init_tables() {
    if(tables_initialized) return;
    
    for(int i=0; i<256; i++){
        uint32_t a = Sbox[i];
        uint32_t b = (a << 24) | (a << 16) | (a << 8) | a;
        T_table[i] = b ^ ((b << 2) | (b >> 30)) ^ 
                    ((b << 10) | (b >> 22)) ^ 
                    ((b << 18) | (b >> 14)) ^ 
                    ((b << 24) | (b >> 8));
    }
    FULL_MEMORY_BARRIER();
    tables_initialized = 1;
}

/* 优化的T函数 */
static inline uint32_t T(uint32_t x) {
    uint32_t ret;
    ret  = T_table[(x >> 24) & 0xff];
    ret ^= T_table[(x >> 16) & 0xff];
    ret ^= T_table[(x >> 8)  & 0xff];
    ret ^= T_table[x & 0xff];
    COMPILER_BARRIER();
    return ret;
}

/* 密钥扩展 */
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36] __attribute__((aligned(ALIGNMENT)));
    
    const uint32_t *key32 = (const uint32_t*)key;
    K[0] = __builtin_bswap32(key32[0]) ^ FK[0];
    K[1] = __builtin_bswap32(key32[1]) ^ FK[1];
    K[2] = __builtin_bswap32(key32[2]) ^ FK[2];
    K[3] = __builtin_bswap32(key32[3]) ^ FK[3];

    for(int i=0; i<32; i+=4){
        uint32_t tmp0 = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        uint32_t tmp1 = K[i+2] ^ K[i+3] ^ K[i+4] ^ CK[i+1];
        uint32_t tmp2 = K[i+3] ^ K[i+4] ^ K[i+5] ^ CK[i+2];
        uint32_t tmp3 = K[i+4] ^ K[i+5] ^ K[i+6] ^ CK[i+3];
        
        tmp0 = T(tmp0);
        tmp1 = T(tmp1);
        tmp2 = T(tmp2);
        tmp3 = T(tmp3);
        
        K[i+4] = K[i]   ^ (tmp0 << 13) ^ (tmp0 >> 19);
        K[i+5] = K[i+1] ^ (tmp1 << 13) ^ (tmp1 >> 19);
        K[i+6] = K[i+2] ^ (tmp2 << 13) ^ (tmp2 >> 19);
        K[i+7] = K[i+3] ^ (tmp3 << 13) ^ (tmp3 >> 19);
        
        rk[i]   = K[i+4];
        rk[i+1] = K[i+5];
        rk[i+2] = K[i+6];
        rk[i+3] = K[i+7];
    }
}

/* 加密块 */
void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36] __attribute__((aligned(ALIGNMENT)));
    
    const uint32_t *in32 = (const uint32_t*)in;
    X[0] = __builtin_bswap32(in32[0]);
    X[1] = __builtin_bswap32(in32[1]);
    X[2] = __builtin_bswap32(in32[2]);
    X[3] = __builtin_bswap32(in32[3]);

    #define ROUND(i) \
        X[i+4] = X[i] ^ T(X[i+1]^X[i+2]^X[i+3]^rk[i])
    
    ROUND(0);  ROUND(1);  ROUND(2);  ROUND(3);
    ROUND(4);  ROUND(5);  ROUND(6);  ROUND(7);
    ROUND(8);  ROUND(9);  ROUND(10); ROUND(11);
    ROUND(12); ROUND(13); ROUND(14); ROUND(15);
    ROUND(16); ROUND(17); ROUND(18); ROUND(19);
    ROUND(20); ROUND(21); ROUND(22); ROUND(23);
    ROUND(24); ROUND(25); ROUND(26); ROUND(27);
    ROUND(28); ROUND(29); ROUND(30); ROUND(31);
    
    uint32_t *out32 = (uint32_t*)out;
    out32[0] = __builtin_bswap32(X[35]);
    out32[1] = __builtin_bswap32(X[34]);
    out32[2] = __builtin_bswap32(X[33]);
    out32[3] = __builtin_bswap32(X[32]);
}

/* 块异或操作 */
static inline void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    uint64_t *d64 = (uint64_t*)dst;
    const uint64_t *a64 = (const uint64_t*)a;
    const uint64_t *b64 = (const uint64_t*)b;
    d64[0] = a64[0] ^ b64[0];
    d64[1] = a64[1] ^ b64[1];
}

/* 线程参数结构 */
typedef struct {
    const uint8_t *input;
    uint8_t *output;
    size_t start_block;
    size_t num_blocks;
    const uint32_t *rk;
    uint8_t iv[BLOCK_SIZE];
    uint8_t final_iv[BLOCK_SIZE];
    pthread_barrier_t *barrier;
} __attribute__((aligned(ALIGNMENT))) ThreadData;

/* 加密分段 */
void* encrypt_segment(void *arg) {
    ThreadData *data = (ThreadData*)arg;
    uint8_t prev_iv[BLOCK_SIZE] __attribute__((aligned(ALIGNMENT)));
    uint8_t block[BLOCK_SIZE] __attribute__((aligned(ALIGNMENT)));
    
    memcpy(prev_iv, data->iv, BLOCK_SIZE);
    pthread_barrier_wait(data->barrier);

    for(size_t i=0; i<data->num_blocks; i++){
        const uint8_t *in_ptr = data->input + (data->start_block + i)*BLOCK_SIZE;
        uint8_t *out_ptr = data->output + (data->start_block + i)*BLOCK_SIZE;
        
        xor_block(block, in_ptr, prev_iv);
        sm4_encrypt_block(block, out_ptr, data->rk);
        memcpy(prev_iv, out_ptr, BLOCK_SIZE);
    }
    
    memcpy(data->final_iv, prev_iv, BLOCK_SIZE);
    return NULL;
}

/* CBC加密 */
void sm4_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, 
                    const uint8_t key[16], const uint8_t iv[16], int threads) {
    assert(len % BLOCK_SIZE == 0);
    static pthread_barrier_t barrier;
    uint32_t rk[32] __attribute__((aligned(ALIGNMENT)));
    sm4_key_schedule(key, rk);
    
    ThreadData *args = aligned_alloc_wrapper(threads * sizeof(ThreadData));
    pthread_t *tids = aligned_alloc_wrapper(threads * sizeof(pthread_t));
    
    size_t total_blocks = len / BLOCK_SIZE;
    size_t blocks_per_thread = total_blocks / threads;
    size_t remaining = total_blocks % threads;
    uint8_t current_iv[BLOCK_SIZE];
    memcpy(current_iv, iv, BLOCK_SIZE);
    
    pthread_barrier_init(&barrier, NULL, threads+1);

    for(int i=0; i<threads; i++){
        args[i].input = in;
        args[i].output = out;
        args[i].rk = rk;
        args[i].start_block = i * blocks_per_thread;
        args[i].num_blocks = blocks_per_thread + (i < remaining ? 1 : 0);
        args[i].barrier = &barrier;
        memcpy(args[i].iv, current_iv, BLOCK_SIZE);
        
        size_t last_block = args[i].start_block + args[i].num_blocks;
        const uint8_t *last_cipher = out + (last_block-1)*BLOCK_SIZE;
        memcpy(current_iv, last_cipher, BLOCK_SIZE);
        
        pthread_create(&tids[i], NULL, encrypt_segment, &args[i]);
    }
    
    pthread_barrier_wait(&barrier);
    for(int i=0; i<threads; i++) pthread_join(tids[i], NULL);
    
    free(args);
    free(tids);
    pthread_barrier_destroy(&barrier);
}

/* 随机数生成（替代arc4random_buf） */
void secure_random(uint8_t *buf, size_t size) {
    FILE *f = fopen("/dev/urandom", "rb");
    assert(f != NULL);
    fread(buf, 1, size, f);
    fclose(f);
}

/* 高精度计时器 */
static double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* 性能测试 */
void performance_test(size_t data_size_mb, int max_threads) {
    const uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                           0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const uint8_t iv[16] = {0};
    size_t data_size = data_size_mb * 1024 * 1024;
    
    // 添加基准时间变量声明
    double baseline_time = 0.0;  // 单线程基准时间
    
    uint8_t *plain = aligned_alloc_wrapper(data_size);
    uint8_t *cipher = aligned_alloc_wrapper(data_size);
    secure_random(plain, data_size);

    // 预热运行
    sm4_cbc_encrypt(plain, cipher, BLOCK_SIZE, key, iv, 1);
    cache_warmup();

    printf("\n=== 测试开始 数据量: %zuMB ===\n", data_size_mb);
    for(int t=1; t<=max_threads; t++){
        double total_time = 0;
        double speed_ratio = 0.0; // 添加速度比变量声明
        int runs = (data_size_mb < 100) ? 5 : 3;

        for(int i=0; i<runs; i++){
            double start = get_time();
            sm4_cbc_encrypt(plain, cipher, data_size, key, iv, t);
            total_time += get_time() - start;
            if(i != runs-1) memset(cipher, 0, data_size);
        }

        double avg_time = total_time / runs;
        
        // 加速比计算逻辑
        if(t == 1) {
            baseline_time = avg_time;
            speed_ratio = 1.0; 
        } else {
            speed_ratio = baseline_time / avg_time;
        }

        printf("| 线程 %-2d | 耗时: %-6.4fs | 吞吐率: %7.2f MB/s | 加速比: %5.2fx |\n",
              t, avg_time, data_size_mb / avg_time, speed_ratio);
    }
    
    free(plain);
    free(cipher);
    printf("=== 测试结束 ===\n\n");
}
/* 命令行参数解析 */
int main(int argc, char **argv) {
    init_tables();
    
    // 默认测试模式
    int test_mode = 0;
    if(argc > 1) test_mode = atoi(argv[1]);
    
    switch(test_mode){
        case 0:  // 完整测试套件
            performance_test(1, 4);     // 快速测试
            performance_test(100, 8);   // 压力测试
            break;
            
        case 1: { // 自定义测试
            if(argc < 4){
                printf("用法: %s 1 <数据量MB> <最大线程数>\n", argv[0]);
                return 1;
            }
            size_t size = atoi(argv[2]);
            int threads = atoi(argv[3]);
            performance_test(size, threads);
            break;
        }
            
        case 2:  // 验证测试
            printf("运行基础加密验证...\n");
            // 添加标准测试向量验证
            // [此处可添加NIST标准测试向量验证代码]
            break;
            
        default:
            printf("无效测试模式\n");
            return 1;
    }
    
    return 0;
}

