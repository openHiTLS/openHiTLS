#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
/*================== 数据转换与位运算宏定义 ==================*/
#define GET_UINT32_BE(n, b, i) do {                        \
    (n) = ((uint32_t)(b)[(i)] << 24)                       \
        | ((uint32_t)(b)[(i)+1] << 16)                     \
        | ((uint32_t)(b)[(i)+2] << 8)                      \
        | ((uint32_t)(b)[(i)+3]);                          \
} while (0)

#define PUT_UINT32_BE(n, b, i) do {                        \
    (b)[(i)]   = (unsigned char)((n) >> 24);              \
    (b)[(i)+1] = (unsigned char)((n) >> 16);              \
    (b)[(i)+2] = (unsigned char)((n) >> 8);               \
    (b)[(i)+3] = (unsigned char)(n);                      \
} while (0)

#define SHL(x, n) (((x) & 0xFFFFFFFF) << (n))
#define ROTL(x, n) (SHL((x), n) | ((x) >> (32 - (n))))

/*================== SM4 上下文定义 ==================*/
typedef struct {
    int mode;               /* 模式：1 为加密，0 为解密 */
    uint32_t sk[32];        /* 轮密钥 */
} sm4_context;

/*================== SM4 算法常量 ==================*/
/* S盒：二维数组定义，确保访问时不会越界 */
static const unsigned char SboxTable[16][16] = {
    {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
    {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
    {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
    {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
    {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
    {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
    {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
    {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
    {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
    {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
    {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
    {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
    {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
    {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
    {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
    {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
};

/* 系统参数 FK 与轮常量 CK */
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

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

/*================== 辅助函数 ==================*/
/* S盒替换：利用二维数组索引计算，防止越界 */
static unsigned char sm4Sbox(unsigned char inch)
{
    uint32_t row = inch >> 4;
    uint32_t col = inch & 0x0F;
    return SboxTable[row][col];
}

/*
 * 线性变换T函数（包含S盒替换与循环左移）
 */
static uint32_t sm4Lt(uint32_t ka)
{
    uint32_t bb = 0, c = 0;
    unsigned char a[4], b[4];
    PUT_UINT32_BE(ka, a, 0);
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_UINT32_BE(bb, b, 0);
    c = bb ^ ROTL(bb, 2) ^ ROTL(bb, 10) ^ ROTL(bb, 18) ^ ROTL(bb, 24);
    return c;
}

/*
 * F函数：利用4个32位数据和轮密钥进行运算
 */
static uint32_t sm4F(uint32_t x0, uint32_t x1, uint32_t x2,
    uint32_t x3, uint32_t rk)
{
    return x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk);
}

/*
 * 计算轮密钥：利用非线性变换与循环左移
 */
static uint32_t sm4CalciRK(uint32_t ka)
{
    uint32_t bb = 0, rk = 0;
    unsigned char a[4], b[4];
    PUT_UINT32_BE(ka, a, 0);
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_UINT32_BE(bb, b, 0);
    rk = bb ^ ROTL(bb, 13) ^ ROTL(bb, 23);
    return rk;
}

/*
 * 轮密钥生成函数：
 * 输入 128 位密钥，生成 32 个 32 位轮密钥
 */
static void sm4_setkey(uint32_t SK[32], unsigned char key[16])
{
    uint32_t MK[4], k[36];
    int i;
    GET_UINT32_BE(MK[0], key, 0);
    GET_UINT32_BE(MK[1], key, 4);
    GET_UINT32_BE(MK[2], key, 8);
    GET_UINT32_BE(MK[3], key, 12);
    k[0] = MK[0] ^ FK[0];
    k[1] = MK[1] ^ FK[1];
    k[2] = MK[2] ^ FK[2];
    k[3] = MK[3] ^ FK[3];
    for (i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        SK[i] = k[i + 4];
    }
}

/*
 * 设置加密密钥
 */
void sm4_setkey_enc(sm4_context* ctx, unsigned char key[16])
{
    ctx->mode = 1;
    sm4_setkey(ctx->sk, key);
}

/*
 * 单块加密函数：
 * 对 16 字节数据块（经过异或IV后）做 32 轮 SM4 运算
 */
static void sm4_one_round(uint32_t sk[32],
    unsigned char input[16],
    unsigned char output[16])
{
    int i;
    uint32_t ulbuf[36];
    memset(ulbuf, 0, sizeof(ulbuf));
    GET_UINT32_BE(ulbuf[0], input, 0);
    GET_UINT32_BE(ulbuf[1], input, 4);
    GET_UINT32_BE(ulbuf[2], input, 8);
    GET_UINT32_BE(ulbuf[3], input, 12);
    for (i = 0; i < 32; i++) {
        ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], sk[i]);
    }
    PUT_UINT32_BE(ulbuf[35], output, 0);
    PUT_UINT32_BE(ulbuf[34], output, 4);
    PUT_UINT32_BE(ulbuf[33], output, 8);
    PUT_UINT32_BE(ulbuf[32], output, 12);
}

/*================== PKCS#7 填充 ==================*/
/*
 * PKCS#7 填充：返回填充后数据，新长度存入 out_len，
 * 内存由调用者释放。
 */
unsigned char* pkcs7_padding(const unsigned char* input, int len, int block_size, int* out_len)
{
    int padding = block_size - (len % block_size);
    int new_len = len + padding;
    unsigned char* output = (unsigned char*)malloc(new_len);
    if (!output) return NULL;
    memcpy(output, input, len);
    memset(output + len, padding, padding);
    *out_len = new_len;
    return output;
}

/*================== 辅助打印函数 ==================*/
void print_hex(const unsigned char* data, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", data[i]);
    printf("\n");
}







/*------------------- 用于段加密的线程参数 -------------------*/
typedef struct {
    int seg_index;
    int start_block;
    int end_block;
    unsigned char* padded;
    unsigned char* ciphertext;
    unsigned char* iv;
    sm4_context* ctx;
} segment_arg_t;

pthread_mutex_t seg_mutex[4];
pthread_cond_t seg_cond[4];
int seg_done[4] = { 0, 0, 0, 0 };

void* encrypt_segment_thread(void* arg)
{
    segment_arg_t* targ = (segment_arg_t*)arg;
    int seg = targ->seg_index;

    if (seg > 0) {
        pthread_mutex_lock(&seg_mutex[seg - 1]);
        while (seg_done[seg - 1] == 0) {
            pthread_cond_wait(&seg_cond[seg - 1], &seg_mutex[seg - 1]);
        }
        pthread_mutex_unlock(&seg_mutex[seg - 1]);

        int prev_last_block = targ->start_block - 1;
        targ->iv = targ->ciphertext + prev_last_block * 16;
    }

    unsigned char current_iv[16];
    memcpy(current_iv, targ->iv, 16);

    for (int i = targ->start_block; i < targ->end_block; i++) {
        unsigned char in_temp[16];
        unsigned char* plaintext_block = targ->padded + i * 16;
        unsigned char* ciphertext_block = targ->ciphertext + i * 16;


        for (int j = 0; j < 16; j++) {
            in_temp[j] = plaintext_block[j] ^ current_iv[j];
        }
        sm4_one_round(targ->ctx->sk, in_temp, ciphertext_block);


        memcpy(current_iv, ciphertext_block, 16);
    }

    pthread_mutex_lock(&seg_mutex[seg]);
    seg_done[seg] = 1;
    pthread_cond_signal(&seg_cond[seg]);
    pthread_mutex_unlock(&seg_mutex[seg]);

    free(targ);
    pthread_exit(NULL);
}

unsigned char* read_file(const char* filename, int* out_len) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("打开文件 %s 失败！\n", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    rewind(fp);

    unsigned char* buf = (unsigned char*)malloc(len + 1);
    if (!buf) {
        printf("内存分配失败！\n");
        fclose(fp);
        return NULL;
    }

    if (fread(buf, 1, len, fp) != (size_t)len) {
        printf("读取文件失败！\n");
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[len] = '\0';
    fclose(fp);
    *out_len = (int)len;
    return buf;
}

/*------------------- 主函数 -------------------*/
int main(void)
{

    unsigned char key[16] = { 0x01, 0x23, 0x45, 0x67,
                              0x89, 0xAB, 0xCD, 0xEF,
                              0xFE, 0xDC, 0xBA, 0x98,
                              0x76, 0x54, 0x32, 0x10 };

    unsigned char iv[16] = { 0 };


    int file_len;
    unsigned char* file_content = read_file("msg1.txt", &file_len);
    if (!file_content) {
        return -1;
    }
    //printf("从文件读取的明文 (%d 字节):\n%s\n", file_len, file_content);
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);  // 记录开始时间

    int padded_len;
    unsigned char* padded = pkcs7_padding(file_content, file_len, 16, &padded_len);
    if (!padded) {
        free(file_content);
        printf("内存分配失败！\n");
        return -1;
    }
    free(file_content);

    int num_blocks = padded_len / 16;
    //printf("填充后的数据 (%d 字节):\n", padded_len);
    //print_hex(padded, padded_len);
    sm4_context ctx;
    sm4_setkey_enc(&ctx, key);

    unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
    if (!ciphertext) {
        free(padded);
        printf("内存分配失败！\n");
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        pthread_mutex_init(&seg_mutex[i], NULL);
        pthread_cond_init(&seg_cond[i], NULL);
        seg_done[i] = 0;
    }

    pthread_t threads[4];

    int base = num_blocks / 4;
    int rem = num_blocks % 4;
    int start = 0;



    for (int i = 0; i < 4; i++) {
        segment_arg_t* targ = malloc(sizeof(segment_arg_t));
        if (!targ) {
            printf("内存分配失败！\n");
            exit(-1);
        }
        targ->seg_index = i;
        targ->start_block = start;
        int seg_blocks = base + (i < rem ? 1 : 0);
        targ->end_block = start + seg_blocks;
        targ->padded = padded;
        targ->ciphertext = ciphertext;
        /* 段0使用外部 IV，其他段由线程内部获取上一段的密文块 */
        targ->iv = (i == 0) ? iv : NULL;
        targ->ctx = &ctx;

        if (pthread_create(&threads[i], NULL, encrypt_segment_thread, targ) != 0) {
            printf("创建线程失败！\n");
            exit(-1);
        }
        start += seg_blocks;
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    gettimeofday(&end_time, NULL);  // 记录结束时间

    double enc_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1e6;
    printf("所有消息加密完毕，总耗时: %f 秒\n", enc_time);


    for (int i = 0; i < 4; i++) {
        pthread_mutex_destroy(&seg_mutex[i]);
        pthread_cond_destroy(&seg_cond[i]);
    }
    free(padded);
    free(ciphertext);

    return 0;
}