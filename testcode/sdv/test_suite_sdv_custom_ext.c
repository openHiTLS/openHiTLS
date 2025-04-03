#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h>
#include <regex.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/ioctl.h>
#include "securec.h"
#include "bsl_sal.h"
#include "sal_net.h"
#include "frame_tls.h"
#include "cert_callback.h"
#include "hitls_config.h"
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "frame_io.h"
#include "uio_abstraction.h"
#include "tls.h"
#include "tls_config.h"
#include "logger.h"
#include "process.h"
#include "hs_ctx.h"
#include "hlt.h"
#include "stub_replace.h"
#include "hitls_type.h"
#include "frame_link.h"
#include "session_type.h"
#include "common_func.h"
#include "hitls_func.h"
#include "hitls_cert_type.h"
#include "cert_mgr_ctx.h"
#include "parser_frame_msg.h"
#include "recv_process.h"
#include "simulate_io.h"
#include "rec_wrapper.h"
#include "cipher_suite.h"
#include "alert.h"
#include "conn_init.h"
#include "pack.h"
#include "send_process.h"
#include "cert.h"
#include "hitls_cert_reg.h"
#include "hitls_crypt_type.h"
#include "hs.h"
#include "hs_state_recv.h"
#include "app.h"
#include "record.h"
#include "rec_conn.h"
#include "session.h"
#include "frame_msg.h"
#include "pack_frame_msg.h"
#include "cert_mgr.h"
#include "hs_extensions.h"
#include "hlt_type.h"
#include "sctp_channel.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "hitls_crypt_reg.h"
#include "crypt_errno.h"
#include "bsl_list.h"
#include "hitls_cert.h"
#inlcude "custom_extensions.h"
#inlcude "custom_extensions.c"

// 测试 PackCustomExtensions 函数
void SDV_TLS_PACK_CUSTOM_EXT_FUNC_TC001(void) {
    TLS_Ctx ctx = {0};  // 假设 TLS_Ctx 已定义
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;  // 自定义扩展类型

    // 初始化 ctx（此处简化为假设已有自定义扩展方法）
    custom_ext_methods exts = {0};
    custom_ext_method meth = {0};
    meth.ext_type = type;
    meth.context = type;
    meth.add_cb = NULL;  // 模拟无回调的情况
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.custext = &exts;

    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    TEST_ASSERT_EQUAL(ret, HITLS_SUCCESS);  // 验证返回成功
    TEST_ASSERT_EQUAL(len, 1);  // 验证长度（仅包含 ext_type）
    TEST_ASSERT_EQUAL(buf[0], type);  // 验证打包内容
}

// 测试 ParseCustomExtensions 函数
void SDV_TLS_PARSE_CUSTOM_EXT_FUNC_TC001(void) {
    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {1, 0, 0, 0, 0};  // ext_type=1, len=0（模拟空数据）
    uint32_t bufOffset = 0;
    uint8_t type = 1;

    // 初始化 ctx
    custom_ext_methods exts = {0};
    custom_ext_method meth = {0};
    meth.ext_type = type;
    meth.parse_cb = NULL;  // 模拟无回调
    exts.meths = &meth;
    exts.meths_count = 1;
    ctx.custext = &exts;

    int32_t ret = ParseCustomExtensions(&ctx, buf, &bufOffset, type);
    TEST_ASSERT_EQUAL(ret, HITLS_SUCCESS);  // 验证返回成功
    TEST_ASSERT_EQUAL(bufOffset, 5);  // 验证偏移（ext_type + len）
}

// 测试多个自定义扩展的打包
void SDV_TLS_PACK_CUSTOM_EXT_MULTIPLE_TC001(void) {
    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    // 初始化多个扩展
    custom_ext_methods exts = {0};
    custom_ext_method meths[2] = {{0}, {0}};
    meths[0].ext_type = 1;
    meths[0].context = type;
    meths[1].ext_type = 2;
    meths[1].context = type;
    exts.meths = meths;
    exts.meths_count = 2;
    ctx.custext = &exts;

    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    TEST_ASSERT_EQUAL(ret, HITLS_SUCCESS);
    TEST_ASSERT_EQUAL(len, 2);  // 两个 ext_type
    TEST_ASSERT_EQUAL(buf[0], 1);
    TEST_ASSERT_EQUAL(buf[1], 2);
}

// 测试空扩展的情况
void SDV_TLS_PACK_CUSTOM_EXT_EMPTY_TC001(void) {
    TLS_Ctx ctx = {0};
    uint8_t buf[1024] = {0};
    uint32_t bufLen = sizeof(buf);
    uint32_t len = 0;
    uint8_t type = 1;

    ctx.custext = NULL;  // 无扩展

    int32_t ret = PackCustomExtensions(&ctx, buf, bufLen, &len, type);
    TEST_ASSERT_EQUAL(ret, HITLS_SUCCESS);
    TEST_ASSERT_EQUAL(len, 0);  // 长度应为 0
}

int main(void) {
    TEST_AddTest("SDV_TLS_PACK_CUSTOM_EXT_FUNC_TC001", SDV_TLS_PACK_CUSTOM_EXT_FUNC_TC001);
    TEST_AddTest("SDV_TLS_PARSE_CUSTOM_EXT_FUNC_TC001", SDV_TLS_PARSE_CUSTOM_EXT_FUNC_TC001);
    TEST_AddTest("SDV_TLS_PACK_CUSTOM_EXT_MULTIPLE_TC001", SDV_TLS_PACK_CUSTOM_EXT_MULTIPLE_TC001);
    TEST_AddTest("SDV_TLS_PACK_CUSTOM_EXT_EMPTY_TC001", SDV_TLS_PACK_CUSTOM_EXT_EMPTY_TC001);
    TEST_RunAll();
    return 0;
}
