# RFC8879 证书压缩设计说明

本目录用于记录 RFC8879 证书压缩功能的设计和测试说明，帮助后续贡献者快速理解当前实现边界、测试归属和后续补测方向。

包含内容如下：

- `设计说明.md`：RFC8879 功能背景、设计思路、当前实现现状、demo/SDV 执行定位以及后续补测建议。
- `测试用例清单.md`：当前 RFC8879 相关断言测试的场景、目标、预期结果与覆盖边界。
- `测试结果清单.md`：当前已执行测试项、执行方式、结果汇总以及与 `sdv_macos` 相关的脚本验证结果。

## 当前实现状态

从当前全局代码看，RFC8879 证书压缩已经具备以下实现能力：

1. 对外配置接口已经完整提供。
   在 `include/tls/hitls_config.h`、`include/tls/hitls.h` 以及对应实现中，已经提供：
   - 证书压缩开关
   - 算法列表配置
   - 压缩阈值配置
   - 最大解压长度配置

2. 已定义并支持标准算法 ID。
   当前代码已经定义：
   - `HITLS_CERT_COMPRESSION_ZLIB`
   - `HITLS_CERT_COMPRESSION_BROTLI`
   - `HITLS_CERT_COMPRESSION_ZSTD`

3. 默认配置与配置复制路径已经落地。
   在配置默认值与配置复制实现中，已经覆盖：
   - 默认关闭证书压缩
   - 默认压缩阈值
   - 默认最大解压长度
   - 配置深拷贝

4. TLS 1.3 客户端扩展打包与服务端扩展解析已经实现。
   当前代码已经支持：
   - 客户端在 TLS 1.3 `ClientHello` 中打包 `compress_certificate`
   - 服务端解析算法列表
   - 检查重复扩展与非法长度

5. 证书压缩算法协商与发送判定已经实现。
   当前代码已经具备：
   - 根据本地配置与对端算法列表选择协商算法
   - 在协商成功后记录 `isCertCompressionNegotiated`
   - 根据证书消息长度与阈值决定发送普通 `Certificate` 还是 `CompressedCertificate`

6. `CompressedCertificate` 的收发主路径已经实现。
   当前代码已经支持：
   - TLS 1.3 下打包并发送 `CompressedCertificate`
   - 接收后解析算法、长度和解压长度
   - 解压后复用现有证书解析逻辑

7. 版本边界与输入校验已经实现。
   当前代码已经显式覆盖：
   - TLS 1.2 及以下版本不协商证书压缩
   - TLS 1.2 及以下版本不接受 `CompressedCertificate`
   - 非法算法
   - 重复扩展
   - 非法扩展长度
   - 非法解压长度

8. 已有专项断言测试与之对应。
   当前 RFC8879 相关专项测试已经集中在
   `testcode/sdv/testcase/tls/consistency/tls13/test_suite_sdv_frame_tls13_consistency_rfc8446_extensions_1.c`
   中，对正常协商、协商失败回退、TLS 1.2 边界和部分异常输入进行了验证。
