# Quick Start

Welcome to the openHiTLS tutorial. This tutorial will guide you through installing, integrating, and using openHiTLS.

## What Is openHiTLS?

openHiTLS is a C/C++ library for building cryptographic security capabilities. It provides cryptographic algorithms and TLS protocol stacks that comply with public standards.

## Installing openHiTLS

1. Download the source code:

   ```
   git clone https://gitcode.com/openhitls/openhitls.git
   ```

   > - The GitHub repository (https://github.com/openHiTLS/openHiTLS) is bidirectionally synchronized with the GitCode repository.
   > - The Gitee repository (https://gitee.com/openhitls/openhitls.git) is synchronized one-way from GitHub, so it may lag behind.

2. To build and install openHiTLS, run the following commands in the openHiTLS root directory:

   ```
   mkdir build
   cd build
   cmake ..
   make && make install
   ```

   Installation notes:

   - The default installation prefix is `/usr/local`: header files are installed under the `bsl`, `crypto`, `tls`, `pki`, and `auth` subdirectories of `/usr/local/include/hitls/`, and libraries are installed to `/usr/local/lib`.
   - Non-root users need `sudo` for `make install`, or specify a custom prefix at configuration time via `-DCMAKE_INSTALL_PREFIX=<directory>` (adjust the header and library paths accordingly in later steps).

## Integrate openHiTLS in your C/C++ Project

1. Call the APIs provided by openHiTLS in your project code according to the [API Reference](./5_Developer%20Guide/3_API%20Reference.md).
2. Add the header file and library paths of openHiTLS to your project dependencies. The following uses the gcc compiler as an example.

   Header files are installed in per-module directories. If your code includes headers from multiple modules (the example below uses both `crypto` and `bsl`), specify one `-I` for each module; do the same for `tls`, `pki`, and `auth` when they are used. Use `-L` to specify the library path:

   ```
   gcc application.c -o app \
     -lhitls_crypto -lhitls_bsl \
     -I /usr/local/include/hitls/crypto -I /usr/local/include/hitls/bsl \
     -L /usr/local/lib
   ```

3. Runtime prerequisites: before the first run of a program linked against the openHiTLS shared libraries, make sure the libraries can be loaded; otherwise you will see `libhitls_crypto.so: cannot open shared object file`.

   - Linux: run `sudo ldconfig` to refresh the shared library cache;
   - macOS: run `export DYLD_LIBRARY_PATH=/usr/local/lib`, or append `-Wl,-rpath,/usr/local/lib` to the compile command.

## Getting Started with openHiTLS

The following example computes an SM3 message digest and serves as a minimal check that your environment is ready (see `testcode/demo/` for complete examples of other algorithms). Save the code as `application.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypt_eal_md.h" // Digest API header
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h" // Algorithm ID list
#include "crypt_errno.h" // Error code list

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

int main(void)
{
    const uint8_t data[] = "hello openHiTLS";
    uint8_t digest[64] = {0};
    uint32_t len = sizeof(digest);
    int32_t ret;

    // Initialize the error module and register memory callbacks
    BSL_ERR_Init();
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);

    // Create the SM3 digest context
    CRYPT_EAL_MdCtx *ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    if (ctx == NULL) {
        printf("create md ctx failed\n");
        return 1;
    }

    // Compute the digest: Init -> Update -> Final
    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("init failed, error code is %x\n", ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, data, sizeof(data) - 1);
    if (ret != CRYPT_SUCCESS) {
        printf("update failed, error code is %x\n", ret);
        goto EXIT;
    }
    ret = CRYPT_EAL_MdFinal(ctx, digest, &len);
    if (ret != CRYPT_SUCCESS) {
        printf("final failed, error code is %x\n", ret);
        goto EXIT;
    }

    printf("sm3(\"%s\") = ", data);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    BSL_ERR_DeInit();
    return ret;
}
```

Build and run it with the commands from the previous section:

```
gcc application.c -o app \
  -lhitls_crypto -lhitls_bsl \
  -I /usr/local/include/hitls/crypto -I /usr/local/include/hitls/bsl \
  -L /usr/local/lib
sudo ldconfig
./app
```

Expected output (if you see the following, your environment is ready):

```
sm3("hello openHiTLS") = 76c94d0f012e2a19a5cb8f41e8fcab0e73a4db5934f75cd81570bd2e6703d06d
```

## Next Steps

- [Encryption and Integrity Protection Application Development Guide](./5_Developer%20Guide/1_Encryption%20and%20Integrity%20Protection%20Application%20Development%20Guide.md)
- [Secure Communication Application Development Guide](./5_Developer%20Guide/2_Secure%20Communication%20Application%20Development%20Guide.md)
- [Command Line Guide](./4_User%20Guide/5_Command%20Line%20Guide.md)
- [API Reference](./5_Developer%20Guide/3_API%20Reference.md)
- More algorithm examples: [testcode/demo](../../testcode/demo/)
