# Quick Start

Welcome to the openHiTLS tutorial. This tutorial will guide you through installing, integrating, and using openHiTLS.

## What Is openHiTLS?

openHiTLS is a C/C++ library for building cryptographic security capabilities. It provides cryptographic algorithms and TLS protocol stacks that comply with public standards.

## Installing openHiTLS

1. Download related codes.
   openHiTLS download address: https://gitee.com/openhitls/openhitls.git

   libboundscheck download address: https://gitee.com/openeuler/libboundscheck.git

   Note: Download libboundscheck to the **openHiTLS/platform/Secure_C** directory.
2. To build and install openHiTLS, run the following commands in the openHiTLS root directory:

```~~~~
mkdir build
cd build
cmake ..
make && make install
```

## Integrate openHiTLS in your C/C++ project.

1. Call the APIs provided by openHiTLS in your project code according to the API manual.
2. Add the header file and library path of openHiTLS to your project dependency. The following uses the gcc compiler as an example:

```
# Use **-I** to specify the path of the header file and **-L** to specify the path of the dynamic library.
gcc application.c -lhitls_crypto -lhitls_tls -lhitls_bsl -lboundscheck -I <openHiTLS header file installation path> -L <openHiTLS dynamic library installation path>
```

## Getting Started with openHiTLS

After the preceding operations are performed, the security capabilities provided by openHiTLS can be used.
