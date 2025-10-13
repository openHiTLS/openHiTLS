# OpenHITLS Command Line Development Guide

## 1. Compilation and Building

python3 ./configure.py --executes hitls --lib_type shared --enable all --asm_type x8664
cmake ..
make -j

The executable file will be generated in the build directory:

## 2. Instructions

### 2.1 Help Command

./hitls help

```
help        rand        enc         pkcs12      
rsa         x509        list        dgst        
crl         genrsa      verify      passwd      
pkey        genpkey     req    
```
