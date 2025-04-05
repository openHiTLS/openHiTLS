## openhitls benchmark

Before running benchmark, openhitls should be built firstly.

### 

### run like 
```
openhitls_benchmark    // run all benchmark testcases

openhtils_benchmark -a sm2* // run all sm2 benchmark testcases

openhitls_benchmark -a sm2-KeyGen  // just run sm2 KeyGen

openhitls_benchmark -a *KeyGen  // run all KeyGen benchmark testcases

openhitls_benchmark -a sm2-KeyGen -t 10000 // run 'sm2 KeyGen' 10000 times

openhitls_benchmark -t 10000 // run every benchmark testcase 10000 times

openhitls_benchmark -s 5 // run every benchmark testcase 5 seconds
```