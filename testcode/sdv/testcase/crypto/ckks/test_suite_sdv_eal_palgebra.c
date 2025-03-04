#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "PAlgebra.h"
#include "hitls_build.h"
#include "helper.h"
#include "test.h"
#include <time.h>
int main(void) {
    uint32_t k = 10; // 2^10
    BN_BigNum **rev;

    BRC_init(k, &rev);

    for (uint32_t i = 0; i < (1U << k); i++) {
        uint8_t buffer[64];
        uint32_t len = sizeof(buffer);
        BN_Bn2Bin(rev[i], buffer, &len);
        printf("rev[%u] = ", i);
        for (uint32_t j = 0; j < len; j++) {
            printf("%02X", buffer[j]);
        }
        printf("\n");
        BN_Destroy(rev[i]);
    }

    free(rev);
    return 0;
}
