/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef BENCHMARK_REGISTRY_H
#define BENCHMARK_REGISTRY_H

typedef struct BenchCtx_ BenchCtx;

#define BENCHMARK_LIST(X) \
    X(Sm2)                \
    X(Sm9)                \
    X(SlhDsa)             \
    X(Ecdsa)              \
    X(Md)                 \
    X(Cipher)             \
    X(Mac)                \
    X(Dh)                 \
    X(Ecdh)               \
    X(Rsa)                \
    X(X25519)             \
    X(Ed25519)            \
    X(Mldsa)              \
    X(Mlkem)              \
    X(Xmss)               \
    X(Mceliece)

#define DECLARE_BENCH_GETTER(name) \
    const BenchCtx *BenchmarkGet##name(void);

BENCHMARK_LIST(DECLARE_BENCH_GETTER)

#undef DECLARE_BENCH_GETTER

#endif /* BENCHMARK_REGISTRY_H */
