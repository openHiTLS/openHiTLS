/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "crypt_sm4_macro_x86_64.s"

 .file	"crypt_sm4_x86_64.S"
 .text

##### 1st Block #####
.set	X0,	%r8d
.set	X1, %r9d
.set	X2, %r10d
.set	X3, %r11d

.set	T0, %eax
.set	T0BL, %al
.set	T1, %ecx

.set	T0_64, %rax
.set	T1_64, %rcx


##### 2nd Block #####
.set	Y0,	%r12d
.set	Y1, %r13d
.set	Y2, %r14d
.set	Y3, %r15d

.set	V0, %ebx
.set	V0BL, %bl
.set	V1, %ebp

.set	V0_64, %rbx
.set	V1_64, %rbp


##### Round Key #####
.set    RK, %rdx
.set	ADDR, %rsi


##### Serial Round #####
.macro	SM4_ROUND	A0 A1 A2 A3	RKey No

	#x4 = x1 ^ x2 ^ x3 ^ *(rk + i);
	#x4 = SBOX(x4);
	#x0 = x0 ^ L32(x4);

	#x4 = x1 ^ x2 ^ x3 ^ *(rk + i);
	movl	\No(\RKey), T0
	xorl	\A1, T0
	xorl    \A2, T0
	xorl    \A3, T0

	#x0 = x0 ^ (SBOX_0[x4 & 0xff]) ^ (SBOX_1[(x4 >> 8) & 0xff]) ^ (SBOX_2[(x4 >> 16) & 0xff]) ^ (SBOX_3[(x4 >> 24) & 0xff]);
	movzbl	T0BL, T1
	xorl	(ADDR,T1_64,4), \A0
	shrl	$8, T0
	movzbl	T0BL, T1
	xorl	1024(ADDR,T1_64,4), \A0
	shrl	$8, T0
	movzbl	T0BL, T1
	xorl	2048(ADDR,T1_64,4), \A0
	shrl	$8, T0
	xorl	3072(ADDR,T0_64,4), \A0

.endm


##### Parallel Round #####
.macro	SM4_2_ROUND	A0 A1 A2 A3	B0 B1 B2 B3 RKey No

	#x4 = x1 ^ x2 ^ x3 ^ *(rk + i);
	#x4 = SBOX(x4);
	#x0 = x0 ^ L32(x4);

	#x4 = x1 ^ x2 ^ x3 ^ *(rk + i);
	movl	\No(\RKey), T0
	movl	\No(\RKey), V0
	xorl	\A1, T0
	xorl	\B1, V0
	xorl    \A2, T0
	xorl	\B2, V0
	xorl    \A3, T0
	xorl	\B3, V0

	#x0 = x0 ^ (SBOX_0[x4 & 0xff]) ^ (SBOX_1[(x4 >> 8) & 0xff]) ^ (SBOX_2[(x4 >> 16) & 0xff]) ^ (SBOX_3[(x4 >> 24) & 0xff]);
	movzbl	T0BL, T1
	movzbl	V0BL, V1

	xorl	(ADDR,T1_64,4), \A0
	xorl	(ADDR,V1_64,4), \B0
	shrl	$8, T0
	shrl	$8, V0
	movzbl	T0BL, T1
	movzbl	V0BL, V1

	xorl	1024(ADDR,T1_64,4), \A0
	xorl	1024(ADDR,V1_64,4), \B0
	shrl	$8, T0
	shrl	$8, V0
	movzbl	T0BL, T1
	movzbl	V0BL, V1

	xorl	2048(ADDR,T1_64,4), \A0
	xorl	2048(ADDR,V1_64,4), \B0
	shrl	$8, T0
	shrl	$8, V0

	xorl	3072(ADDR,T0_64,4), \A0
	xorl	3072(ADDR,V0_64,4), \B0

.endm



##### Serial Function #####

	##### SM4 Encryption #####
	# void SM4_Encrypt(uint8_t *out, const uint8_t *in, const unsigned int *rk)
	# %rdi 	out 	cipher ptr		16 bytes
	# %rsi 	in 		plain ptr		16 bytes
	# %rdx  rk		round key ptr	128 bytes

	.globl	SM4_Encrypt
	.type	SM4_Encrypt, @function
	.align	64

SM4_Encrypt:

	###### Load Plain #####
	movl	(%rsi), X0
	movl	4(%rsi), X1
	movl	8(%rsi), X2
	movl	12(%rsi), X3
	bswap	X0
	bswap	X1
	bswap	X2
	bswap	X3

	###### Load SBOX ADDRESS #####
	leaq	SBOX4X_MASK(%rip), ADDR

	xorq 	T0_64, T0_64
	xorq 	T1_64, T1_64

	##### Serial Rounds #####
	SM4_ROUND	X0 X1 X2 X3	RK 0
	SM4_ROUND	X1 X2 X3 X0	RK 4
	SM4_ROUND	X2 X3 X0 X1	RK 8
	SM4_ROUND	X3 X0 X1 X2	RK 12
	SM4_ROUND	X0 X1 X2 X3	RK 16
	SM4_ROUND	X1 X2 X3 X0	RK 20
	SM4_ROUND	X2 X3 X0 X1	RK 24
	SM4_ROUND	X3 X0 X1 X2	RK 28
	SM4_ROUND	X0 X1 X2 X3	RK 32
	SM4_ROUND	X1 X2 X3 X0	RK 36
	SM4_ROUND	X2 X3 X0 X1	RK 40
	SM4_ROUND	X3 X0 X1 X2	RK 44
	SM4_ROUND	X0 X1 X2 X3	RK 48
	SM4_ROUND	X1 X2 X3 X0	RK 52
	SM4_ROUND	X2 X3 X0 X1	RK 56
	SM4_ROUND	X3 X0 X1 X2	RK 60
	SM4_ROUND	X0 X1 X2 X3	RK 64
	SM4_ROUND	X1 X2 X3 X0	RK 68
	SM4_ROUND	X2 X3 X0 X1	RK 72
	SM4_ROUND	X3 X0 X1 X2	RK 76
	SM4_ROUND	X0 X1 X2 X3	RK 80
	SM4_ROUND	X1 X2 X3 X0	RK 84
	SM4_ROUND	X2 X3 X0 X1	RK 88
	SM4_ROUND	X3 X0 X1 X2	RK 92
	SM4_ROUND	X0 X1 X2 X3	RK 96
	SM4_ROUND	X1 X2 X3 X0	RK 100
	SM4_ROUND	X2 X3 X0 X1	RK 104
	SM4_ROUND	X3 X0 X1 X2	RK 108
	SM4_ROUND	X0 X1 X2 X3	RK 112
	SM4_ROUND	X1 X2 X3 X0	RK 116
	SM4_ROUND	X2 X3 X0 X1	RK 120
	SM4_ROUND	X3 X0 X1 X2	RK 124

	##### Store Result #####
	bswap	X0
	bswap	X1
	bswap	X2
	bswap	X3
	movl	X3, (%rdi)
	movl	X2, 4(%rdi)
	movl	X1, 8(%rdi)
	movl	X0, 12(%rdi)

	##### Clear Context #####
	xorl	X0, X0
	xorl	X1, X1
	xorl	X2, X2
	xorl	X3, X3
	xorl	T0, T0
	xorl	T1, T1

	ret
	.size	SM4_Encrypt, .-SM4_Encrypt


	#### SM4 Decryption #####
	# void SM4_Decrypt(uint8_t *out, const uint8_t *in, const unsigned int *rk)
	# %rdi 	out 	plain ptr		16 bytes
	# %rsi 	in 		cipher ptr		16 bytes
	# %rdx  rk		round key ptr	128 bytes

	.globl	SM4_Decrypt
	.type	SM4_Decrypt, @function
	.align	64

SM4_Decrypt:

	###### Load Plain #####
	movl	(%rsi), X0
	movl	4(%rsi), X1
	movl	8(%rsi), X2
	movl	12(%rsi), X3
	bswap	X0
	bswap	X1
	bswap	X2
	bswap	X3

	###### Load SBOX ADDRESS #####
	leaq	SBOX4X_MASK(%rip), ADDR

	xorq 	T0_64, T0_64
	xorq 	T1_64, T1_64

	##### Serial Rounds #####
	SM4_ROUND	X0 X1 X2 X3	RK 124
	SM4_ROUND	X1 X2 X3 X0	RK 120
	SM4_ROUND	X2 X3 X0 X1	RK 116
	SM4_ROUND	X3 X0 X1 X2	RK 112
	SM4_ROUND	X0 X1 X2 X3	RK 108
	SM4_ROUND	X1 X2 X3 X0	RK 104
	SM4_ROUND	X2 X3 X0 X1	RK 100
	SM4_ROUND	X3 X0 X1 X2	RK 96
	SM4_ROUND	X0 X1 X2 X3	RK 92
	SM4_ROUND	X1 X2 X3 X0	RK 88
	SM4_ROUND	X2 X3 X0 X1	RK 84
	SM4_ROUND	X3 X0 X1 X2	RK 80
	SM4_ROUND	X0 X1 X2 X3	RK 76
	SM4_ROUND	X1 X2 X3 X0	RK 72
	SM4_ROUND	X2 X3 X0 X1	RK 68
	SM4_ROUND	X3 X0 X1 X2	RK 64
	SM4_ROUND	X0 X1 X2 X3	RK 60
	SM4_ROUND	X1 X2 X3 X0	RK 56
	SM4_ROUND	X2 X3 X0 X1	RK 52
	SM4_ROUND	X3 X0 X1 X2	RK 48
	SM4_ROUND	X0 X1 X2 X3	RK 44
	SM4_ROUND	X1 X2 X3 X0	RK 40
	SM4_ROUND	X2 X3 X0 X1	RK 36
	SM4_ROUND	X3 X0 X1 X2	RK 32
	SM4_ROUND	X0 X1 X2 X3	RK 28
	SM4_ROUND	X1 X2 X3 X0	RK 24
	SM4_ROUND	X2 X3 X0 X1	RK 20
	SM4_ROUND	X3 X0 X1 X2	RK 16
	SM4_ROUND	X0 X1 X2 X3	RK 12
	SM4_ROUND	X1 X2 X3 X0	RK 8
	SM4_ROUND	X2 X3 X0 X1	RK 4
	SM4_ROUND	X3 X0 X1 X2	RK 0

	##### Store Result #####
	bswap	X0
	bswap	X1
	bswap	X2
	bswap	X3
	movl	X3, (%rdi)
	movl	X2, 4(%rdi)
	movl	X1, 8(%rdi)
	movl	X0, 12(%rdi)

	##### Clear Context #####
	xorl	X0, X0
	xorl	X1, X1
	xorl	X2, X2
	xorl	X3, X3
	xorl	T0, T0
	xorl	T1, T1

	ret
	.size	SM4_Decrypt, .-SM4_Decrypt

#endif
