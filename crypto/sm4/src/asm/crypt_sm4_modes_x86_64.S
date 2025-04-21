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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include "crypt_sm4_modes_macro_x86_64.s"

.file	"crypt_sm4_modes_x86_64.S"
.text
.extern g_cpuState
.hidden g_cpuState

.set	X0,%ymm0
.set	X1,%ymm1
.set	X2,%ymm2
.set	X3,%ymm3
.set	Y0,%ymm4
.set	Y1,%ymm5
.set	Y2,%ymm6
.set	Y3,%ymm7

.set	ADDR,%rax
.set	IN,%rdi
.set	OUT,%rsi
.set	LEN,%rdx
.set	BLOCKS,%rdx
.set	RK,%rcx
.set	IV,%r8
.set	TWEAK,%r8
.set	TWEAK_MASK,%r9
.set	ENC,%r9d
.set	HI,%r12
.set	LO,%r13
.set	HI_TMP,%r14
.set	LO_TMP,%r15

.set	T0,%r10d
.set	T0BL,%r10b
.set	T1,%r11d

.set	T0_64,%r10
.set	T1_64,%r11

.set	W0,%r12d
.set	W1,%r13d
.set	W2,%r14d
.set	W3,%r15d

.macro	LOAD_DATA
	vmovdqu		(IN),X0
	vmovdqu		32(IN),X1
	vmovdqu		64(IN),X2
	vmovdqu		96(IN),X3
	vmovdqu		128(IN),Y0
	vmovdqu		128+32(IN),Y1
	vmovdqu		128+64(IN),Y2
	vmovdqu		128+96(IN),Y3
.endm

.macro	XOR_DATA
	vpxor	(IN),X0,X0
	vpxor	32(IN),X1,X1
	vpxor	64(IN),X2,X2
	vpxor	96(IN),X3,X3
	vpxor	128(IN),Y0,Y0
	vpxor	128+32(IN),Y1,Y1
	vpxor	128+64(IN),Y2,Y2
	vpxor	128+96(IN),Y3,Y3
.endm

.macro CHECK_GFNI re tmp
	xorl	\re, \re

	movl    $0x100, \tmp
	andl	g_cpuState+24(%rip), \tmp  # get gfni flag
	orl		\tmp, \re

	movl	$0x20, \tmp
	andl	g_cpuState+20(%rip), \tmp  # check avx2 flag
	orl		\tmp, \re

	cmpl	$0x120, \re   # code7Out[EAX] & (1<<5)) | code7Out[ECX_OUT_IDX] & (1<<8))
.endm

.macro	SM4_CRYPT_GFNI_BLOCK16
	# load affine matric
    vpbroadcastq .PreAffinT(%rip),PreAffineTRegBLOCK16
    vpbroadcastq .PostAffinT(%rip),PostAffineTRegBLOCK16

	vmovdqa		32+4096(ADDR),TMP0
	# vmovdqa		64+4096(ADDR),AES_MASK
	# vmovdqa		96+4096(ADDR),AES_AND_MASK

	vpshufb		TMP0,X0,X0
	vpshufb		TMP0,X1,X1
	vpshufb		TMP0,X2,X2
	vpshufb		TMP0,X3,X3
	vpshufb		TMP0,Y0,Y0
	vpshufb		TMP0,Y1,Y1
	vpshufb		TMP0,Y2,Y2
	vpshufb		TMP0,Y3,Y3

	# Pack SIMD Vectors
	MATRIX_TRANSPOSE	X0 X1 X2 X3
	MATRIX_TRANSPOSE	Y0 Y1 Y2 Y3

	# AVX2 Rounds
	SM4_AVX2_GFNI_2_ROUNDS

	# Restore SIMD Vectors
	MATRIX_TRANSPOSE	X0 X1 X2 X3
	MATRIX_TRANSPOSE	Y0 Y1 Y2 Y3

	# Reverse Transformation
	vmovdqa		4096(ADDR),TMP0
	vpshufb		TMP0,X0,X0
	vpshufb		TMP0,X1,X1
	vpshufb		TMP0,X2,X2
	vpshufb		TMP0,X3,X3
	vpshufb		TMP0,Y0,Y0
	vpshufb		TMP0,Y1,Y1
	vpshufb		TMP0,Y2,Y2
	vpshufb		TMP0,Y3,Y3
.endm

.macro	SM4_CRYPT_AESNI_BLOCK16

	vmovdqa		32+4096(ADDR),TMP0
	vmovdqa		64+4096(ADDR),AES_MASK
	vmovdqa		96+4096(ADDR),AES_AND_MASK

	vpshufb		TMP0,X0,X0
	vpshufb		TMP0,X1,X1
	vpshufb		TMP0,X2,X2
	vpshufb		TMP0,X3,X3
	vpshufb		TMP0,Y0,Y0
	vpshufb		TMP0,Y1,Y1
	vpshufb		TMP0,Y2,Y2
	vpshufb		TMP0,Y3,Y3

	# Pack SIMD Vectors
	MATRIX_TRANSPOSE	X0 X1 X2 X3
	MATRIX_TRANSPOSE	Y0 Y1 Y2 Y3

	# AVX2 Rounds
	SM4_AVX2_AES_2_ROUNDS

	# Restore SIMD Vectors
	MATRIX_TRANSPOSE	X0 X1 X2 X3
	MATRIX_TRANSPOSE	Y0 Y1 Y2 Y3

	# Reverse Transformation
	vmovdqa		4096(ADDR),TMP0
	vpshufb		TMP0,X0,X0
	vpshufb		TMP0,X1,X1
	vpshufb		TMP0,X2,X2
	vpshufb		TMP0,X3,X3
	vpshufb		TMP0,Y0,Y0
	vpshufb		TMP0,Y1,Y1
	vpshufb		TMP0,Y2,Y2
	vpshufb		TMP0,Y3,Y3
.endm

.macro	STORE_RESULTS
	vmovdqu		X0,0(OUT)
	vmovdqu		X1,32(OUT)
	vmovdqu		X2,64(OUT)
	vmovdqu		X3,96(OUT)
	vmovdqu		Y0,128(OUT)
	vmovdqu		Y1,128+32(OUT)
	vmovdqu		Y2,128+64(OUT)
	vmovdqu		Y3,128+96(OUT)
.endm

.macro	CLEAR_CONTEXT
	xorl	T0,T0
	xorl	T1,T1
	xorl	W0,W0
	xorl	W1,W1
	xorl	W2,W2
	xorl	W3,W3
.endm

##### SM4-CBC #####
	# void SM4_CBC_Encrypt(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key, unsigned char *iv, const int enc)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# rk		%rcx
	# iv		%r8
	# enc		%r9d
	.globl	SM4_CBC_Encrypt
	.type	SM4_CBC_Encrypt, @function
	.align	64
	
SM4_CBC_Encrypt:

	# Store Registers
	subq	$72,%rsp
	movq	%rbx,(%rsp)
	movq	%rbp,8(%rsp)
	movq	%r9,16(%rsp)
	movq	%r10,24(%rsp)
	movq	%r11,32(%rsp)
	movq	%r12,40(%rsp)
	movq	%r13,48(%rsp)
	movq	%r14,56(%rsp)
	movq	%r15,64(%rsp)

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

	testl	ENC,ENC
	jz		.Lcbc_decrypt

.Lcbc_encrypt:

	cmpq	$16,LEN
	jl		.Lcbc_ret

	# Load Data
	movl	(IN),W0
	movl	4(IN),W1
	movl	8(IN),W2
	movl	12(IN),W3

	# XOR IV
	xorl	(IV),W0
	xorl	4(IV),W1
	xorl	8(IV),W2
	xorl	12(IV),W3

	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3
	
	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Results
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	movl	W3,(IV)
	movl	W2,4(IV)
	movl	W1,8(IV)
	movl	W0,12(IV)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN

	jmp		.Lcbc_encrypt

.Lcbc_decrypt:

	cmpq	$256,LEN
	jl		.Lcbc_dec

.Lcbc_dec16:

	LOAD_DATA
	CHECK_GFNI %r9d %r10d
	jl .Lcbc_dec_aesni
.Lcbc_dec_gfni:
	SM4_CRYPT_GFNI_BLOCK16
	jmp .Lafter_cbc_dec
.Lcbc_dec_aesni:
	SM4_CRYPT_AESNI_BLOCK16
.Lafter_cbc_dec:

	vmovdqu		(IV),TMP0x
	vmovdqu		(IN),TMP1x
	vinserti128	$1,TMP1x,TMP0,TMP0
	vmovdqu		240(IN),TMP2x
	vmovdqu		TMP2x,(IV)

	vpxor	TMP0,X0,X0
	vpxor	16(IN),X1,X1
	vpxor	32+16(IN),X2,X2
	vpxor	64+16(IN),X3,X3
	vpxor	96+16(IN),Y0,Y0
	vpxor	128+16(IN),Y1,Y1
	vpxor	160+16(IN),Y2,Y2
	vpxor	192+16(IN),Y3,Y3

	STORE_RESULTS

	leaq	256(IN),IN
	leaq	256(OUT),OUT
	subq	$256,LEN
	cmpq	$256,LEN
	jl		.Lcbc_dec16_ret
	jmp		.Lcbc_dec16

.Lcbc_dec16_ret:

	vzeroall

.Lcbc_dec:

	cmpq	$16,LEN
	jl		.Lcbc_ret

	# Load Data
	movl	(IN),W0
	movl	4(IN),W1
	movl	8(IN),W2
	movl	12(IN),W3
	
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3
	
	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Result
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	xorl	(IV),W3
	xorl	4(IV),W2
	xorl	8(IV),W1
	xorl	12(IV),W0

	movq	(IN),%r10
	movq	%r10,(IV)
	movq	8(IN),%r10
	movq	%r10,8(IV)

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN
	
	jmp		.Lcbc_dec

.Lcbc_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%rbx
	movq	8(%rsp),%rbp
	movq	16(%rsp),%rax
	movq	24(%rsp),%r10
	movq	32(%rsp),%r11
	movq	40(%rsp),%r12
	movq	48(%rsp),%r13
	movq	56(%rsp),%r14
	movq	64(%rsp),%r15
	addq	$72,%rsp

	ret
	.size	SM4_CBC_Encrypt, .-SM4_CBC_Encrypt

##### SM4-ECB #####
	# void SM4_ECB_Encrypt(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# key		%rcx
	.globl	SM4_ECB_Encrypt
	.type	SM4_ECB_Encrypt, @function
	.align	64
	
SM4_ECB_Encrypt:

	# Store Registers
	subq	$32,%rsp
	movq	%r12,(%rsp)
	movq	%r13,8(%rsp)
	movq	%r14,16(%rsp)
	movq	%r15,24(%rsp)

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

.Lecb_encrypt:

	cmpq	$256,LEN
	jl		.Lecb_enc

.Lecb_enc16:

	LOAD_DATA

	CHECK_GFNI %r12d %r13d
	jl .Lecb_enc_aesni
.Lecb_enc_gfni:
	SM4_CRYPT_GFNI_BLOCK16
	jmp .Lafter_ecb_enc
.Lecb_enc_aesni:
	SM4_CRYPT_AESNI_BLOCK16
.Lafter_ecb_enc:
	STORE_RESULTS

	leaq	256(IN),IN
	leaq	256(OUT),OUT
	subq	$256,LEN
	cmpq	$256,LEN
	jl		.Lecb_enc16_ret
	jmp		.Lecb_enc16

.Lecb_enc16_ret:

	vzeroall

.Lecb_enc:

	cmpq	$16,LEN
	jl		.Lecb_ret

	# Load Data
	movl	(IN),W0
	movl	4(IN),W1
	movl	8(IN),W2
	movl	12(IN),W3
	
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3
	
	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Result
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN
	
	jmp		.Lecb_enc

.Lecb_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%r12
	movq	8(%rsp),%r13
	movq	16(%rsp),%r14
	movq	24(%rsp),%r15
	addq	$32,%rsp

	ret
	.size	SM4_ECB_Encrypt, .-SM4_ECB_Encrypt

##### SM4-CFB ENC #####
	# void SM4_CFB128_Encrypt(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key, unsigned char *iv, int *num)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# rk		%rcx
	# iv		%r8
	# num		%r9d
	.globl	SM4_CFB128_Encrypt
	.type	SM4_CFB128_Encrypt, @function
	.align	64

SM4_CFB128_Encrypt:

	# Store Registers
	subq	$72,%rsp
	movq	%rbx,(%rsp)
	movq	%rbp,8(%rsp)
	movq	%r9,16(%rsp)
	movq	%r10,24(%rsp)
	movq	%r11,32(%rsp)
	movq	%r12,40(%rsp)
	movq	%r13,48(%rsp)
	movq	%r14,56(%rsp)
	movq	%r15,64(%rsp)

	# Load Num
	movl	(%r9),%r9d
	cmpl	$0,%r9d
	je		.Lcfb128_enc_update

.Lcfb128_enc_init:

	movb	0(IV,%r9,1),%al
	xorb	(IN),%al
	movb	%al,(OUT)
	movb	%al,0(IV,%r9,1)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	cmpl	$16,%r9d
	je		.Lcfb128_enc_update
	cmpq	$0,LEN
	je		.Lcfb128_enc_ret

	jmp		.Lcfb128_enc_init
	
.Lcfb128_enc_update:

	movl	$0,%r9d

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

.Lcfb128_enc_loop:

	cmpq	$0,LEN
	je		.Lcfb128_enc_ret

	movl	 $0,%r9d

	# Load IV
	movl	(IV),W0
	movl	4(IV),W1
	movl	8(IV),W2
	movl	12(IV),W3

	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3
	
	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Results
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	movl	W3,(IV)
	movl	W2,4(IV)
	movl	W1,8(IV)
	movl	W0,12(IV)

	cmpq	$16,LEN
	jl		.Lcfb128_enc_final

	xorl	(IN),W3
	xorl	4(IN),W2
	xorl	8(IN),W1
	xorl	12(IN),W0

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	movl	W3,(IV)
	movl	W2,4(IV)
	movl	W1,8(IV)
	movl	W0,12(IV)
	
	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN

	jmp		.Lcfb128_enc_loop

.Lcfb128_enc_final:

	movb	0(IV,%r9,1),%al
	xorb	(IN),%al
	movb	%al,(OUT)
	movb	%al,0(IV,%r9,1)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	jnz		.Lcfb128_enc_final

.Lcfb128_enc_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%rbx
	movq	8(%rsp),%rbp
	movq	16(%rsp),%rax
	movq	24(%rsp),%r10
	movq	32(%rsp),%r11
	movq	40(%rsp),%r12
	movq	48(%rsp),%r13
	movq	56(%rsp),%r14
	movq	64(%rsp),%r15
	addq	$72,%rsp

	# Store Num
	movl	%r9d,(%rax)

	ret
	.size	SM4_CFB128_Encrypt, .-SM4_CFB128_Encrypt

##### SM4-CFB DEC #####
	# void SM4_CFB128_Decrypt(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key, unsigned char *iv, int *num)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# rk		%rcx
	# iv		%r8
	# num		%r9d
	.globl	SM4_CFB128_Decrypt
	.type	SM4_CFB128_Decrypt, @function
	.align	64

SM4_CFB128_Decrypt:

	# Store Registers
	subq	$72,%rsp
	movq	%rbx,(%rsp)
	movq	%rbp,8(%rsp)
	movq	%r9,16(%rsp)
	movq	%r10,24(%rsp)
	movq	%r11,32(%rsp)
	movq	%r12,40(%rsp)
	movq	%r13,48(%rsp)
	movq	%r14,56(%rsp)
	movq	%r15,64(%rsp)

	# Load Num
	movl	(%r9),%r9d
	cmpl	$0,%r9d
	je		.Lcfb128_dec_update

.Lcfb128_dec_init:

	movb	0(IV,%r9,1),%al
	movb	(IN),%bl
	xorb	%bl,%al
	movb	%al,(OUT)
	movb	%bl,0(IV,%r9,1)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	cmpl	$16,%r9d
	je		.Lcfb128_dec_update
	cmpq	$0,LEN
	je		.Lcfb128_dec_ret

	jmp		.Lcfb128_dec_init

.Lcfb128_dec_update:

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

	movl	$0,%r9d

	cmpq	$256,LEN
	jl		.Lcfb128_dec

.Lcfb128_dec16:

	vmovdqu		(IV),TMP0x
	vmovdqu		(IN),TMP1x
	vinserti128	$1,TMP1x,TMP0,TMP0
	vmovdqu		240(IN),TMP2x
	vmovdqu		TMP2x,(IV)

	vmovdqu		TMP0,X0
	vmovdqu		16(IN),X1
	vmovdqu		32+16(IN),X2
	vmovdqu		64+16(IN),X3
	vmovdqu		96+16(IN),Y0
	vmovdqu		128+16(IN),Y1
	vmovdqu		160+16(IN),Y2
	vmovdqu		192+16(IN),Y3

	CHECK_GFNI %r10d %r11d
	jl .Lcfb128_dec_aesni
.Lcfb128_dec_gfni:
	SM4_CRYPT_GFNI_BLOCK16
	jmp .Lafter_cfb128_dec
.Lcfb128_dec_aesni:
	SM4_CRYPT_AESNI_BLOCK16
.Lafter_cfb128_dec:
	XOR_DATA
	STORE_RESULTS

	leaq	256(IN),IN
	leaq	256(OUT),OUT
	subq	$256,LEN
	cmpq	$256,LEN
	jl		.Lcfb128_dec16_ret
	jmp		.Lcfb128_dec16

.Lcfb128_dec16_ret:

	vzeroall

.Lcfb128_dec:

	cmpq	$0,LEN
	je		.Lcfb128_dec_ret

.Lcfb128_dec1:

	# Load IV
	movl	(IV),W0
	movl	4(IV),W1
	movl	8(IV),W2
	movl	12(IV),W3

	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3
	
	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Results
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	movl	W3,(IV)
	movl	W2,4(IV)
	movl	W1,8(IV)
	movl	W0,12(IV)

	cmpq	$16,LEN
	jl		.Lcfb128_dec_final

	movq	(IN),%rbx
	movq	%rbx,(IV)
	movq	8(IN),%rbx
	movq	%rbx,8(IV)
	xorq	%rbx,%rbx

	xorl	(IN),W3
	xorl	4(IN),W2
	xorl	8(IN),W1
	xorl	12(IN),W0

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN
	cmpq	$0,LEN
	je		.Lcfb128_dec_ret
	jmp		.Lcfb128_dec1

.Lcfb128_dec_final:

	movb	0(IV,%r9,1),%al
	movb	(IN),%bl
	xorb	%bl,%al
	movb	%al,(OUT)
	movb	%bl,0(IV,%r9,1)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	jnz		.Lcfb128_dec_final

.Lcfb128_dec_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%rbx
	movq	8(%rsp),%rbp
	movq	16(%rsp),%rax
	movq	24(%rsp),%r10
	movq	32(%rsp),%r11
	movq	40(%rsp),%r12
	movq	48(%rsp),%r13
	movq	56(%rsp),%r14
	movq	64(%rsp),%r15
	addq	$72,%rsp

	# Store Num
	movl	%r9d,(%rax)

	ret
	.size	SM4_CFB128_Decrypt, .-SM4_CFB128_Decrypt

##### SM4-OFB #####
	# void SM4_OFB_Encrypt(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key, unsigned char *iv, int *num)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# rk		%rcx
	# iv		%r8
	# num		%r9d
	.globl	SM4_OFB_Encrypt
	.type	SM4_OFB_Encrypt, @function
	.align	64

SM4_OFB_Encrypt:

	# Store Registers
	subq	$72,%rsp
	movq	%rbx,(%rsp)
	movq	%rbp,8(%rsp)
	movq	%r9,16(%rsp)
	movq	%r10,24(%rsp)
	movq	%r11,32(%rsp)
	movq	%r12,40(%rsp)
	movq	%r13,48(%rsp)
	movq	%r14,56(%rsp)
	movq	%r15,64(%rsp)

	# Load Num
	movl	(%r9),%r9d
	cmpl	$0,%r9d
	jz		.Lofb128_enc_update

.Lofb128_enc_init:

	movb	0(IV,%r9,1),%al
	xorb	(IN),%al
	movb	%al,(OUT)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	cmpl	$16,%r9d
	je		.Lofb128_enc_update
	cmpq	$0,LEN
	je		.Lofb128_enc_ret

	jmp		.Lofb128_enc_init

.Lofb128_enc_update:

	movl	$0,%r9d

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

.Lofb128_enc_loop:

	cmpq	$0,LEN
	je		.Lofb128_enc_ret

	# Load IV
	movl	(IV),W0
	movl	4(IV),W1
	movl	8(IV),W2
	movl	12(IV),W3

	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Results
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	movl	W3,(IV)
	movl	W2,4(IV)
	movl	W1,8(IV)
	movl	W0,12(IV)

	cmpq	$16,LEN
	jl		.Lofb128_enc_final

	xorl	(IN),W3
	xorl	4(IN),W2
	xorl	8(IN),W1
	xorl	12(IN),W0

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	subq	$16,LEN

	jmp		.Lofb128_enc_loop

.Lofb128_enc_final:

	movb	0(IV,%r9,1),%al
	xorb	(IN),%al
	movb	%al,(OUT)

	leaq	1(IN),IN
	leaq	1(OUT),OUT

	incl	%r9d
	decq	LEN
	jnz		.Lofb128_enc_final

.Lofb128_enc_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%rbx
	movq	8(%rsp),%rbp
	movq	16(%rsp),%rax
	movq	24(%rsp),%r10
	movq	32(%rsp),%r11
	movq	40(%rsp),%r12
	movq	48(%rsp),%r13
	movq	56(%rsp),%r14
	movq	64(%rsp),%r15
	addq	$72,%rsp

	# Store Num
	movl	%r9d,(%rax)

	ret
	.size	SM4_OFB_Encrypt, .-SM4_OFB_Encrypt

##### SM4-CTR32 #####
# NOTE: the IV/counter CTR mode is big-endian.
.align	64
.Lmovbe12:
.byte	0,1,2,3,4,5,6,7,8,9,10,11,15,14,13,12,0,1,2,3,4,5,6,7,8,9,10,11,15,14,13,12
.Lone:
.long	0,0,0,1

.macro	INCREMENT_COUNTER
	movbe	12(IV),%ebx
	incl	%ebx
	movbe	%ebx,12(IV)
.endm

.macro	LOAD_ECOUNT_BUF	SINK
	vpaddd		TMP1x,TMP2x,TMP3x
	vpaddd		TMP1x,TMP3x,TMP4x
	vinserti128	$1,TMP3x,TMP2,TMP2
	vpshufb		TMP0,TMP2,TMP2
	vmovdqa		TMP2,\SINK
	vmovdqa		TMP4x,TMP2x
.endm

.macro	LOAD_ECOUNT_BUF_ALL
	vmovdqa	.Lmovbe12(%rip),TMP0
	vmovdqa	.Lone(%rip),TMP1x
	vmovdqu	(IV),TMP2x
	vpshufb	TMP0x,TMP2x,TMP2x
	LOAD_ECOUNT_BUF		X0
	LOAD_ECOUNT_BUF		X1
	LOAD_ECOUNT_BUF		X2
	LOAD_ECOUNT_BUF		X3
	LOAD_ECOUNT_BUF		Y0
	LOAD_ECOUNT_BUF		Y1
	LOAD_ECOUNT_BUF		Y2
	LOAD_ECOUNT_BUF		Y3
	vpshufb	TMP0x,TMP2x,TMP2x
	vmovdqu	TMP2x,(IV)
.endm

	# void SM4_CTR_EncryptBlocks(const unsigned char *in, unsigned char *out, size_t blocks, const SM4_KEY *key, const unsigned char *iv)
	# in		%rdi
	# out		%rsi
	# blocks	%rdx
	# rk		%rcx
	# iv		%r8
	.globl	SM4_CTR_EncryptBlocks
	.type	SM4_CTR_EncryptBlocks, @function
	.align	64

SM4_CTR_EncryptBlocks:

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

	# Store Registers
	subq	$88,%rsp
	movq	%rbx,(%rsp)
	movq	%rbp,8(%rsp)
	movq	%r8,16(%rsp)
	movq	%r9,24(%rsp)
	movq	%r10,32(%rsp)
	movq	%r11,40(%rsp)
	movq	%r12,48(%rsp)
	movq	%r13,56(%rsp)
	movq	%r14,64(%rsp)
	movq	%r15,72(%rsp)
	movq	%rdx,80(%rsp)

	cmpq	$16,BLOCKS
	jl		.Lctr32_enc

.Lctr32_enc16:

	LOAD_ECOUNT_BUF_ALL
	CHECK_GFNI %r9d %r10d
	jl .Lctr32_enc_aesni
.Lctr32_enc_gfni:
	SM4_CRYPT_GFNI_BLOCK16
	jmp .Lafter_ctr32_enc
.Lctr32_enc_aesni:
	SM4_CRYPT_AESNI_BLOCK16
.Lafter_ctr32_enc:

	XOR_DATA
	STORE_RESULTS

	leaq	256(IN),IN
	leaq	256(OUT),OUT
	subq	$16,BLOCKS
	cmpq	$16,BLOCKS
	jl		.Lctr32_enc16_ret
	jmp		.Lctr32_enc16

.Lctr32_enc16_ret:

	vzeroall

.Lctr32_enc:

	cmpq	$0,BLOCKS
	je		.Lctr32_ret

	# Load IV
	movl	(IV),W0
	movl	4(IV),W1
	movl	8(IV),W2
	movl	12(IV),W3

	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	# Serial Rounds
	SM4_SERIAL_ROUNDS

	# Store Results
	bswap	W0
	bswap	W1
	bswap	W2
	bswap	W3

	xorl	(IN),W3
	xorl	4(IN),W2
	xorl	8(IN),W1
	xorl	12(IN),W0

	movl	W3,(OUT)
	movl	W2,4(OUT)
	movl	W1,8(OUT)
	movl	W0,12(OUT)

	leaq	16(IN),IN
	leaq	16(OUT),OUT
	decq	BLOCKS

	INCREMENT_COUNTER

	jmp		.Lctr32_enc

.Lctr32_ret:

	CLEAR_CONTEXT

	# Restore Registers
	movq	(%rsp),%rbx
	movq	8(%rsp),%rbp
	movq	16(%rsp),%r8
	movq	24(%rsp),%r9
	movq	32(%rsp),%r10
	movq	40(%rsp),%r11
	movq	48(%rsp),%r12
	movq	56(%rsp),%r13
	movq	64(%rsp),%r14
	movq	72(%rsp),%r15
	movq	80(%rsp),%rdx
	addq	$88,%rsp

	ret
	.size	SM4_CTR_EncryptBlocks, .-SM4_CTR_EncryptBlocks

##### SM4-XTS #####

.align	16
.Lxts_tweak_mask:
.long	0,0xe1000000

.macro GALOIS_FIELD_MUL	Idx
	xorq	LO_TMP,LO_TMP

	testq	$1,LO
	cmovnzq	TWEAK_MASK,LO_TMP
	shrd	$1,HI,LO
	shrq	$1,HI
	xorq	LO_TMP,HI

	movbe	HI,\Idx(TWEAK)
	movbe	LO,\Idx+8(TWEAK)
.endm

.macro GALOIS_FIELD_MUL_16_INNER
	GALOIS_FIELD_MUL 16
	# T2:T1->T2
	GALOIS_FIELD_MUL 32
	# T3:T2->T3
	GALOIS_FIELD_MUL 48
	# T4:T3->T4
	GALOIS_FIELD_MUL 64
	# T5:T4->T5
	GALOIS_FIELD_MUL 80
	# T6:T5->T6
	GALOIS_FIELD_MUL 96
	# T7:T6->T7
	GALOIS_FIELD_MUL 112
	# T8:T7->T8
	GALOIS_FIELD_MUL 128
	# T9:T8->T9
	GALOIS_FIELD_MUL 144
	# T10:T9->T10
	GALOIS_FIELD_MUL 160
	# T11:T10->T11
	GALOIS_FIELD_MUL 176
	# T12:T11->T12
	GALOIS_FIELD_MUL 192
	# T13:T12->T13
	GALOIS_FIELD_MUL 208
	# T14:T13->T14
	GALOIS_FIELD_MUL 224
	# T15:T14->T15
	GALOIS_FIELD_MUL 240
.endm

.macro XOR_TWEAK
	vpxor	(TWEAK),X0,X0
	vpxor	32(TWEAK),X1,X1
	vpxor	64(TWEAK),X2,X2
	vpxor	96(TWEAK),X3,X3
	vpxor	128(TWEAK),Y0,Y0
	vpxor	128+32(TWEAK),Y1,Y1
	vpxor	128+64(TWEAK),Y2,Y2
	vpxor	128+96(TWEAK),Y3,Y3
.endm

.macro SM4_XTS_16_EN_INNER
	LOAD_DATA
	XOR_TWEAK
	CHECK_GFNI %r15d %r14d
	jl .Lxts_enc_aesni
.Lxts_enc_gfni:
	SM4_CRYPT_GFNI_BLOCK16
	jmp .Lafter_xts_enc
.Lxts_enc_aesni:
	SM4_CRYPT_AESNI_BLOCK16
.Lafter_xts_enc:
	XOR_TWEAK
	STORE_RESULTS
.endm

	# void SM4_XTS_Encrypt_Blocks(const unsigned char *in, unsigned char *out, size_t len, const SM4_KEY *key, unsigned char *t)
	# in		%rdi
	# out		%rsi
	# len		%rdx
	# key		%rcx
	# t			%r8
	.globl	SM4_XTS_Encrypt_Blocks
	.type	SM4_XTS_Encrypt_Blocks, @function
	.align	64

SM4_XTS_Encrypt_Blocks:

	cmpq	$256,LEN
	jl		.Lxts_ret

	# Store Registers
	subq	$56,%rsp
	movq	%r9,(%rsp)
	movq	%r10,8(%rsp)
	movq	%r11,16(%rsp)
	movq	%r12,24(%rsp)
	movq	%r13,32(%rsp)
	movq	%r14,40(%rsp)
	movq	%r15,48(%rsp)

	# Get Address
	leaq	SBOX4X_MASK(%rip),ADDR

	# Load tweak mask
	movq	.Lxts_tweak_mask(%rip),TWEAK_MASK

	# T0: Initial
	movbe	(TWEAK),HI
	movbe	8(TWEAK),LO

.Lxts_update:

	GALOIS_FIELD_MUL_16_INNER
	SM4_XTS_16_EN_INNER

	leaq	256(IN),IN
	leaq	256(OUT),OUT
	subq	$256,LEN
	cmpq	$256,LEN
	jl		.Lxts_final

	# T15: Initial
	movbe	240(TWEAK),HI
	movbe	248(TWEAK),LO
	# T0:T15->T0
	GALOIS_FIELD_MUL 0

	jmp		.Lxts_update

.Lxts_final:

	# Clear Context
	vzeroall

	# Restore Registers
	movq	(%rsp),%r9
	movq	8(%rsp),%r10
	movq	16(%rsp),%r11
	movq	24(%rsp),%r12
	movq	32(%rsp),%r13
	movq	40(%rsp),%r14
	movq	48(%rsp),%r15
	addq	$56,%rsp

.Lxts_ret:

	ret
	.size	SM4_XTS_Encrypt_Blocks, .-SM4_XTS_Encrypt_Blocks

#endif
