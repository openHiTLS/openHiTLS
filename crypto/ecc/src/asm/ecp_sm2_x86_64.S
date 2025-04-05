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
#ifdef HITLS_CRYPTO_CURVE_SM2

.file	"ecp_sm2_x86_64.S"
.text

.set	s0,%r8
.set	s1,%r9
.set	s2,%r10
.set	s3,%r11
.set	s4,%r12
.set	s5,%r13
.set	s6,%r14
.set	s7,%r15

# The polynomial
.align	64
.Lpoly:
.quad	0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff
# The order of polynomial
.Lord:
.quad	0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff

### Right shift: in >> 1 ###
	# void ECP_Sm2BnRshift1(uint64_t *a)
	# 1-bit right shift
	# a		%rdi
	.globl	ECP_Sm2BnRshift1
	.type	ECP_Sm2BnRshift1, @function
	.align	64

ECP_Sm2BnRshift1:

	# Load inputs
	movq	(%rdi), %r8
	movq	8(%rdi), %r9
	movq	16(%rdi), %r10
	movq	24(%rdi), %r11

	# Right shift
	shrd	$1, %r9, %r8
	shrd	$1, %r10, %r9
	shrd	$1, %r11, %r10
	shrq	$1, %r11

	# Store results
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)

	ret
	.size ECP_Sm2BnRshift1, .-ECP_Sm2BnRshift1

### Modular div by 2: res = in/2 mod p ###
	# void ECP_Sm2DivBy2(uint64_t *r, const uint64_t *a)
	# Modular div by 2
	# r		%rdi
	# a		%rsi
	.globl	ECP_Sm2DivBy2
	.type	ECP_Sm2DivBy2, @function
	.align	64

ECP_Sm2DivBy2:
	# Store scalar registers
	subq	$24, %rsp
	movq	%rbx, (%rsp)
	movq	%r12, 8(%rsp)
	movq	%r13, 16(%rsp)

	xorq	%r12, %r12
	xorq	%r13, %r13

	# Load inputs
	movq	(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11

	movq	%r8, %rax
	movq	%r9, %rbx
	movq	%r10, %rcx
	movq	%r11, %rdx

	# Add polynomial
	leaq	.Lpoly(%rip), %rsi
	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	$0, %r12

	# Parity check
	testq	$1, %rax

	cmovzq	%rax, %r8
	cmovzq	%rbx, %r9
	cmovzq	%rcx, %r10
	cmovzq	%rdx, %r11
	cmovzq	%r13, %r12

	shrd	$1, %r9, %r8
	shrd	$1, %r10, %r9
	shrd	$1, %r11, %r10
	shrd	$1, %r12, %r11

	# Store results
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)

	# Restore scalar registers
	movq	(%rsp), %rbx
	movq	8(%rsp), %r12
	movq	16(%rsp), %r13
	addq	$24, %rsp

	ret
	.size ECP_Sm2DivBy2, .-ECP_Sm2DivBy2

### Modular mul by 3: r = 3*a mod p ###
	# void ECP_Sm2MulBy3(uint64_t *r, const uint64_t *a)
	# Modular mul by 3
	# r		%rdi
	# a		%rsi
	.globl	ECP_Sm2MulBy3
	.type	ECP_Sm2MulBy3, @function
	.align	64

ECP_Sm2MulBy3:

	# Store scalar registers
	subq	$32, %rsp
	movq	%r12, (%rsp)
	movq	%r13, 8(%rsp)
	movq	%r14, 16(%rsp)
	movq	%r15, 24(%rsp)

	xorq	%rax, %rax

	# Load inputs
	movq	(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11

	# 2*a
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10, %r10
	adcq	%r11, %r11
	adcq	$0, %rax

	movq	%r8, %r12
	movq	%r9, %r13
	movq	%r10, %r14
	movq	%r11, %r15

	# Sub polynomial
	subq	.Lpoly(%rip), %r8
	sbbq	.Lpoly+8(%rip), %r9
	sbbq	.Lpoly+16(%rip), %r10
	sbbq	.Lpoly+24(%rip), %r11
	sbbq	$0, %rax

	cmovcq	%r12, %r8
	cmovcq	%r13, %r9
	cmovcq	%r14, %r10
	cmovcq	%r15, %r11

	xorq   %rax, %rax

	# 3*a
	addq	(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	$0, %rax

	movq	%r8, %r12
	movq	%r9, %r13
	movq	%r10, %r14
	movq	%r11, %r15

	# Sub polynomial
	subq	.Lpoly(%rip), %r8
	sbbq	.Lpoly+8(%rip), %r9
	sbbq	.Lpoly+16(%rip), %r10
	sbbq	.Lpoly+24(%rip), %r11
	sbbq	$0, %rax

	cmovcq	%r12, %r8
	cmovcq	%r13, %r9
	cmovcq	%r14, %r10
	cmovcq	%r15, %r11

	# Store results
	movq	%r8, (%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)

	# Restore scalar registers
	movq	(%rsp), %r12
	movq	8(%rsp), %r13
	movq	16(%rsp), %r14
	movq	24(%rsp), %r15
	addq	$32, %rsp

	ret
	.size ECP_Sm2MulBy3, .-ECP_Sm2MulBy3

#define	bn_mod_add(mod)				\
	/* Store scalar registers */	\
	subq	$32, %rsp;				\
	movq	%r12, (%rsp);			\
	movq	%r13, 8(%rsp);			\
	movq	%r14, 16(%rsp);			\
	movq	%r15, 24(%rsp);			\
	xorq	%rax, %rax;				\
	/* Load inputs */				\
	movq	(%rsi), %r8;			\
	movq	8(%rsi), %r9;			\
	movq	16(%rsi), %r10;			\
	movq	24(%rsi), %r11;			\
	/* Addition */					\
	addq	(%rdx), %r8;			\
	adcq	8(%rdx), %r9;			\
	adcq	16(%rdx), %r10;			\
	adcq	24(%rdx), %r11;			\
	/* Store carry */				\
	adcq	$0, %rax;				\
	movq	%r8, %r12;				\
	movq	%r9, %r13;				\
	movq	%r10, %r14;				\
	movq	%r11, %r15;				\
	/* Sub polynomial */			\
	leaq	mod, %rsi;				\
	subq	0(%rsi), %r8;			\
	sbbq	8(%rsi), %r9;			\
	sbbq	16(%rsi), %r10;			\
	sbbq	24(%rsi), %r11;			\
	sbbq	$0, %rax;				\
	cmovcq	%r12, %r8;				\
	cmovcq	%r13, %r9;				\
	cmovcq	%r14, %r10;				\
	cmovcq	%r15, %r11;				\
	/* Store results */				\
	movq	%r8, (%rdi);			\
	movq	%r9, 8(%rdi);			\
	movq	%r10, 16(%rdi);			\
	movq	%r11, 24(%rdi);			\
	/* Restore scalar registers */	\
	movq	(%rsp), %r12;			\
	movq	8(%rsp), %r13;			\
	movq	16(%rsp), %r14;			\
	movq	24(%rsp), %r15;			\
	addq	$32, %rsp;				\

#define	bn_mod_sub(mod)				\
	/* Store scalar registers */	\
	subq	$32, %rsp;				\
	movq	%r12, (%rsp);			\
	movq	%r13, 8(%rsp);			\
	movq	%r14, 16(%rsp);			\
	movq	%r15, 24(%rsp);			\
	xorq	%rax, %rax;				\
	/* Load inputs */				\
	movq	(%rsi), %r8;			\
	movq	8(%rsi), %r9;			\
	movq	16(%rsi), %r10;			\
	movq	24(%rsi), %r11;			\
	/* Subtraction */				\
	subq	(%rdx), %r8;			\
	sbbq	8(%rdx), %r9;			\
	sbbq	16(%rdx), %r10;			\
	sbbq	24(%rdx), %r11;			\
	sbbq	$0, %rax;				\
	movq	%r8, %r12;				\
	movq	%r9, %r13;				\
	movq	%r10, %r14;				\
	movq	%r11, %r15;				\
	/* Add polynomial */			\
	leaq	mod, %rsi;				\
	addq	0(%rsi), %r8;			\
	adcq	8(%rsi), %r9;			\
	adcq	16(%rsi), %r10;			\
	adcq	24(%rsi), %r11;			\
	testq	%rax, %rax;				\
	cmovzq	%r12, %r8;				\
	cmovzq	%r13, %r9;				\
	cmovzq	%r14, %r10;				\
	cmovzq	%r15, %r11;				\
	/* Store results */				\
	movq	%r8, (%rdi);			\
	movq	%r9, 8(%rdi);			\
	movq	%r10, 16(%rdi);			\
	movq	%r11, 24(%rdi);			\
	/* Restore scalar registers */	\
	movq	(%rsp), %r12;			\
	movq	8(%rsp), %r13;			\
	movq	16(%rsp), %r14;			\
	movq	24(%rsp), %r15;			\
	addq	$32, %rsp;				\

### Modular add: r = a+b mod n/p, where n = ord(p) ###
	# void ECP_Sm2Add(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular poly add
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2Add
	.type	ECP_Sm2Add, @function
	.align	64

ECP_Sm2Add:

	bn_mod_add(.Lpoly(%rip))
	
	ret
	.size ECP_Sm2Add, .-ECP_Sm2Add

	# void ECP_Sm2AddModOrd(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular order add
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2AddModOrd
	.type	ECP_Sm2AddModOrd, @function
	.align	64

ECP_Sm2AddModOrd:

	bn_mod_add(.Lord(%rip))

	ret
	.size ECP_Sm2AddModOrd, .-ECP_Sm2AddModOrd

### Modular sub: r = a-b mod n/p, where n = ord(p) ###
	# void ECP_Sm2Sub(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular poly sub
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2Sub
	.type	ECP_Sm2Sub, @function
	.align	64

ECP_Sm2Sub:

	bn_mod_sub(.Lpoly(%rip))
	
	ret
	.size ECP_Sm2Sub, .-ECP_Sm2Sub

	# void ECP_Sm2SubModOrd(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular order sub
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2SubModOrd
	.type	ECP_Sm2SubModOrd, @function
	.align	64

ECP_Sm2SubModOrd:

	bn_mod_sub(.Lord(%rip))

	ret
	.size ECP_Sm2SubModOrd, .-ECP_Sm2SubModOrd

.macro	RDC
	# r = a mod p256
	# a = a15 | a14 | ... | a0, where ai are 32–bit quantities
	# |  a7 |  a6 |  a5 |  a4 |  a3 |  a2 |  a1 |  a0 | (+)
	# |  a8 | a11 | a10 |  a9 |  a8 |   0 |  a9 |  a8 | (+)
	# |  a9 | a14 | a13 | a12 | a11 |   0 | a10 |  a9 | (+)
	# | a10 | a15 | a14 | a13 | a12 |   0 | a11 | a10 | (+)
	# | a11 |   0 | a15 | a14 | a13 |   0 | a12 | a11 | (+)
	# | a12 |   0 | a15 | a14 | a13 |   0 | a13 | a12 | (+)
	# | a12 |   0 |   0 | a15 | a14 |   0 | a14 | a13 | (+)
	# | a13 |   0 |   0 |   0 | a15 |   0 | a14 | a13 | (+)
	# | a13 |   0 |   0 |   0 |   0 |   0 | a15 | a14 | (+)
	# | a14 |   0 |   0 |   0 |   0 |   0 | a15 | a14 | (+)
	# | a14 |   0 |   0 |   0 |   0 |   0 |   0 | a15 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 | a15 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	# |   0 |   0 |   0 |   0 |   0 | a8  |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a9  |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a13 |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a14 |   0 |   0 | (-)
	# | U[7]| U[6]| U[5]| U[4]| U[3]| U[2]| U[1]| U[0]|
	# |    V[3]   |    V[2]   |   V[1]    |    V[0]   |
	# until r < p256
	# s7 (a15|a14), s6 (a13|a12), s5 (a11|a10), s4 (a9|a8)
	# s3 (a7|a6), s2 (a5|a4), s1 (a3|a2), s0 (a1|a0)

	# 1. 64-bit addition
	xorq	%rsi, %rsi		# to store all carry
	xorq	%rax, %rax
	movq	s6, %rcx		# rcx <- s6
	movq	s4, %rdx		# rdx <- s4
	# a13 | a12
	addq	s7, %rcx		# rcx <- s6 + s7
	adcq	$0, %rax		# rax <- carry(s6+s7)
	addq	s7, %rcx		# rcx <- s6 + 2*s7
	adcq	$0, %rax
	# a9 | a8
	movq	%rax, %rbx		# rbx <- carry (rax)
	addq	%rcx, %rdx		# rdx <- s4 + s6 + 2*s7
	adcq	$0, %rbx
	addq	s5, %rdx		# rdx <- s4 + s5 + s6 + 2*s7
	adcq	$0, %rbx
	# sum
	addq	%rdx, s0		# s0 <- s0 + s4 + s5 + s6 + 2*s7
	adcq	%rbx, s1		# s1 <- s1 + rbx + carry
	adcq	%rcx, s2		# s2 <- s2 + s6 + 2*s7 + carry
	adcq	s7, s3			# s3 <- s3 + s7 + carry
	adcq	$0, %rsi
	# add carry
	addq	%rax, s3
	adcq	$0, %rsi		# rsi <- carry
	# store registers
	movq	s0, (%rsp)
	movq	s1, 8(%rsp)
	movq	s2, 16(%rsp)
	movq	s3, 24(%rsp)
	# 2. 4 -> 8  64-bit to 32-bit spread
	movq	$0xffffffff, %rax
	movq	s4, s0
	movq	s5, s1
	movq	s6, s2
	movq	s7, s3
	andq	%rax, s0	# a8
	andq	%rax, s1	# a10
	andq	%rax, s2	# a12
	andq	%rax, s3	# a14
	shrq	$32, s4		# a9
	shrq	$32, s5		# a11
	shrq	$32, s6		# a13
	shrq	$32, s7		# a15
	# 3. 32-bit addition
	movq	s3, %rax
	addq	s2, %rax	# rax <- a12 + a14
	movq	s3, %rbx
	addq	s1, %rbx	# rbx <- a10 + a14
	movq	s7, %rcx
	addq	s6, %rcx	# rcx <- a13 + a15
	movq	s0, %rdx
	addq	s4, %rdx	# rdx <- a8 + a9
	addq	s5, s7		# s7 <-  a11 + a15
	movq	%rcx, s2	# s2 <- a13 + a15
	addq	%rax, s2	# s2 <- a12 + a13 + a14 + a15
	addq	s2, s1		# s1 <- a10 + a12 + a13 + a14 + a15
	addq	s2, s1		# s1 <- a10 + 2*(a12 + a13 + a14 + a15)
	addq	%rdx, s1	# s1 <- a8 + a9 + a10 + 2*(a12 + a13 + a14 + a15)
	addq	s5, s1		# s1 <- a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	addq	s6, s2		# s2 <- a12 + 2*a13 + a14 + a15
	addq	s5, s2		# s2 <- a11 + a12 + 2*a13 + a14 + a15
	addq	s0, s2		# s2 <- a8 + a11 + a12 + 2*a13 + a14 + a15
	addq	s3, %rdx	# rdx <- a8 + a9 + a14
	addq	s6, %rdx	# rdx <- a8 + a9 + a13 + a14
	addq	%rcx, s4	# s4 <- a9 + a13 + a15
	addq	s4, s5		# s5 <- a9 + a11 + a13 + a15
	addq	%rcx, s5	# s5 <- a9 + a11 + 2*(a13 + a15)
	addq	%rbx, %rax	# rax <- a10 + a12 + 2*a14

	# U[0]	s5		a9 + a11 + 2*(a13 + a15)
	# U[1]	%rax	a10 + a12 + 2*a14
	# U[2]
	# U[3]	s2		a8 + a11 + a12 + 2*a13 + a14 + a15
	# U[4]	s4		a9 + a13 + a15
	# U[5]	%rbx	a10 + a14
	# U[6]	s7		a11 + a15
	# U[7]	s1		a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	# sub	%rdx	a8 + a9 + a13 + a14

	# vacant registers: s0 s3 s6  %rcx

	# 4. 8 -> 4  32-bit to 64-bit
	# sub %rdx
	movq	%rax, s0
	shlq	$32, s0			# U[1]'(s0) <- U[1] << 32
	shrd	$32, s2, %rax	# U[3]'(%rax) <- U[3]U[1] >> 32
	shrd	$32, %rbx, s2	# U[5]'(s2) <- U[5]U[3] >> 32
	shrd	$32, s1, %rbx	# U[7]'(%rbx) <- U[7]U[5] >> 32
	shrq	$32, s1			# U[7](s1) <- U[7] >> 32 (carry)

	# 5. 64-bit addition
	addq	s0, s5			# U[0] <- U[1]' + U[0]
	adcq	$0, %rax		# U[3]' <- 0 + U[3]'
	adcq	s2, s4			# U[4] <- U[5]' + U[4]
	adcq	%rbx, s7		# U[6] <- U[7]' + U[6]
	adcq	s1, %rsi		# rsi <- U[7]carry + carry

	# V[0] s5
	# V[1] %rax
	# V[2] s4
	# V[3] s7
	# carry %rsi
	# sub %rdx

	# 5. ADD & SUB
	movq	(%rsp), s0
	movq	8(%rsp), s1
	movq	16(%rsp), s2
	movq	24(%rsp), s3
	# ADD
	addq s5, s0
	adcq %rax, s1
	adcq s4, s2
	adcq s7, s3
	adcq $0, %rsi
	# SUB
	subq %rdx, s1
	sbbq $0, s2
	sbbq $0, s3
	sbbq $0, %rsi

	# 6. MOD
	# First Mod
	movq %rsi, %rax		# rax <- carry (rsi)			+out[0]
	shlq $32, %rax		# rax <- carry << 32
	movq %rax, %rcx		# rcx <- rax					+out[3]
	subq %rsi, %rax		# rax <- carry << 32 - carry	+out[1]

	addq %rsi, s0
	adcq %rax, s1
	adcq $0, s2
	adcq %rcx, s3

	# Last Mod
	# return r - p if r > p else r
	movq	s0, s4
	movq	s1, s5
	movq	s2, s6
	movq	s3, s7

	leaq	.Lpoly(%rip), %rsi

	movq	$0, %rcx
	adcq	$0, %rcx

	subq	0(%rsi), s0
	sbbq	8(%rsi), s1
	sbbq	16(%rsi), s2
	sbbq	24(%rsi), s3
	sbbq	$0, %rcx

	cmovcq	s4, s0
	cmovcq	s5, s1
	cmovcq	s6, s2
	cmovcq	s7, s3

	movq	s0, (%rdi)
	movq	s1, 8(%rdi)
	movq	s2, 16(%rdi)
	movq	s3, 24(%rdi)
.endm

### Modular mul: r = a*b mod p ###
	# void ECP_Sm2Mul(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# 256-bit modular multiplication in SM2
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2Mul
	.type	ECP_Sm2Mul, @function
	.align	64

ECP_Sm2Mul:

	# Store scalar registers
	subq	$72, %rsp
	movq	%rbx, 32(%rsp)
	movq	%r12, 40(%rsp)
	movq	%r13, 48(%rsp)
	movq	%r14, 56(%rsp)
	movq	%r15, 64(%rsp)

	# Load inputs
	movq	(%rsi), s0
	movq	8(%rsi), s1
	movq	16(%rsi), s2
	movq	24(%rsi), s3
	movq	(%rdx), s4
	movq	8(%rdx), s5
	movq	16(%rdx), s6
	movq	24(%rdx), s7

### multiplication ###

	# ========================
	#             s7 s6 s5 s4
	# *           s3 s2 s1 s0
	# ------------------------
	# +           s0 s0 s0 s0
	#              *  *  *  *
	#             s7 s6 s5 s4
	#          s1 s1 s1 s1
	#           *  *  *  *
	#          s7 s6 s5 s4
	#       s2 s2 s2 s2
	#        *  *  *  *
	#       s7 s6 s5 s4
	#    s3 s3 s3 s3
	#     *  *  *  *
	#    s7 s6 s5 s4
	# ------------------------
	# s7 s6 s5 s4 s3 s2 s1 s0
	# ========================

### s0*s4 ###
	movq	s0, %rax
	mulq	s4
	movq	%rax, (%rsp)
	movq	%rdx, %rbx
	xorq	%rcx, %rcx

### s1*s4 + s0*s5 ###
	movq	s1, %rax
	mulq	s4
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	xorq	%rsi, %rsi

	movq	s0, %rax
	mulq	s5
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%rbx, 8(%rsp)
	xorq	%rbx, %rbx

### s2 * s4 + s1 * s5 + s0 *s6 ###
	movq	s2, %rax
	mulq	s4
	addq	%rax, %rcx
	adcq	%rdx, %rsi

	movq	s1, %rax
	mulq	s5
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %rbx

	movq	s0, %rax
	mulq	s6
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %rbx
	movq	%rcx, 16(%rsp)
	xorq	%rcx, %rcx

### s3*s4 + s2*s5 + s1*s6 + s0*s7 ###
	movq	s3, %rax
	mulq	s4
	addq	%rax, %rsi
	adcq	%rdx, %rbx
	adcq	$0, %rcx

	movq	s2, %rax 
	mulq	s5
	addq	%rax, %rsi
	adcq	%rdx, %rbx
	adcq	$0, %rcx

	movq	s1, %rax
	mulq	s6
	addq	%rax, %rsi
	adcq	%rdx, %rbx
	adcq	$0, %rcx

	movq	s0, %rax
	mulq	s7
	addq	%rax, %rsi
	adcq	%rdx, %rbx
	adcq	$0, %rcx
	movq	%rsi, 24(%rsp)
	xorq	%rsi, %rsi

### s3*s5 + s2*s6 + s1*s7 ###
	movq	s3, %rax
	mulq	s5
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	# carry
	adcq	$0, %rsi

	movq	s2, %rax
	mulq	s6
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	adcq	$0, %rsi

	movq	s1, %rax
	mulq	s7
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	adcq	$0, %rsi
	movq	%rbx, s4
	xorq	%rbx, %rbx

### s3*s6 + s2*s7 ###
	movq	s3, %rax
	mulq	s6
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	# carry
	adcq $0, %rbx

	movq	s2, %rax
	mulq	s7
	addq	%rax, %rcx
	adcq	%rdx, %rsi
	adcq	$0, %rbx
	movq	%rcx, s5

### s3*s7 ###
	movq	s3, %rax
	mulq	s7
	addq	%rax, %rsi
	adcq	%rdx, %rbx
	movq	%rsi, s6
	movq	%rbx, s7

	movq	(%rsp), s0
	movq	8(%rsp), s1
	movq	16(%rsp), s2
	movq	24(%rsp), s3

	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0

### Reduction ###
	RDC

	# Restore scalar registers
	movq	32(%rsp), %rbx
	movq	40(%rsp), %r12
	movq	48(%rsp), %r13
	movq	56(%rsp), %r14
	movq	64(%rsp), %r15
	addq	$72, %rsp

	ret
	.size ECP_Sm2Mul, .-ECP_Sm2Mul

### Modular sqr: r = a^2 mod p ###
	# void ECP_Sm2Sqr(uint64_t *r, const uint64_t *a)
	# 256-bit modular multiplication in SM2 ### 
	# r 	%rdi
	# a 	%rsi
	.globl	ECP_Sm2Sqr
	.type	ECP_Sm2Sqr, @function
	.align	64

ECP_Sm2Sqr:

	# Store scalar registers
	subq	$88, %rsp
	movq	%rbx, 32(%rsp)
	movq	%r12, 40(%rsp)
	movq	%r13, 48(%rsp)
	movq	%r14, 56(%rsp)
	movq	%r15, 64(%rsp)
	movq	%rbp, 72(%rsp)
	movq	%rdi, 80(%rsp)

	# Load inputs
	movq	(%rsi), s4
	movq	8(%rsi), s5
	movq	16(%rsi), s6
	movq	24(%rsi), s7

### square ###

	# ========================
	#             s7 s6 s5 s4
	# *           s7 s6 s5 s4
	# ------------------------
	# +           s4 s4 s4 s4
	#              *  *  *  *
	#             s7 s6 s5 s4
	#          s5 s5 s5 s5
	#           *  *  *  *
	#          s7 s6 s5 s4
	#       s6 s6 s6 s6
	#        *  *  *  *
	#       s7 s6 s5 s4
	#    s7 s7 s7 s7
	#     *  *  *  *
	#    s7 s6 s5 s4
	# ------------------------
	# s7 s6 s5 s4 s3 s2 s1 s0
	# ========================

### s1 <- s4*s5, s2 <- carry ###
	movq	s5, %rax
	mulq	s4
	movq	%rax, s1
	movq	%rdx, s2
	xorq	s3, s3

### s2 <- s4*s6 + carry(s2), s3 <- carry ###
	movq	s6, %rax
	mulq	s4
	addq	%rax, s2
	adcq	%rdx, s3
	xorq	s0, s0

### s3 <- s4*s7 + s5*s6 + carry(s3), s0 <- carry ###
	movq	s7, %rax
	mulq	s4
	addq	%rax, s3
	adcq	%rdx, s0
	xorq	%rbx, %rbx

	movq	s6, %rax
	mulq	s5
	addq	%rax, s3
	adcq	%rdx, s0
	adcq	$0, %rbx

### s0 <- s5*s7 + carry(s0), rbx <- carry ###
	movq	s7, %rax
	mulq	s5
	addq	%rax, s0
	adcq	%rdx, %rbx
	xorq	%rcx, %rcx

### rbx <- s6*s7 + carry(rbx), rcx <- carry ###
	movq	s7, %rax
	mulq	s6
	addq	%rax, %rbx
	adcq	%rdx, %rcx
	xorq	%rsi, %rsi

### 2*s0|1|2|3 ###
	addq	s1, s1
	adcq	s2, s2
	adcq	s3, s3
	adcq	s0, s0
	adcq	%rbx, %rbx
	# update carry
	adcq	%rcx, %rcx
	adcq	$0, %rsi
### rbp <- s4*s4, carry <- rdi ###
	movq	s4, %rax
	mulq	s4
	movq	%rax, %rbp
	movq	%rdx, %rdi

### s4 <- s5*s5, carry <- s5 ###
	movq	s5, %rax
	mulq	s5
	movq	%rax, s4
	movq	%rdx, s5

### s6*s6 ###
	movq	s6, %rax
	mulq	s6

	# s1 += carry(s4*s4)
	addq	%rdi, s1
	# s2 += s5*s5
	adcq	s4, s2
	# s3 += carry(s5*s5)
	adcq	s5, s3
	# s4(s0) += s6*s6
	adcq	%rax, s0
	# s5(rbx) += carry(s6*s6)
	adcq	%rdx, %rbx
	adcq	$0, %rcx
	adcq	$0, %rsi

### s7*s7 ###
	movq	s7, %rax
	mulq	s7
	# s6(rcx) += s7*s7
	addq	%rax, %rcx
	# s7(rsi) += carry(s7*s7)
	adcq	%rdx, %rsi

	movq	s0, s4
	movq	%rbp, s0
	movq	%rbx, s5
	movq	%rcx, s6
	movq	%rsi, s7

	# Restore rdi
	movq	80(%rsp), %rdi

	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0

### Reduction ###
	RDC

	# Restore scalar registers
	movq	32(%rsp), %rbx
	movq	40(%rsp), %r12
	movq	48(%rsp), %r13
	movq	56(%rsp), %r14
	movq	64(%rsp), %r15
	movq	72(%rsp), %rbp
	addq	$88, %rsp

	ret
	.size ECP_Sm2Sqr, .-ECP_Sm2Sqr

#endif