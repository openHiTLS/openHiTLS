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

.macro	REGISTER_SAVE
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushq	%rbx
	pushq	%rbp
.endm

.macro	REGISTER_POP
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
.endm

# The polynomial
.align	64
.Lpoly:
.quad	0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff
# The order of polynomial
.Lord:
.quad	0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff

.Lpoly_div_2:
.quad	0x8000000000000000, 0xffffffff80000000, 0xffffffffffffffff, 0x7fffffff7fffffff
.Lord_div_2:
.quad	0xa9ddfa049ceaa092, 0xb901efb590e30295, 0xffffffffffffffff, 0x7fffffff7fffffff

.Lzero:
.quad	0, 0, 0, 0
.Lord_1div4:
.quad	0xd4eefd024e755049, 0xdc80f7dac871814a, 0xffffffffffffffff, 0x3fffffffbfffffff
.Lord_2div4:
.quad	0xa9ddfa049ceaa092, 0xb901efb590e30295, 0xffffffffffffffff, 0x7fffffff7fffffff
.Lord_3div4:
.quad	0x7eccf706eb5ff0db, 0x9582e790595483e0, 0xffffffffffffffff, 0xbfffffff3fffffff

.Lpoly_1div4:
.quad	0x4000000000000000, 0xffffffffc0000000, 0xffffffffffffffff, 0x3fffffffbfffffff
.Lpoly_2div4:
.quad	0x8000000000000000, 0xffffffff80000000, 0xffffffffffffffff, 0x7fffffff7fffffff
.Lpoly_3div4:
.quad	0xc000000000000000, 0xffffffff40000000, 0xffffffffffffffff, 0xbfffffff3fffffff

.LRR:// 2^512 mod P precomputed for sm2 polynomial
.quad	0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0000000400000002
.Lone_mont:
.quad	0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000
.Lone:
.quad	1,0,0,0
.LOne:
.long	1,1,1,1,1,1,1,1

.globl	ECP_Sm2Div2
.type	ECP_Sm2Div2,@function
.align	64

ECP_Sm2Div2:

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11

	shrdq	$1,%r9,%r8
	shrdq	$1,%r10,%r9
	shrdq	$1,%r11,%r10
	shrq	$1,%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	ret
.size	ECP_Sm2Div2, .-ECP_Sm2Div2

.globl	ECP_Sm2Div4
.type	ECP_Sm2Div4,@function
.align	64

ECP_Sm2Div4:

	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11

	shrdq	$2,%r9,%r8
	shrdq	$2,%r10,%r9
	shrdq	$2,%r11,%r10
	shrq	$2,%r11
	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	ret
.size	ECP_Sm2Div4, .-ECP_Sm2Div4

.globl	ECP_Sm2Neg
.type	ECP_Sm2Neg,@function
.align	64

ECP_Sm2Neg:
	movq	(%rdi),%r8
	xorq	%rax,%rax

	movq	$-1,%r8
	movq	$0xffffffff00000000,%r9
	movq	$0xfffffffeffffffff,%r11
	movq	$-1,%r10

	subq	0(%rsi),%r8
	sbbq	8(%rsi),%r9
	sbbq	16(%rsi),%r10
	sbbq	24(%rsi),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	ret
.size	ECP_Sm2Neg, .-ECP_Sm2Neg

.globl	ECP_Sm2BnSub
.type	ECP_Sm2BnSub,@function
.align	64

ECP_Sm2BnSub:

	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	subq	(%rdx),%r8
	sbbq	8(%rdx),%r9
	sbbq	16(%rdx),%r10
	sbbq	24(%rdx),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)
	ret
.size	ECP_Sm2BnSub, .-ECP_Sm2BnSub

.globl	ECP_Sm2BnAdd
.type	ECP_Sm2BnAdd,@function
.align	64

ECP_Sm2BnAdd:

	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	addq	(%rdx),%r8
	adcq	8(%rdx),%r9
	adcq	16(%rdx),%r10
	adcq	24(%rdx),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)
	ret
.size	ECP_Sm2BnAdd, .-ECP_Sm2BnAdd

.globl	ECP_Sm2Div2ModP
.type	ECP_Sm2Div2ModP,@function
.align	64

ECP_Sm2Div2ModP:

	subq	$24,%rsp
	movq	%rbx,(%rsp)
	movq	%r12,8(%rsp)
	movq	%r13,16(%rsp)
	xorq	%r12,%r12

	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	movq	%r8,%r13
	andq	$1,%r13
	shrdq	$1,%r9,%r8
	shrdq	$1,%r10,%r9
	shrdq	$1,%r11,%r10
	shrdq	$1,%r12,%r11

	leaq	.Lzero(%rip),%rax
	leaq	.Lpoly_div_2(%rip),%rbx
	cmpq	$1,%r13
	cmoveq	%rbx,%rax

	addq	(%rax),%r8
	adcq	8(%rax),%r9
	adcq	16(%rax),%r10
	adcq	24(%rax),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	movq	(%rsp),%rbx
	movq	8(%rsp),%r12
	movq	16(%rsp),%r13
	addq	$24,%rsp
	ret
.size	ECP_Sm2Div2ModP, .-ECP_Sm2Div2ModP

.globl	ECP_Sm2Div2ModOrd
.type	ECP_Sm2Div2ModOrd,@function
.align	64

ECP_Sm2Div2ModOrd:

	subq	$24,%rsp
	movq	%rbx,(%rsp)
	movq	%r12,8(%rsp)
	movq	%r13,16(%rsp)
	xorq	%r12,%r12

	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	movq	%r8,%r13
	andq	$1,%r13
	shrdq	$1,%r9,%r8
	shrdq	$1,%r10,%r9
	shrdq	$1,%r11,%r10
	shrdq	$1,%r12,%r11

	leaq	.Lzero(%rip),%rax
	leaq	.Lord_div_2(%rip),%rbx
	cmpq	$1,%r13
	cmoveq	%rbx,%rax

	addq	(%rax),%r8
	adcq	8(%rax),%r9
	adcq	16(%rax),%r10
	adcq	24(%rax),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	movq	(%rsp),%rbx
	movq	8(%rsp),%r12
	movq	16(%rsp),%r13
	addq	$24,%rsp
	ret
.size	ECP_Sm2Div2ModOrd, .-ECP_Sm2Div2ModOrd

.globl	ECP_Sm2Div4ModP
.type	ECP_Sm2Div4ModP,@function
.align	64

ECP_Sm2Div4ModP:

	subq	$24,%rsp
	movq	%rbx,(%rsp)
	movq	%r12,8(%rsp)
	movq	%r13,16(%rsp)
	xorq	%r12,%r12

	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	movq	%r8,%r13
	andq	$3,%r13
	shrdq	$2,%r9,%r8
	shrdq	$2,%r10,%r9
	shrdq	$2,%r11,%r10
	shrdq	$2,%r12,%r11

	leaq	.Lzero(%rip),%rax
	leaq	.Lpoly_1div4(%rip),%rbx
	leaq	.Lpoly_2div4(%rip),%rcx
	leaq	.Lpoly_3div4(%rip),%rdx

	cmpq	$1,%r13
	cmoveq	%rbx,%rax
	cmpq	$2,%r13
	cmoveq	%rcx,%rax
	cmpq	$3,%r13
	cmoveq	%rdx,%rax


	addq	(%rax),%r8
	adcq	8(%rax),%r9
	adcq	16(%rax),%r10
	adcq	24(%rax),%r11


	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	movq	(%rsp),%rbx
	movq	8(%rsp),%r12
	movq	16(%rsp),%r13
	addq	$24,%rsp
	ret
.size	ECP_Sm2Div4ModP, .-ECP_Sm2Div4ModP

.globl	ECP_Sm2Div4ModOrd
.type	ECP_Sm2Div4ModOrd,@function
.align	64

ECP_Sm2Div4ModOrd:

	subq	$24,%rsp
	movq	%rbx,(%rsp)
	movq	%r12,8(%rsp)
	movq	%r13,16(%rsp)
	xorq	%r12,%r12


	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11

	movq	%r8,%r13
	andq	$3,%r13
	shrdq	$2,%r9,%r8
	shrdq	$2,%r10,%r9
	shrdq	$2,%r11,%r10
	shrdq	$2,%r12,%r11

	leaq	.Lzero(%rip),%rax
	leaq	.Lord_1div4(%rip),%rbx
	leaq	.Lord_2div4(%rip),%rcx
	leaq	.Lord_3div4(%rip),%rdx

	cmpq	$1,%r13
	cmoveq	%rbx,%rax
	cmpq	$2,%r13
	cmoveq	%rcx,%rax
	cmpq	$3,%r13
	cmoveq	%rdx,%rax

	addq	(%rax),%r8
	adcq	8(%rax),%r9
	adcq	16(%rax),%r10
	adcq	24(%rax),%r11

	movq	%r8,(%rdi)
	movq	%r9,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r11,24(%rdi)

	movq	(%rsp),%rbx
	movq	8(%rsp),%r12
	movq	16(%rsp),%r13
	addq	$24,%rsp
	ret
.size	ECP_Sm2Div4ModOrd, .-ECP_Sm2Div4ModOrd

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
	# void ECP_Sm2AddModP(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular poly add
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2AddModP
	.type	ECP_Sm2AddModP, @function
	.align	64

ECP_Sm2AddModP:

	bn_mod_add(.Lpoly(%rip))
	
	ret
	.size ECP_Sm2AddModP, .-ECP_Sm2AddModP

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
	# void ECP_Sm2SubModP(uint64_t *r, const uint64_t *a, const uint64_t *b)
	# Modular poly sub
	# r		%rdi
	# a		%rsi
	# b		%rdx
	.globl	ECP_Sm2SubModP
	.type	ECP_Sm2SubModP, @function
	.align	64

ECP_Sm2SubModP:

	bn_mod_sub(.Lpoly(%rip))
	
	ret
	.size ECP_Sm2SubModP, .-ECP_Sm2SubModP

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

.globl	ECP_Sm2ToMont
.type	ECP_Sm2ToMont,@function
.align	32
ECP_Sm2ToMont:
	leaq	.LRR(%rip), %rdx
	REGISTER_SAVE
	movq	0(%rsi), %r9
	movq	8(%rsi), %r10
	movq	16(%rsi), %r11
	movq	24(%rsi), %r12
	movq	%rdx, %rbx
	movq	0(%rdx), %rax

	call	ECP_Sm2MulMont

	REGISTER_POP
	ret
.size	ECP_Sm2ToMont,.-ECP_Sm2ToMont

.type	ECP_Sm2MulMont,@function
.align	32
ECP_Sm2MulMont:

	// a[0~3] * b[0]
	movq	%rax, %rbp
	mulq	%r9
	movq	%rax, %r8
	movq	%rdx, %r9
	movq	%rbp, %rax

	mulq	%r10
	addq	%rax, %r9
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %r10

	mulq	%r11
	addq	%rax, %r10
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %r11

	mulq	%r12
	addq	%rax, %r11
	adcq	$0, %rdx
	movq	%rdx, %r12
	movq	%r8, %rax
	movq	%r8, %r14
	xorq	%r13, %r13

	// begin 1st reduce
	shlq	$32, %rax
	shrq	$32, %r14

	movq	%r8, %rcx
	subq	%rax, %rcx
	movq	$0, %rdx
	sbbq	%r14, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%r14, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	%r12, %r11
	movq	$0, %r12
	adcq	%r13, %r12
	movq	8(%rbx), %rax // b[1]

	movq	%rax, %rbp
	mulq	0(%rsi)
	addq	%rax, %r8
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	8(%rsi)
	addq	%rcx, %r9
	adcq	$0, %rdx
	addq	%rax, %r9
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	16(%rsi)
	addq	%rcx, %r10
	adcq	$0, %rdx
	addq	%rax, %r10
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	24(%rsi)
	addq	%rcx, %r11
	adcq	$0, %rdx
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	adcq	$0, %r13

	movq	%r8, %rax
	movq	%r8, %r14

	// begin 2st reduce
	shlq	$32, %rax
	shrq	$32, %r14

	movq	%r8, %rcx
	subq	%rax, %rcx
	movq	$0, %rdx
	sbbq	%r14, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%r14, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	%r12, %r11
	movq	$0, %r12
	adcq	%r13, %r12
	movq	16(%rbx), %rax // b[2]

	movq	%rax, %rbp
	mulq	0(%rsi)
	addq	%rax, %r8
	movq	%rbp, %rax
	adcq	$0, %rdx
	movq	%rdx, %rcx

	mulq	8(%rsi)
	addq	%rcx, %r9
	adcq	$0, %rdx
	addq	%rax, %r9
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	16(%rsi)
	addq	%rcx, %r10
	adcq	$0, %rdx
	addq	%rax, %r10
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	24(%rsi)
	addq	%rcx, %r11
	adcq	$0, %rdx
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	adcq	$0, %r13

	movq	%r8, %rax
	movq	%r8, %r14

	// begin 3st reduce
	shlq	$32, %rax
	shrq	$32, %r14

	movq	%r8, %rcx
	movq	$0, %rdx
	subq	%rax, %rcx
	sbbq	%r14, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	sbbq	%r14, %r8
	movq	%rdx, %rax
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	%r12, %r11
	movq	$0, %r12
	adcq	%r13, %r12
	movq	24(%rbx), %rax // b[3]

	movq	%rax, %rbp
	mulq	0(%rsi)
	addq	%rax, %r8
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	8(%rsi)
	addq	%rcx, %r9
	adcq	$0, %rdx
	addq	%rax, %r9
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	16(%rsi)
	addq	%rcx, %r10
	adcq	$0, %rdx
	addq	%rax, %r10
	adcq	$0, %rdx
	movq	%rbp, %rax
	movq	%rdx, %rcx

	mulq	24(%rsi)
	addq	%rcx, %r11
	adcq	$0, %rdx
	addq	%rax, %r11
	adcq	%rdx, %r12
	adcq	$0, %r13
	movq	%r9, %rax

	movq	%r8, %rax
	movq	%r8, %r14

	// last reduction begin
	shlq	$32, %rax
	shrq	$32, %r14

	movq	%r8, %rcx
	subq	%rax, %rcx
	movq	$0, %rdx
	sbbq	%r14, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%r14, %r8
	movq	%r8, %rdx
	movq	%rcx, %r8

	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	%r12, %r11
	movq	$0, %rcx
	adcq	%r13, %rcx
	// last reduction end

	// ret - p
	movq	%r8, %r12
	subq	$-1, %r12
	movq	.Lpoly+8(%rip), %r14
	movq	%r9, %r13
	sbbq	%r14, %r13

	movq	%r10, %rbp
	sbbq	$-1, %rbp

	movq	.Lpoly+24(%rip), %r15
	movq	%r11, %rdx
	sbbq	%r15, %rdx
	sbbq	$0, %rcx

	cmovcq	%r8, %r12
	cmovcq	%r9, %r13
	cmovcq	%r10, %rbp
	movq	%r12,(%rdi)
	movq	%r13,8(%rdi)
	cmovcq	%r11, %rdx
	movq	%rbp,16(%rdi)
	movq	%rdx,24(%rdi)

	movq	%rbp, %r8
	movq	%rdx, %r9
	ret
.size	ECP_Sm2MulMont, .-ECP_Sm2MulMont

.globl	ECP_Sm2FromMont
.type	ECP_Sm2FromMont,@function
.align	32
ECP_Sm2FromMont:

	leaq	.Lone(%rip), %rdx
	REGISTER_SAVE
	movq	%rdx, %rbx
	movq	0(%rsi), %r9
	movq	8(%rsi), %r10
	movq	16(%rsi), %r11
	movq	24(%rsi), %r12
	movq	0(%rdx), %rax

	call	ECP_Sm2MulMont

	REGISTER_POP
	ret
.size	ECP_Sm2FromMont,.-ECP_Sm2FromMont

.type	ECP_Sm2SqrMont,@function
.align	32
ECP_Sm2SqrMont:

	movq	%rax, %r13
	mulq	%r14		// a[0] * a[1]
	movq	%rax, %r9
	movq	%rdx, %r10
	movq	%r15, %rax

	mulq	%r13		// a[0] * a[2]
	addq	%rax, %r10
	adcq	$0, %rdx
	movq	%r8, %rax
	movq	%rdx, %r11

	mulq	%r13		// a[0] * a[3]
	addq	%rax, %r11
	adcq	$0, %rdx
	movq	%r15, %rax
	movq	%rdx, %r12

	mulq	%r14		// a[1] * a[2]
	addq	%rax, %r11
	adcq	$0, %rdx
	movq	%r8, %rax
	movq	%rdx, %rbp

	mulq	%r14		// a[1] * a[3]
	addq	%rax, %r12
	adcq	$0, %rdx
	addq	%rbp, %r12
	movq	%rdx, %r13
	movq	%r8, %rax
	adcq	$0, %r13

	mulq	%r15		// a[2] * a[3]
	addq	%rax, %r13
	movq	(%rsi), %rax
	movq	%rdx, %r14
	adcq	$0, %r14

	movq	$0, %r15
	addq	%r9, %r9
	adcq	%r10, %r10
	adcq	%r11, %r11
	adcq	%r12, %r12
	adcq	%r13, %r13
	adcq	%r14, %r14
	adcq	$0, %r15

	mulq	%rax		// cal a[0] * a[0]
	movq	%rax, %r8
	movq	8(%rsi), %rax // get a[1]
	movq	%rdx, %rcx

	mulq	%rax		// a[1] * a[1]
	addq	%rcx, %r9
	adcq	%rax, %r10
	adcq	$0, %rdx
	movq	16(%rsi), %rax
	movq	%rdx, %rcx

	mulq	%rax		// a[2] * a[2]
	addq	%rcx, %r11
	adcq	%rax, %r12
	adcq	$0, %rdx
	movq	24(%rsi), %rax
	movq	%rdx, %rcx

	mulq	%rax		// a[3] * a[3]
	addq	%rcx, %r13
	adcq	%rax, %r14
	movq	%r8, %rax
	adcq	%rdx, %r15

	movq	%r8, %rax
	movq	%r8, %rsi

	// begin 1st reduce
	shlq	$32, %rax
	shrq	$32, %rsi
	movq	%r8, %rcx
	subq	%rax, %rcx

	movq	$0, %rdx
	sbbq	%rsi, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%rsi, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	$0, %r11

	movq	%r8, %rax
	movq	%r8, %rsi

	// begin 2st reduce
	shlq	$32, %rax
	shrq	$32, %rsi
	movq	%r8, %rcx
	subq	%rax, %rcx

	movq	$0, %rdx
	sbbq	%rsi, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%rsi, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	$0, %r11

	movq	%r8, %rax
	movq	%r8, %rsi

	// begin 3st reduce
	shlq	$32, %rax
	shrq	$32, %rsi
	movq	%r8, %rcx
	subq	%rax, %rcx

	movq	$0, %rdx
	sbbq	%rsi, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%rsi, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	$0, %r11

	movq	%r8, %rax
	movq	%r8, %rsi

	// begin 4st reduce
	shlq	$32, %rax
	shrq	$32, %rsi
	movq	%r8, %rcx
	subq	%rax, %rcx

	movq	$0, %rdx
	sbbq	%rsi, %rdx
	movq	%rdx, %rbp
	movq	$0, %rdx
	sbbq	%rax, %rdx
	movq	%rdx, %rax
	sbbq	%rsi, %r8
	movq	%r8, %rdx

	movq	%rcx, %r8
	addq	%r9, %r8
	movq	%rbp, %r9
	adcq	%r10, %r9
	movq	%rax, %r10
	adcq	%r11, %r10
	movq	%rdx, %r11
	adcq	$0, %r11

	movq	.Lpoly+8(%rip), %rsi
	movq	.Lpoly+24(%rip), %rbp

	addq	%r8, %r12
	adcq	%r9, %r13
	adcq	%r10, %r14
	adcq	%r11, %r15
	movq	$0, %r11
	adcq	$0, %r11

	// ret - q
	movq	%r12, %rax
	subq	$-1, %rax
	movq	%r13, %rcx
	sbbq	%rsi, %rcx
	movq	%r14, %r8
	sbbq	$-1, %r8
	movq	%r15, %rdx
	sbbq	%rbp, %rdx
	sbbq	$0, %r11

	cmovncq	%rax, %r12
	cmovncq	%rcx, %r13
	cmovncq	%r8, %r14
	movq	%r12,(%rdi)
	movq	%r13,8(%rdi)
	cmovncq	%rdx, %r15
	movq	%r14,16(%rdi)
	movq	%r15,24(%rdi)
	ret
.size	ECP_Sm2SqrMont,.-ECP_Sm2SqrMont

.type	ECP_Sm2AddCore,@function
.align	32
ECP_Sm2AddCore:

	addq	(%rbx), %r12
	adcq	8(%rbx), %r13
	movq	%r12, %rcx
	adcq	16(%rbx), %r8
	adcq	24(%rbx), %r9
	movq	$0, %r11
	movq	%r13, %rbp
	adcq	$0, %r11

	subq	$-1, %r12	//  + 0xffffffffffffffff = -(-1)
	movq	%r8, %rax
	sbbq	%r14, %r13
	sbbq	$-1, %r8
	movq	%r9, %r10
	sbbq	%r15, %r9
	sbbq	$0, %r11

	cmovcq	%rcx, %r12
	cmovcq	%rbp, %r13
	movq	%r12, 0(%rdi)
	cmovcq	%rax, %r8
	movq	%r13, 8(%rdi)
	cmovcq	%r10, %r9
	movq	%r8, 16(%rdi)
	movq	%r9, 24(%rdi)

	ret
.size	ECP_Sm2AddCore,.-ECP_Sm2AddCore

.type	ECP_Sm2SubBA,@function
.align	32
ECP_Sm2SubBA:
	subq	%r12, %rcx
	sbbq	%r13, %rbp
	movq	%rcx, %r12
	sbbq	%r8, %rax
	sbbq	%r9, %r10
	movq	%rbp, %r13
	sbbq	%r11, %r11

	addq	$-1, %rcx
	movq	%rax, %r8
	adcq	%r14, %rbp
	adcq	$-1, %rax
	movq	%r10, %r9
	adcq	%r15, %r10
	testq	%r11, %r11

	cmovnzq	%rcx, %r12
	cmovnzq	%rbp, %r13
	cmovnzq	%rax, %r8
	cmovnzq	%r10, %r9
	ret
.size	ECP_Sm2SubBA,.-ECP_Sm2SubBA

.type	ECP_Sm2SubAB,@function
.align	32
ECP_Sm2SubAB:
	subq	0(%rbx), %r12
	sbbq	8(%rbx), %r13
	sbbq	16(%rbx), %r8
	sbbq	24(%rbx), %r9
	sbbq	%r11, %r11

	movq	%r14, %rbp
	andq	%r11, %rbp
	movq	%r11, %rax
	btrq	$32, %rax

	addq	%r11, %r12
	adcq	%rbp, %r13
	adcq	%r11, %r8
	adcq	%rax, %r9

	movq	%r12, (%rdi)
	movq	%r13, 8(%rdi)
	movq	%r8, 16(%rdi)
	movq	%r9, 24(%rdi)

	ret
.size	ECP_Sm2SubAB,.-ECP_Sm2SubAB

.type	ECP_Sm2MulBy2Core,@function
.align	32
ECP_Sm2MulBy2Core:
	addq	%r12, %r12
	adcq	%r13, %r13
	movq	%r12, %rcx
	adcq	%r8, %r8
	adcq	%r9, %r9
	movq	$0, %r11
	movq	%r13, %rbp
	adcq	$0, %r11

	subq	$-1, %r12	//  + 0xffffffffffffffff = -(-1)
	movq	%r8, %rax
	sbbq	%r14, %r13
	sbbq	$-1, %r8
	movq	%r9, %r10
	sbbq	%r15, %r9
	sbbq	$0, %r11

	cmovcq	%rcx, %r12
	cmovcq	%rbp, %r13
	cmovcq	%rax, %r8
	cmovcq	%r10, %r9

	movq	%r12, (%rdi)
	movq	%r13, 8(%rdi)
	movq	%r8, 16(%rdi)
	movq	%r9, 24(%rdi)
	ret
.size	ECP_Sm2MulBy2Core,.-ECP_Sm2MulBy2Core

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
# Deal process:
#     delta = Z12
#     gamma = Y12
#     beta = X1*gamma
#     alpha = 3*(X1-delta)*(X1+delta)
#     X3 = alpha2-8*beta
#     Z3 = (Y1+Z1)2-gamma-delta
#     Y3 = alpha*(4*beta-X3)-8*gamma2
.globl	ECP_Sm2PointDoubleMont
.type	ECP_Sm2PointDoubleMont,@function
.align	32
ECP_Sm2PointDoubleMont:
	REGISTER_SAVE
	subq	$168, %rsp

.Lpoint_double:
	vmovdqu	0(%rsi), %xmm0
	vmovdqu	16(%rsi), %xmm1
	vmovdqa	%xmm0,96(%rsp)
	vmovdqa	%xmm1,96+16(%rsp)

	movq	%rsi, %rbx
	leaq	32(%rdi), %r10
	leaq	64(%rdi), %r11
	vmovq	%rdi, %xmm0
	vmovq	%r10, %xmm1
	vmovq	%r11, %xmm2

	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r8
	movq	56(%rsi), %r9

	movq	.Lpoly+8(%rip), %r14
	movq	.Lpoly+24(%rip), %r15
	leaq	(%rsp), %rdi
	call	ECP_Sm2MulBy2Core

	movq	64(%rsi), %rax
	movq	72(%rsi), %r14
	movq	80(%rsi), %r15
	movq	88(%rsi), %r8

	leaq	64(%rsi), %rsi              // Setting Input Parameters
	leaq	64(%rsp), %rdi              // store the result
	call	ECP_Sm2SqrMont

	movq	(%rsp), %rax
	movq	8(%rsp), %r14
	movq	16(%rsp), %r15
	movq	24(%rsp), %r8
	leaq	(%rsp), %rsi
	leaq	(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	32(%rbx), %rax
	movq	64(%rbx), %r9
	movq	72(%rbx), %r10
	movq	80(%rbx), %r11
	movq	88(%rbx), %r12

	leaq	64(%rbx), %rsi
	leaq	32(%rbx), %rbx
	vmovq	%xmm2, %rdi
	call	ECP_Sm2MulMont
	call	ECP_Sm2MulBy2Core

	movq	96(%rsp), %r12
	movq	104(%rsp), %r13
	movq	112(%rsp), %r8
	movq	120(%rsp), %r9

	leaq	32(%rsp), %rdi
	leaq	64(%rsp), %rbx
	call	ECP_Sm2AddCore

	movq	96(%rsp), %r12
	movq	104(%rsp), %r13
	movq	112(%rsp), %r8
	movq	120(%rsp), %r9

	leaq	64(%rsp), %rbx  // intput
	leaq	64(%rsp), %rdi  // output
	call	ECP_Sm2SubAB

	movq	(%rsp), %rax
	movq	8(%rsp), %r14
	movq	16(%rsp), %r15
	movq	24(%rsp), %r8
	leaq	(%rsp), %rsi
	vmovq	%xmm1, %rdi

	call	ECP_Sm2SqrMont

	movq	%r12, %rcx
	addq	$-1, %r12
	movq	%r13, %r10
	adcq	%rsi, %r13
	movq	%r14, %rax
	adcq	$-1, %r14
	movq	$0, %r9
	movq	%r15, %r8
	adcq	%rbp, %r15
	adcq	$0, %r9
	xorq	%rsi, %rsi
	testq	$1, %rcx

	cmovzq	%rcx, %r12
	cmovzq	%r10, %r13
	cmovzq	%rax, %r14
	cmovzq	%r8, %r15
	cmovzq	%rsi, %r9

	movq	%r13, %rcx
	shrq	$1, %r12
	shlq	$63, %rcx
	shrq	$1, %r13
	movq	%r14, %r10
	orq		%rcx, %r12
	shlq	$63, %r10
	movq	%r15, %rax
	shrq	$1, %r14
	orq		%r10, %r13
	shlq	$63, %rax
	movq	%r12,0(%rdi)
	shrq	$1, %r15
	movq	%r13,8(%rdi)
	shlq	$63, %r9
	orq		%rax, %r14
	orq		%r9, %r15

	movq	%r14,16(%rdi)
	movq	%r15,24(%rdi)

	movq	64(%rsp), %rax
	leaq	64(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	32(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	128(%rsp), %rdi
	call	ECP_Sm2MulBy2Core

	leaq	32(%rsp), %rbx
	leaq	32(%rsp), %rdi
	call	ECP_Sm2AddCore

	movq	96(%rsp), %rax
	leaq	96(%rsp), %rbx
	movq	(%rsp), %r9
	movq	8(%rsp), %r10
	leaq	(%rsp), %rsi
	movq	16(%rsp), %r11
	movq	24(%rsp), %r12
	leaq	0(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	128(%rsp), %rdi
	call	ECP_Sm2MulBy2Core

	movq	32(%rsp), %rax
	movq	40(%rsp), %r14
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r15
	movq	56(%rsp), %r8
	vmovq	%xmm0, %rdi
	call	ECP_Sm2SqrMont

	leaq	128(%rsp), %rbx
	movq	%r14, %r8
	movq	%r15, %r9
	movq	%rsi, %r14
	movq	%rbp, %r15
	call	ECP_Sm2SubAB

	movq	(%rsp), %rcx
	movq	8(%rsp), %rbp
	movq	16(%rsp), %rax
	movq	24(%rsp), %r10
	leaq	0(%rsp), %rdi
	call	ECP_Sm2SubBA

	movq	32(%rsp), %rax
	leaq	32(%rsp), %rbx
	movq	%r12, %r14
	xorl	%ecx, %ecx
	movq	%r12,(%rsp)
	movq	%r13, %r10
	movq	%r13,8(%rsp)
	cmovzq	%r8, %r11
	movq	%r8,16(%rsp)
	cmovzq	%r9, %r12
	movq	%r9,24(%rsp)
	movq	%r14, %r9

	leaq	0(%rsp), %rsi
	leaq	0(%rsp), %rdi
	call	ECP_Sm2MulMont

	vmovq	%xmm1, %rbx
	vmovq	%xmm1, %rdi
	call	ECP_Sm2SubAB

	leaq	168(%rsp), %rsp
	REGISTER_POP
	ret
.size	ECP_Sm2PointDoubleMont,.-ECP_Sm2PointDoubleMont

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo
# Deal process:
#     U1 = X1*Z22
#     U2 = X2*Z12
#     S1 = Y1*Z23
#     S2 = Y2*Z13
#     H = U2-U1
#     r = S2-S1
#     X3 = r2-H3-2*U1*H2
#     Y3 = r*(U1*H2-X3)-S1*H3
#     Z3 = Z1*Z2*H
.globl	ECP_Sm2PointAddMont
.type	ECP_Sm2PointAddMont,@function
.align	32
ECP_Sm2PointAddMont:
	REGISTER_SAVE
	subq	$584, %rsp

	vmovdqu	0(%rsi), %xmm0
	vmovdqu	16(%rsi), %xmm1
	vmovdqu	32(%rsi), %xmm2
	vmovdqu	48(%rsi), %xmm3
	vmovdqu	64(%rsi), %xmm4
	vmovdqu	80(%rsi), %xmm5
	movq	%rsi, %rbx
	movq	%rdx, %rsi
	vmovdqa	%xmm0,384(%rsp)
	vmovdqa	%xmm1,384+16(%rsp)
	vmovdqa	%xmm2,416(%rsp)
	vmovdqa	%xmm3,416+16(%rsp)
	vmovdqa	%xmm4,448(%rsp)
	vmovdqa	%xmm5,448+16(%rsp)
	vpor     %xmm4, %xmm5, %xmm5

	vmovdqu	0(%rsi), %xmm0
	vpshufd	$0xb1, %xmm5, %xmm3
	vmovdqu	16(%rsi), %xmm1
	vmovdqu	32(%rsi), %xmm2
	vpor		%xmm3, %xmm5, %xmm5
	vmovdqu	48(%rsi), %xmm3

	movq	64(%rsi), %rax
	movq	72(%rsi), %r14
	movq	80(%rsi), %r15
	movq	88(%rsi), %r8

	vmovdqa	%xmm0,480(%rsp)
	vpshufd	$0x1e, %xmm5, %xmm4
	vmovdqa	%xmm1,480+16(%rsp)
	vmovdqu	64(%rsi), %xmm0
	vmovdqu	80(%rsi), %xmm1
	vmovdqa	%xmm2,512(%rsp)
	vmovdqa	%xmm3,512+16(%rsp)
	vpor	%xmm4, %xmm5, %xmm5
	vpxor	%xmm4, %xmm4, %xmm4
	vpor	%xmm0, %xmm1, %xmm1
	vmovq	%rdi, %xmm0

	leaq	64(%rsi), %rsi
	movq	%rax,544(%rsp)
	movq	%r14,544+8(%rsp)
	movq	%r15,544+16(%rsp)
	movq	%r8,544+24(%rsp)
	leaq	96(%rsp), %rdi
	call	ECP_Sm2SqrMont

	vpcmpeqd	%xmm4, %xmm5, %xmm5
	vpshufd		$0xb1, %xmm1, %xmm4
	vpor		%xmm1, %xmm4, %xmm4
	vpshufd		$0, %xmm5, %xmm5
	vpshufd		$0x1e, %xmm4, %xmm3
	vpor		%xmm3, %xmm4, %xmm4
	vpxor		%xmm3, %xmm3, %xmm3
	vpcmpeqd	%xmm3, %xmm4, %xmm4
	vpshufd		$0, %xmm4, %xmm4

	movq		64(%rbx), %rax
	movq		72(%rbx), %r14
	movq		80(%rbx), %r15
	movq		88(%rbx), %r8
	vmovq		%rbx, %xmm1

	leaq	64(%rbx), %rsi
	leaq	32(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	544(%rsp), %rax
	leaq	544(%rsp), %rbx
	movq	96(%rsp), %r9
	movq	104(%rsp), %r10
	leaq	96(%rsp), %rsi
	movq	112(%rsp), %r11
	movq	120(%rsp), %r12
	leaq	224(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	448(%rsp), %rax
	leaq	448(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	256(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	416(%rsp), %rax
	leaq	416(%rsp), %rbx
	movq	224(%rsp), %r9
	movq	232(%rsp), %r10
	leaq	224(%rsp), %rsi
	movq	240(%rsp), %r11
	movq	248(%rsp), %r12
	leaq	224(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	512(%rsp), %rax
	leaq	512(%rsp), %rbx
	movq	256(%rsp), %r9
	movq	264(%rsp), %r10
	leaq	256(%rsp), %rsi
	movq	272(%rsp), %r11
	movq	280(%rsp), %r12
	leaq	256(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	224(%rsp), %rbx
	leaq	64(%rsp), %rdi
	call	ECP_Sm2SubAB

	orq		%r13, %r12
	vmovdqa	%xmm4, %xmm2
	orq		%r8, %r12
	orq		%r9, %r12
	vpor	%xmm5, %xmm2, %xmm2
	vmovq	%r12, %xmm3

	movq	384(%rsp), %rax
	leaq	384(%rsp), %rbx
	movq	96(%rsp), %r9
	movq	104(%rsp), %r10
	leaq	96(%rsp), %rsi
	movq	112(%rsp), %r11
	movq	120(%rsp), %r12
	leaq	160(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	480(%rsp), %rax
	leaq	480(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	192(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	160(%rsp), %rbx
	leaq	0(%rsp), %rdi
	call	ECP_Sm2SubAB

	orq		%r13, %r12
	orq		%r8, %r12
	orq		%r9, %r12

	vmovq	%xmm2, %r8
	vmovq	%xmm3, %r9

	orq		%r8, %r12
	orq		%r9, %r12
	jnz		.Lpoint_add

.Ladd_double:
	vmovq	%xmm1, %rsi
	vmovq	%xmm0, %rdi
	addq	$416, %rsp
	jmp	.Lpoint_double

.align	32
.Lpoint_add:
	movq	64(%rsp), %rax
	movq	72(%rsp), %r14
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r15
	movq	88(%rsp), %r8
	leaq	96(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	448(%rsp), %rax
	leaq	448(%rsp), %rbx
	movq	(%rsp), %r9
	movq	8(%rsp), %r10
	leaq	(%rsp), %rsi
	movq	16(%rsp), %r11
	movq	24(%rsp), %r12
	leaq	352(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	(%rsp), %rax
	movq	8(%rsp), %r14
	leaq	(%rsp), %rsi
	movq	16(%rsp), %r15
	movq	24(%rsp), %r8
	leaq	32(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	544(%rsp), %rax
	leaq	544(%rsp), %rbx
	movq	352(%rsp), %r9
	movq	360(%rsp), %r10
	leaq	352(%rsp), %rsi
	movq	368(%rsp), %r11
	movq	24+352(%rsp), %r12
	leaq	352(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	(%rsp), %rax
	leaq	(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	128(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	160(%rsp), %rax
	leaq	160(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	192(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	96(%rsp), %rsi
	movq	$0, %r11
	addq	%r12, %r12
	adcq	%r13, %r13
	movq	%r12, %rcx
	adcq	%r8, %r8
	adcq	%r9, %r9
	movq	%r13, %rbp
	adcq	$0, %r11

	subq	$-1, %r12
	movq	%r8, %rax
	sbbq	%r14, %r13
	sbbq	$-1, %r8
	movq	%r9, %r10
	sbbq	%r15, %r9
	sbbq	$0, %r11

	cmovcq	%rcx, %r12
	movq	(%rsi), %rcx
	cmovcq	%rbp, %r13
	movq	8(%rsi), %rbp
	cmovcq	%rax, %r8
	movq	16(%rsi), %rax
	cmovcq	%r10, %r9
	movq	24(%rsi), %r10

	call	ECP_Sm2SubBA

	leaq	128(%rsp), %rbx
	leaq	288(%rsp), %rdi
	call	ECP_Sm2SubAB

	movq	192(%rsp), %rcx
	movq	200(%rsp), %rbp
	movq	208(%rsp), %rax
	movq	216(%rsp), %r10
	leaq	320(%rsp), %rdi

	call	ECP_Sm2SubBA

	movq	%r12,(%rdi)
	movq	%r13,8(%rdi)
	movq	%r8,16(%rdi)
	movq	%r9,24(%rdi)

	movq	128(%rsp), %rax
	leaq	128(%rsp), %rbx
	movq	224(%rsp), %r9
	movq	232(%rsp), %r10
	leaq	224(%rsp), %rsi
	movq	240(%rsp), %r11
	movq	248(%rsp), %r12
	leaq	256(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	320(%rsp), %rax
	leaq	320(%rsp), %rbx
	movq	64(%rsp), %r9
	movq	72(%rsp), %r10
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r11
	movq	88(%rsp), %r12
	leaq	320(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	256(%rsp), %rbx
	leaq	320(%rsp), %rdi
	call	ECP_Sm2SubAB

	vmovq	%xmm0, %rdi
	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	352(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	368(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	544(%rsp), %xmm2, %xmm2
	vpand	560(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	448(%rsp), %xmm2, %xmm2
	vpand	464(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,64(%rdi)
	vmovdqu	%xmm3,80(%rdi)

	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	288(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	304(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	480(%rsp), %xmm2, %xmm2
	vpand	496(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	384(%rsp), %xmm2, %xmm2
	vpand	400(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,(%rdi)
	vmovdqu	%xmm3,16(%rdi)

	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	320(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	336(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	512(%rsp), %xmm2, %xmm2
	vpand	528(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	416(%rsp), %xmm2, %xmm2
	vpand	432(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,32(%rdi)
	vmovdqu	%xmm3,48(%rdi)

.Ladd_done:
	leaq	584(%rsp), %rsp
	REGISTER_POP
	ret
.size	ECP_Sm2PointAddMont,.-ECP_Sm2PointAddMont

# ref. https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
# Deal process:
#     Z1Z1 = Z12
#     U2 = X2*Z1Z1
#     S2 = Y2*Z1*Z1Z1
#     H = U2-X1
#     HH = H2
#     I = 4*HH
#     J = H*I
#     r = 2*(S2-Y1)
#     V = X1*I
#     X3 = r2-J-2*V
#     Y3 = r*(V-X3)-2*Y1*J
#     Z3 = (Z1+H)2-Z1Z1-HH
.globl	ECP_Sm2PointAddAffineMont
.type	ECP_Sm2PointAddAffineMont,@function
.align	32
ECP_Sm2PointAddAffineMont:
	REGISTER_SAVE
	subq	$488, %rsp
	vmovdqu	(%rsi), %xmm0
	vmovdqu	16(%rsi), %xmm1
	vmovdqu	32(%rsi), %xmm2
	vmovdqu	48(%rsi), %xmm3
	vmovdqu	64(%rsi), %xmm4
	vmovdqu	80(%rsi), %xmm5
	movq	%rdx, %rbx
	movq	64(%rsi), %rax
	movq	72(%rsi), %r14
	movq	80(%rsi), %r15
	movq	88(%rsi), %r8

	vmovdqa	%xmm0,320(%rsp)
	vmovdqa	%xmm1,336(%rsp)
	vmovdqa	%xmm2,352(%rsp)
	vmovdqa	%xmm3,368(%rsp)
	vmovdqa	%xmm4,384(%rsp)
	vmovdqa	%xmm5,400(%rsp)
	vpor	%xmm4, %xmm5, %xmm5

	vmovdqu	(%rbx), %xmm0
	vpshufd	$0xb1, %xmm5, %xmm3
	vmovdqu	16(%rbx), %xmm1
	vmovdqu	32(%rbx), %xmm2
	vpor	%xmm3, %xmm5, %xmm5
	vmovdqu	48(%rbx), %xmm3
	vmovdqa	%xmm0, 416(%rsp)
	vpshufd	$0x1e, %xmm5, %xmm4
	vmovdqa	%xmm1, 416+16(%rsp)
	vpor	%xmm0, %xmm1, %xmm1

	vmovq	%rdi, %xmm0
	vmovdqa	%xmm2, 448(%rsp)
	vmovdqa	%xmm3, 464(%rsp)
	vpor	%xmm2, %xmm3, %xmm3
	vpor	%xmm4, %xmm5, %xmm5
	vpxor	%xmm4, %xmm4, %xmm4
	vpor	%xmm1, %xmm3, %xmm3

	leaq	64(%rsi), %rsi
	leaq	32(%rsp), %rdi
	call	ECP_Sm2SqrMont

	vpcmpeqd	%xmm4, %xmm5, %xmm5
	vpshufd		$0xb1, %xmm3, %xmm4
	vpor		%xmm3, %xmm4, %xmm4
	vpshufd		$0, %xmm5, %xmm5
	vpshufd		$0x1e, %xmm4, %xmm3
	vpor		%xmm3, %xmm4, %xmm4
	vpxor		%xmm3, %xmm3, %xmm3
	vpcmpeqd	%xmm3, %xmm4, %xmm4
	vpshufd		$0, %xmm4, %xmm4

	movq        (%rbx), %rax
	movq		%r12, %r9
	movq		%r13, %r10
	movq		%r14, %r11

	leaq	32(%rsp), %rsi
	movq	%r15, %r12
	leaq	(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	320(%rsp), %rbx
	leaq	64(%rsp), %rdi
	call	ECP_Sm2SubAB

	movq	384(%rsp), %rax
	leaq	384(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	32(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	384(%rsp), %rax
	leaq	384(%rsp), %rbx
	movq	64(%rsp), %r9
	movq	72(%rsp), %r10
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r11
	movq	88(%rsp), %r12
	leaq	288(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	448(%rsp), %rax
	leaq	448(%rsp), %rbx
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	leaq	32(%rsp), %rsi
	movq	48(%rsp), %r11
	movq	56(%rsp), %r12
	leaq	32(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	352(%rsp), %rbx
	leaq	96(%rsp), %rdi
	call	ECP_Sm2SubAB

	movq	64(%rsp), %rax
	movq	72(%rsp), %r14
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r15
	movq	88(%rsp), %r8
	leaq	128(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	96(%rsp), %rax
	movq	104(%rsp), %r14
	leaq	96(%rsp), %rsi
	movq	112(%rsp), %r15
	movq	120(%rsp), %r8
	leaq	192(%rsp), %rdi
	call	ECP_Sm2SqrMont

	movq	128(%rsp), %rax
	leaq	128(%rsp), %rbx
	movq	64(%rsp), %r9
	movq	72(%rsp), %r10
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r11
	movq	88(%rsp), %r12
	leaq	160(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	320(%rsp), %rax
	leaq	320(%rsp), %rbx
	movq	128(%rsp), %r9
	movq	136(%rsp), %r10
	leaq	128(%rsp), %rsi
	movq	144(%rsp), %r11
	movq	152(%rsp), %r12
	leaq	(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	192(%rsp), %rsi
	movq	$0, %r11
	addq	%r12, %r12
	adcq	%r13, %r13
	movq	%r12, %rcx
	adcq	%r8, %r8
	adcq	%r9, %r9
	movq	%r13, %rbp
	adcq	$0, %r11

	subq	$-1, %r12
	movq	%r8, %rax
	sbbq	%r14, %r13
	sbbq	$-1, %r8
	movq	%r9, %r10
	sbbq	%r15, %r9
	sbbq	$0, %r11

	cmovcq	%rcx, %r12
	movq	(%rsi), %rcx
	cmovcq	%rbp, %r13
	movq	8(%rsi), %rbp
	cmovcq	%rax, %r8
	movq	16(%rsi), %rax
	cmovcq	%r10, %r9
	movq	24(%rsi), %r10

	call	ECP_Sm2SubBA

	leaq	160(%rsp), %rbx
	leaq	224(%rsp), %rdi
	call	ECP_Sm2SubAB

	movq	(%rsp), %rcx
	movq	8(%rsp), %rbp
	movq	16(%rsp), %rax
	movq	24(%rsp), %r10
	leaq	64(%rsp), %rdi

	call	ECP_Sm2SubBA

	movq	%r12,(%rdi)
	movq	%r13,8(%rdi)
	movq	%r8,16(%rdi)
	movq	%r9,24(%rdi)

	movq	352(%rsp), %rax
	leaq	352(%rsp), %rbx
	movq	160(%rsp), %r9
	movq	168(%rsp), %r10
	leaq	160(%rsp), %rsi
	movq	176(%rsp), %r11
	movq	184(%rsp), %r12
	leaq	32(%rsp), %rdi
	call	ECP_Sm2MulMont

	movq	96(%rsp), %rax
	leaq	96(%rsp), %rbx
	movq	64(%rsp), %r9
	movq	72(%rsp), %r10
	leaq	64(%rsp), %rsi
	movq	80(%rsp), %r11
	movq	88(%rsp), %r12
	leaq	64(%rsp), %rdi
	call	ECP_Sm2MulMont

	leaq	32(%rsp), %rbx
	leaq	256(%rsp), %rdi
	call	ECP_Sm2SubAB

	vmovq	%xmm0, %rdi
	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	288(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	304(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	.Lone_mont(%rip), %xmm2, %xmm2
	vpand	.Lone_mont+16(%rip), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	384(%rsp), %xmm2, %xmm2
	vpand	400(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,64(%rdi)
	vmovdqu	%xmm3,80(%rdi)

	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	224(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	240(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	416(%rsp), %xmm2, %xmm2
	vpand	432(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	320(%rsp), %xmm2, %xmm2
	vpand	336(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,(%rdi)
	vmovdqu	%xmm3,16(%rdi)

	vmovdqa	%xmm5, %xmm0
	vmovdqa	%xmm5, %xmm1
	vpandn	256(%rsp), %xmm0, %xmm0
	vmovdqa	%xmm5, %xmm2
	vpandn	272(%rsp), %xmm1, %xmm1
	vmovdqa	%xmm5, %xmm3
	vpand	448(%rsp), %xmm2, %xmm2
	vpand	464(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3

	vmovdqa	%xmm4, %xmm0
	vmovdqa	%xmm4, %xmm1
	vpandn	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm4, %xmm2
	vpandn	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm4, %xmm3
	vpand	352(%rsp), %xmm2, %xmm2
	vpand	368(%rsp), %xmm3, %xmm3
	vpor	%xmm0, %xmm2, %xmm2
	vpor	%xmm1, %xmm3, %xmm3
	vmovdqu	%xmm2,32(%rdi)
	vmovdqu	%xmm3,48(%rdi)

	leaq	488(%rsp), %rsp
	REGISTER_POP
	ret
.size	ECP_Sm2PointAddAffineMont,.-ECP_Sm2PointAddAffineMont
#endif