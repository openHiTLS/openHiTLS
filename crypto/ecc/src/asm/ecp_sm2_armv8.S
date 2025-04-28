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
#include "crypt_arm.h"
.file	"ecp_sm2_armv8.S"

#define	s0 x7
#define	s1 x8
#define	s2 x9
#define	s3 x10
#define	s4 x11
#define	s5 x12
#define	s6 x13
#define	s7 x14

.section .rodata
# The polynomial
.align	4
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

.LRR:	//	2^512 mod P precomputed for sm2 polynomial
.quad	0x0000000200000003, 0x00000002ffffffff, 0x0000000100000001, 0x0000000400000002
.Lone_mont:
.quad	0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000, 0x0000000100000000
.Lone:
.quad	1,0,0,0

.text
### Right shift: in >> 1 ###
# void ECP_Sm2Div2(BN_UINT *r, BN_UINT *a);
# 1-bit right shift
.globl	ECP_Sm2Div2
.type	ECP_Sm2Div2, %function
.align	4
ECP_Sm2Div2:
AARCH64_PACIASP
	# Load inputs
	ldp	x9, x10, [x1]
	ldp	x11, x12, [x1, #16]

	# Right shift
	extr	x9, x10, x9, #1
	extr	x10, x11, x10, #1
	extr	x11, x12, x11, #1
	lsr	x12, x12, #1

	# Store results
	stp	x9, x10, [x0]
	stp	x11, x12, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div2, .-ECP_Sm2Div2

### Right shift: in >> 2 ###

# void ECP_Sm2Div4(BN_UINT *r, BN_UINT *a);
# 2-bit right shift
.globl	ECP_Sm2Div4
.type	ECP_Sm2Div4, %function
.align	4
ECP_Sm2Div4:
AARCH64_PACIASP
	# Load inputs
	ldp	x7, x8, [x1]
	ldp	x9, x10, [x1, #16]

	# Right shift
	extr	x7, x8, x7, #2
	extr	x8, x9, x8, #2
	extr	x9, x10, x9, #2
	lsr	x10, x10, #2

	# Store results
	stp	x7, x8, [x0]
	stp	x9, x10, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div4, .-ECP_Sm2Div4

### Sub: r = a-b ###
.globl	ECP_Sm2BnSub
.type	ECP_Sm2BnSub, %function
.align	4
ECP_Sm2BnSub:
AARCH64_PACIASP
	# Load inputs
	ldp	x7, x8, [x1]
	ldp	x11, x12, [x2]
	ldp	x9, x10, [x1, #16]
	ldp	x13, x14, [x2, #16]

	# Sub
	subs	x7,x7,x11
	sbcs	x8,x8,x12
	sbcs	x9,x9,x13
	sbc	x10,x10,x14

	# Store results
	stp	x7, x8, [x0]
	stp	x9, x10, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2BnSub, .-ECP_Sm2BnSub

### Add: r = a+b ###
.globl	ECP_Sm2BnAdd
.type	ECP_Sm2BnAdd, %function
.align	4
ECP_Sm2BnAdd:
AARCH64_PACIASP
	# Load inputs
	ldp	x7, x8, [x1]
	ldp	x11, x12, [x2]
	ldp	x9, x10, [x1, #16]
	ldp	x13, x14, [x2, #16]

	# Add
	adds	x7,x7,x11
	adcs	x8,x8,x12
	adcs	x9,x9,x13
	adc	x10,x10,x14

	# Store results
	stp	x7, x8, [x0]
	stp	x9, x10, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2BnAdd, .-ECP_Sm2BnAdd

### Modular div by 2: res = in/2 mod p ###
# void ECP_Sm2Div2ModP(BN_UINT *r, BN_UINT *a)
.globl	ECP_Sm2Div2ModP
.type	ECP_Sm2Div2ModP, %function
.align	4
ECP_Sm2Div2ModP:
AARCH64_PACIASP
	# Load inputs
	ldp	x3, x4, [x1]
	ldp	x5, x6, [x1, #16]

	# Save last bit
	mov	x11, x3

	# Right shift 1
	extr	x3, x4, x3, #1
	extr	x4, x5, x4, #1
	extr	x5, x6, x5, #1
	lsr	x6, x6, #1

	# Load polynomial
    adrp    x1, .Lpoly_div_2
    add 	x1,x1,:lo12:.Lpoly_div_2

	ldp	x7, x8, [x1]
	ldp	x9, x10, [x1, #16]

	# Parity check
	tst	x11, #1
	csel	x7,xzr,x7,eq
	csel	x8,xzr,x8,eq
	csel	x9,xzr,x9,eq
	csel	x10,xzr,x10,eq

	# Add
	adds	x3,x3,x7
	adcs	x4,x4,x8
	adcs	x5,x5,x9
	adc	x6,x6,x10

	# Store results
	stp	x3, x4, [x0]
	stp	x5, x6, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div2ModP, .-ECP_Sm2Div2ModP

### Modular div by 2: res = in/2 mod n, where n = ord(p) ###
# void ECP_Sm2Div2ModOrd(BN_UINT *r, BN_UINT *a)
.globl	ECP_Sm2Div2ModOrd
.type	ECP_Sm2Div2ModOrd, %function
.align	4
ECP_Sm2Div2ModOrd:
AARCH64_PACIASP
	# Load inputs
	ldp	x3, x4, [x1]
	ldp	x5, x6, [x1, #16]

	# Save last bit
	mov	x11, x3

	# Right shift 1
	extr	x3, x4, x3, #1
	extr	x4, x5, x4, #1
	extr	x5, x6, x5, #1
	lsr	x6, x6, #1

	# Load polynomial
    adrp    x1, .Lord_div_2
    add 	x1,x1,:lo12:.Lord_div_2
	ldp	x7, x8, [x1]
	ldp	x9, x10, [x1, #16]

	# Parity check
	tst	x11, #1
	csel	x7,xzr,x7,eq
	csel	x8,xzr,x8,eq
	csel	x9,xzr,x9,eq
	csel	x10,xzr,x10,eq

	# Add
	adds	x3,x3,x7
	adcs	x4,x4,x8
	adcs	x5,x5,x9
	adc	x6,x6,x10

	# Store results
	stp	x3, x4, [x0]
	stp	x5, x6, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div2ModOrd, .-ECP_Sm2Div2ModOrd

### Modular div by 4: res = in/4 mod p ###
# void ECP_Sm2Div4ModP(BN_UINT *r, BN_UINT *a)
.globl	ECP_Sm2Div4ModP
.type	ECP_Sm2Div4ModP, %function
.align	4

ECP_Sm2Div4ModP:
AARCH64_PACIASP
	# Load inputs
	ldp	x3, x4, [x1]
	ldp	x5, x6, [x1, #16]

	# Save last 2 bits
	and	x11, x3, 0x3

	# Right shift 2
	extr	x3, x4, x3, #2
	extr	x4, x5, x4, #2
	extr	x5, x6, x5, #2
	lsr	x6, x6, #2

	# Load polynomial
    adrp    x12, .Lzero
    add     x12,x12,:lo12:.Lzero
    adrp    x13, .Lpoly_1div4
    add     x13,x13,:lo12:.Lpoly_1div4
    adrp    x14, .Lpoly_2div4
    add     x14,x14,:lo12:.Lpoly_2div4
    adrp    x15, .Lpoly_3div4
    add     x15,x15,:lo12:.Lpoly_3div4
	cmp	x11, #1
	csel	x1,x12,x13,cc
	cmp	x11, #2
	csel	x1,x1,x14,cc
	cmp	x11, #3
	csel	x1,x1,x15,cc

	ldp	x7, x8, [x1]
	ldp	x9, x10, [x1, #16]

	# Add
	adds	x3,x3,x7
	adcs	x4,x4,x8
	adcs	x5,x5,x9
	adc	x6,x6,x10

	# Store results
	stp	x3, x4, [x0]
	stp	x5, x6, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div4ModP, .-ECP_Sm2Div4ModP

### Modular div by 4: res = in/4 mod n, where n = ord(p) ###
# void ECP_Sm2Div4ModOrd(BN_UINT *r, BN_UINT *a)
.globl	ECP_Sm2Div4ModOrd
.type	ECP_Sm2Div4ModOrd, %function
.align	4

ECP_Sm2Div4ModOrd:
AARCH64_PACIASP
	# Load inputs
	ldp	x3, x4, [x1]
	ldp	x5, x6, [x1, #16]

	# Save last 2 bits
	and	x11, x3, 0x3

	# Right shift 2
	extr	x3, x4, x3, #2
	extr	x4, x5, x4, #2
	extr	x5, x6, x5, #2
	lsr	x6, x6, #2

	# Load polynomial
    adrp    x12, .Lzero
    add     x12,x12,:lo12:.Lzero
    adrp    x13, .Lord_1div4
    add     x13,x13,:lo12:.Lord_1div4
    adrp    x14, .Lord_2div4
    add     x14,x14,:lo12:.Lord_2div4
    adrp    x15, .Lord_3div4
    add     x15,x15,:lo12:.Lord_3div4
	cmp	x11, #1
	csel	x1,x12,x13,cc
	cmp	x11, #2
	csel	x1,x1,x14,cc
	cmp	x11, #3
	csel	x1,x1,x15,cc

	ldp	x7, x8, [x1]
	ldp	x9, x10, [x1, #16]

	# Add
	adds	x3,x3,x7
	adcs	x4,x4,x8
	adcs	x5,x5,x9
	adc	x6,x6,x10

	# Store results
	stp	x3, x4, [x0]
	stp	x5, x6, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Div4ModOrd, .-ECP_Sm2Div4ModOrd

#define	bn_mod_add(mod)			\
	/* Load inputs */			\
	ldp		x3,x4,[x1];			\
	ldp		x5,x6,[x1,#0x10];	\
	/* Addition */				\
	ldp		x7,x8,[x2];			\
	ldp		x9,x10,[x2,#0x10];	\
	adds	x3,x3,x7;			\
	adcs	x4,x4,x8;			\
	adcs	x5,x5,x9;			\
	adcs	x6,x6,x10;			\
	adc 	x15,xzr,xzr;		\
	mov		x11,x3;				\
	mov		x12,x4;				\
	mov		x13,x5;				\
	mov		x14,x6;				\
	/* Sub polynomial */		\
	adrp    x2, mod;            \
    add	    x2, x2, :lo12:mod;  \
	ldp		x7,x8,[x2];			\
	ldp		x9,x10,[x2,#0x10];	\
	subs	x11,x11,x7;			\
	sbcs	x12,x12,x8;			\
	sbcs	x13,x13,x9;			\
	sbcs	x14,x14,x10;		\
	sbcs	x15,x15,xzr;		\
	csel	x3,x3,x11,cc;		\
	csel	x4,x4,x12,cc;		\
	csel	x5,x5,x13,cc;		\
	csel	x6,x6,x14,cc;		\
	/* Store results */			\
	stp		x3,x4,[x0];			\
	stp		x5,x6,[x0,#0x10];	\

#define	bn_mod_sub(mod)			\
	/* Load inputs */			\
	ldp		x3,x4,[x1];			\
	ldp		x5,x6,[x1,#0x10];	\
	/* Addition */				\
	ldp		x7,x8,[x2];			\
	ldp		x9,x10,[x2,#0x10];	\
	subs	x3,x3,x7;			\
	sbcs	x4,x4,x8;			\
	sbcs	x5,x5,x9;			\
	sbcs	x6,x6,x10;			\
	sbc 	x15,xzr,xzr;		\
	mov		x11,x3;				\
	mov		x12,x4;				\
	mov		x13,x5;				\
	mov		x14,x6;				\
	/* Add polynomial */		\
	adrp    x2, mod;            \
    add	    x2, x2, :lo12:mod;  \
	ldp		x7,x8,[x2];			\
	ldp		x9,x10,[x2,#0x10];	\
	adds	x11,x11,x7;			\
	adcs	x12,x12,x8;			\
	adcs	x13,x13,x9;			\
	adcs	x14,x14,x10;		\
	tst		x15,x15;			\
	csel	x3,x3,x11,eq;		\
	csel	x4,x4,x12,eq;		\
	csel	x5,x5,x13,eq;		\
	csel	x6,x6,x14,eq;		\
	/* Store results */			\
	stp		x3,x4,[x0];			\
	stp		x5,x6,[x0,#0x10];	\

### Modular add: r = a+b mod p ###
.globl	ECP_Sm2AddModP
.type	ECP_Sm2AddModP, @function
.align	4

ECP_Sm2AddModP:

AARCH64_PACIASP
	bn_mod_add(.Lpoly);
AARCH64_AUTIASP
	ret
.size	ECP_Sm2AddModP, .-ECP_Sm2AddModP

### Modular sub: r = p - r ###
.globl	ECP_Sm2Neg
.type	ECP_Sm2Neg, @function
.align	4

ECP_Sm2Neg:
AARCH64_PACIASP
	ldp	x11, x12, [x1]
    mov     x7, #0xffffffff00000000
	ldp	x13, x14, [x1, #16]
    mov     x8, #0xfffffffeffffffff

	mov		x10, #-1
	subs	x9,x10,x11
	sbcs	x7,x7,x12
	sbcs	x10,x10,x13
	sbc	x8,x8,x14
	stp	x9, x7, [x0]
	stp	x10, x8, [x0, #16]
	ret
AARCH64_AUTIASP
	ret
.size	ECP_Sm2Neg, .-ECP_Sm2Neg

### Modular sub: r = a-b mod p ###
.globl	ECP_Sm2SubModP
.type	ECP_Sm2SubModP, @function
.align	4

ECP_Sm2SubModP:

AARCH64_PACIASP
	bn_mod_sub(.Lpoly);
AARCH64_AUTIASP
	ret
.size	ECP_Sm2SubModP, .-ECP_Sm2SubModP

### Modular add: r = a+b mod n/p, where n = ord(p) ###
.globl	ECP_Sm2AddModOrd
.type	ECP_Sm2AddModOrd, @function
.align	4
ECP_Sm2AddModOrd:

AARCH64_PACIASP
	bn_mod_add(.Lord);
AARCH64_AUTIASP
	ret
.size ECP_Sm2AddModOrd, .-ECP_Sm2AddModOrd

### Modular sub: r = a-b mod n/p, where n = ord(p) ###
.globl	ECP_Sm2SubModOrd
.type	ECP_Sm2SubModOrd, @function
.align	4
ECP_Sm2SubModOrd:

AARCH64_PACIASP
	bn_mod_sub(.Lord);
AARCH64_AUTIASP
	ret
.size ECP_Sm2SubModOrd, .-ECP_Sm2SubModOrd

.macro	RDC
	# registers map
	# x3  x4  x5  x6  x15
	# rsi rax rcx rdx rbx

	# r = a mod sm2
	# a = a15 | a14 | ... | a0, where ai are 32–bit quantities
	# | a7  | a6  | a5  | a4  | a3  | a2  | a1  | a0  | (+)
	# | a8  | a11 | a10 | a9  | a8  |   0 | a9  | a8  | (+)
	# | a9  | a14 | a13 | a12 | a11 |   0 | a10 | a9  | (+)
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
	# until r < sm2
	# s7 (a15|a14), s6 (a13|a12), s5 (a11|a10), s4 (a9|a8)
	# s3 (a7|a6), s2 (a5|a4), s1 (a3|a2), s0 (a1|a0)

	# 1. 64-bit addition
	eor x3, x3, x3			// to store all carry
	eor x4, x4, x4
	mov x5, s6				// rcx <- s6
	mov x6, s4				// rdx <- s4
	# a13 | a12
	adds x5, x5, s7			// rcx <- s6 + s7
	adcs x4, xzr, xzr		// rax <- carry(s6+s7)
	adds x5, x5, s7			// rcx <- s6 + 2*s7
	adcs x4, x4, xzr
	# a9 | a8
	mov x15, x4				// rbx <- carry (rax)
	adds x6, x6, x5			// rdx <- s4 + s6 + 2*s7
	adcs x15, x15, xzr
	adds x6, x6, s5			// rdx <- s4 + s5 + s6 + 2*s7
	adcs x15, x15, xzr
	# sum
	adds s0, s0, x6			// s0 <- s0 + s4 + s5 + s6 + 2*s7
	adcs s1, s1, x15		// s1 <- s1 + rbx + carry
	adcs s2, s2, x5			// s2 <- s2 + s6 + 2*s7 + carry
	adcs s3, s3, s7
	adcs x3, xzr, xzr
	# add carry
	adds s3, s3, x4
	adcs x3, x3, xzr		// all carry

	stp s0, s1, [sp, #32]
	stp s2, s3, [sp, #48]
	# 2. 4 -> 8  64-bit to 32-bit spread
	mov x4, #0xffffffff
	mov s0, s4
	mov s1, s5
	mov s2, s6
	mov s3, s7
	and s0, s0, x4		// a8
	and s1, s1, x4		// a10
	and s2, s2, x4		// a12
	and s3, s3, x4		// a14
	lsr s4, s4, #32		// a9
	lsr s5, s5, #32		// a11
	lsr s6, s6, #32		// a13
	lsr s7, s7, #32		// a15
	# 3. 32-bit addition
	mov x4, s3
	add x4, x4, s2		// rax <- a12 + a14
	mov x15, s3
	add	x15, x15, s1	// rbx <- a10 + a14
	mov x5, s7
	add x5, x5, s6		// rcx <- a13 + a15
	mov x6, s0
	add x6, x6, s4		// rdx <- a8 + a9
	add s7, s7, s5		// s7 <-  a11 + a15
	mov s2, x5			// s2 <- a13 + a15
	add s2, s2, x4		// s2 <- a12 + a13 + a14 + a15
	add s1, s1, s2		// s1 <- a10 + a12 + a13 + a14 + a15
	add s1, s1, s2		// s1 <- a10 + 2*(a12 + a13 + a14 + a15)
	add s1, s1, x6		// s1 <- a8 + a9 + a10 + 2*(a12 + a13 + a14 + a15)
	add s1, s1, s5		// s1 <- a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	add s2, s2, s6		// s2 <- a12 + 2*a13 + a14 + a15
	add s2, s2, s5		// s2 <- a11 + a12 + 2*a13 + a14 + a15
	add s2, s2, s0		// s2 <- a8 + a11 + a12 + 2*a13 + a14 + a15
	add x6, x6, s3		// rdx <- a8 + a9 + a14
	add x6, x6, s6		// rdx <- a8 + a9 + a13 + a14
	add s4, s4, x5		// s4 <- a9 + a13 + a15
	add s5, s5, s4		// s5 <- a9 + a11 + a13 + a15
	add s5, s5, x5		// s5 <- a9 + a11 + 2*(a13 + a15)
	add x4, x4, x15		// rax <- a10 + a12 + 2*a14

	# U[0]	s5		a9 + a11 + 2*(a13 + a15)
	# U[1]	%rax	a10 + a12 + 2*a14
	# U[2]
	# U[3]	s2		a8 + a11 + a12 + 2*a13 + a14 + a15
	# U[4]	s4		a9 + a13 + a15
	# U[5]	%rbx	a10 + a14
	# U[6]	s7		a11 + a15
	# U[7]	s1		a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	# sub	%rdx	a8 + a9 + a13 + a14

	# s0 s3 s6  %rcx

	# 4. 8 -> 4  32-bit to 64-bit
	# sub %rdx
	mov s0, x4
	lsl s0, s0, #32
	extr x4, s2, x4, #32
	extr s2, x15, s2, #32
	extr x15, s1, x15, #32
	lsr s1, s1, #32

	# 5. 64-bit addition
	adds s5, s5, s0
	adcs x4, x4, xzr
	adcs s4, s4, s2
	adcs s7, s7, x15
	adcs x3, x3, s1

	# V[0] s5
	# V[1] %rax
	# V[2] s4
	# V[3] s7
	# carry %rsi
	# sub %rdx

	# 5. ADD & SUB
	ldp s0, s1, [sp, #32]
	ldp s2, s3, [sp, #48]

	# ADD
	adds s0, s0, s5
	adcs s1, s1, x4
	adcs s2, s2, s4
	adcs s3, s3, s7
	adcs x3, x3, xzr
	# SUB
	subs s1, s1, x6
	sbcs s2, s2, xzr
	sbcs s3, s3, xzr
	sbcs x3, x3, xzr

	# 6. MOD
	# First Mod
	mov x4, x3
	lsl x4, x4, #32
	mov x5, x4
	subs x4, x4, x3

	adds s0, s0, x3
	adcs s1, s1, x4
	adcs s2, s2, xzr
	adcs s3, s3, x5

	# Last Mod
	# return y - p if y > p else y
	mov s4, s0
	mov s5, s1
	mov s6, s2
	mov s7, s3

	adrp x3, .Lpoly
    add	x3, x3, :lo12:.Lpoly
	ldp x4, x15, [x3]
	ldp x16, x17, [x3, #16]

	eor x5, x5, x5
	adcs x5, xzr, xzr

	subs s0, s0, x4
	sbcs s1, s1, x15
	sbcs s2, s2, x16
	sbcs s3, s3, x17
	sbcs x5, x5, xzr

	csel s0, s0, s4, cs
	csel s1, s1, s5, cs
	csel s2, s2, s6, cs
	csel s3, s3, s7, cs

	stp s0, s1, [x0]
	stp s2, s3, [x0, #16]
.endm

### Modular mul: r = a*b mod p ###
# void ECP_Sm2Mul(uint64_t *r, const uint64_t *a, const uint64_t *b)
# 256-bit modular multiplication in SM2
# r		%rdi
# a		%rsi
# b		%rdx
# registers map
# s0  s1  s2  s3  s4  s5  s6  s7
# x7  x8  x9  x10 x11 x12 x13 x14 x3  x4  x5  x6  x15
# r8  r9  r10 r11 r12 r13 r14 r15 rax rdx rbx rcx rsi
.globl	ECP_Sm2Mul
.type	ECP_Sm2Mul, @function
.align	4
ECP_Sm2Mul:
AARCH64_PACIASP
	# Store scalar registers
	stp     x29, x30, [sp, #-80]!
    add     x29, sp, #0
    stp     x16, x17, [sp, #16]
	stp     x18, x19, [sp, #64]

	# Load inputs
	ldp s0, s1, [x1]
	ldp s2, s3, [x1, #16]
	ldp s4, s5, [x2]
	ldp s6, s7, [x2, #16]

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
	mul x16, s0, s4
	umulh x5, s0, s4
	eor x6, x6, x6

### s1*s4 + s0*s5 ###
	mul x3, s1, s4
	umulh x4, s1, s4
	adds x5, x5, x3
	adcs x6, x6, x4
	eor x15, x15, x15

	mul x3, s0, s5
	umulh x4, s0, s5
	adds x5, x5, x3
	adcs x6, x6, x4
	adcs x15, x15, xzr
	mov x17, x5
	eor x5, x5, x5

### s2 * s4 + s1 * s5 + s0 *s6 ###
	mul x3, s2, s4
	umulh x4, s2, s4
	adds x6, x6, x3
	adcs x15, x15, x4

	mul x3, s1, s5
	umulh x4, s1, s5
	adds x6, x6, x3
	adcs x15, x15, x4
	adcs x5, x5, xzr

	mul x3, s0, s6
	umulh x4, s0, s6
	adds x6, x6, x3
	adcs x15, x15, x4
	adcs x5, x5, xzr
	mov x18, x6
	eor x6, x6, x6

### s3*s4 + s2*s5 + s1*s6 + s0*s7 ###
	mul x3, s3, s4
	umulh x4, s3, s4
	adds x15, x15, x3
	adcs x5, x5, x4
	adcs x6, x6, xzr

	mul x3, s2, s5
	umulh x4, s2, s5
	adds x15, x15, x3
	adcs x5, x5, x4
	adcs x6, x6, xzr

	mul x3, s1, s6
	umulh x4, s1, s6
	adds x15, x15, x3
	adcs x5, x5, x4
	adcs x6, x6, xzr

	mul x3, s0 ,s7
	umulh x4, s0, s7
	adds x15, x15, x3
	adcs x5, x5, x4
	adcs x6, x6, xzr
	mov x19, x15
	eor x15, x15, x15

### s3*s5 + s2*s6 + s1*s7 ###
	mul x3, s3, s5
	umulh x4, s3, s5
	adds x5, x5, x3
	adcs x6, x6, x4
	# carry
	adcs x15, x15, xzr

	mul x3, s2, s6
	umulh x4, s2, s6
	adds x5, x5, x3
	adcs x6, x6, x4
	adcs x15, x15, xzr

	mul x3, s1, s7
	umulh x4, s1, s7
	adds x5, x5, x3
	adcs x6, x6, x4
	adcs x15, x15, xzr
	mov s4, x5
	eor x5, x5, x5

### s3*s6 + s2*s7 ###
	mul x3, s3, s6
	umulh x4, s3, s6
	adds x6, x6, x3
	adcs x15, x15, x4
	adcs x5, x5, xzr

	mul x3, s2, s7
	umulh x4, s2, s7
	adds x6, x6, x3
	adcs x15, x15, x4
	adcs x5, x5, xzr
	mov s5, x6

### s3*s7 ###
	mul x3, s3, s7
	umulh x4, s3, s7
	adds x15, x15, x3
	adcs x5, x5, x4
	mov s6, x15
	mov s7, x5

	mov s0, x16
	mov s1, x17
	mov s2, x18
	mov s3, x19

	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0

### Reduction ###
	RDC

	# Restore scalar registers
	ldp x16, x17, [sp, #16]
	ldp x18, x19, [sp, #64]
	ldp x29, x30, [sp], #80
AARCH64_AUTIASP
	ret
.size ECP_Sm2Mul, .-ECP_Sm2Mul

### Modular sqr: r = a^2 mod p ###
# void ECP_Sm2Sqr(uint64_t *r, const uint64_t *a)
# 256-bit modular multiplication in SM2 ###
# r 	%rdi
# a 	%rsi
# registers map
# s0  s1  s2  s3  s4  s5  s6  s7
# x7  x8  x9  x10 x11 x12 x13 x14 x3  x4  x5  x6  x15 x16 x17
# r8  r9  r10 r11 r12 r13 r14 r15 rax rdx rbx rcx rsi rbp rdi
.globl	ECP_Sm2Sqr
.type	ECP_Sm2Sqr, @function
.align	4
ECP_Sm2Sqr:
AARCH64_PACIASP
	# Store scalar registers
	stp     x29, x30, [sp, #-64]!
    add     x29, sp, #0
    stp     x16, x17, [sp, #16]

	# Load inputs
	ldp s4, s5, [x1]
	ldp s6, s7, [x1, #16]

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
	mul s1, s4, s5
	umulh s2, s4, s5
	eor s3, s3, s3

### s2 <- s4*s6 + carry(s2), s3 <- carry ###
	mul x3, s6, s4
	umulh s3, s6, s4
	adds s2, s2, x3
	adcs s3, s3, xzr
	eor s0, s0, s0

### s3 <- s4*s7 + s5*s6 + carry(s3), s0 <- carry ###
	mul x3, s7, s4
	umulh x4, s7, s4
	adds s3, s3, x3
	adcs s0, s0, x4
	eor x5, x5, x5

	mul x3, s6, s5
	umulh x4, s6, s5
	adds s3, s3, x3
	adcs s0, s0, x4
	adcs x5, xzr, xzr

### s0 <- s5*s7 + carry(s0), rbx <- carry ###
	mul x3, s7, s5
	umulh x4, s7, s5
	adds s0, s0, x3
	adcs x5, x5, x4
	eor x6, x6, x6

### rbx <- s6*s7 + carry(rbx), rcx <- carry ###
	mul x3, s7, s6
	umulh x4, s7, s6
	adds x5, x5, x3
	adcs x6, x6, x4
	eor x15, x15, x15

### 2*s0|1|2|3 ###
	adds s1, s1, s1
	adcs s2, s2, s2
	adcs s3, s3, s3
	adcs s0, s0, s0
	adcs x5, x5, x5
	# update carry
	adcs x6, x6, x6
	adcs x15, xzr, xzr

### rbp <- s4*s4, carry <- rdi ###
	mul x16, s4, s4
	umulh x17, s4, s4

### s4 <- s5*s5, carry <- s5 ###
	mul s4, s5, s5
	umulh s5, s5, s5

### s6*s6 ###
	mul x3, s6, s6
	umulh x4, s6, s6

	# s1 += carry(s4*s4)
	adds s1, s1, x17
	# s2 += s5*s5
	adcs s2, s2, s4
	# s3 += carry(s5*s5)
	adcs s3, s3, s5
	# s4(s0) += s6*s6
	adcs s0, s0, x3
	# s5(rbx) += carry(s6*s6)
	adcs x5, x5, x4
	adcs x6, x6, xzr
	adcs x15, x15, xzr

### s7*s7 ###
	mul x3, s7, s7
	umulh x4, s7, s7
	# s6(rcx) += s7*s7
	adds x6, x6, x3
	# s7(rsi) += carry(s7*s7)
	adcs x15, x15, x4

	mov s4, s0
	mov s0, x16
	mov s5, x5
	mov s6, x6
	mov s7, x15
	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0=
### Reduction ###
	RDC

	# Restore scalar registers
	ldp x16, x17, [sp, #16]
	ldp x29, x30, [sp], #64
AARCH64_AUTIASP
	ret
.size ECP_Sm2Sqr, .-ECP_Sm2Sqr

.globl	ECP_Sm2ToMont
.type	ECP_Sm2ToMont,%function
.align	4
ECP_Sm2ToMont:
AARCH64_PACIASP
	stp		x29, x30,[sp, #-32]!
	add		x29,sp, #0
	stp		x19, x20,[sp, #16]

    adrp    x3, .LRR		// bp[0]
    add 	x3, x3,:lo12:.LRR
	ldr	   	x3,[x3]

	ldp		x4, x5,[x1]
	ldp		x6, x7,[x1, #16]

    adrp    x14, .Lpoly+8
    add 	x14, x14,:lo12:.Lpoly+8
	ldr	   	x14,[x14]

    adrp    x15, .Lpoly+24
    add 	x15, x15,:lo12:.Lpoly+24
	ldr	   	x15,[x15]

    adrp    x2, .LRR
    add 	x2, x2,:lo12:.LRR

	bl		ECP_Sm2MulMont

	ldp		x19, x20,[sp, #16]
	ldp		x29, x30,[sp], #32
AARCH64_AUTIASP
	ret
.size	ECP_Sm2ToMont,.-ECP_Sm2ToMont

.globl	ECP_Sm2FromMont
.type	ECP_Sm2FromMont,%function
.align	4
ECP_Sm2FromMont:
AARCH64_PACIASP
	stp		x29, x30,[sp, #-32]!
	add		x29,sp, #0
	stp		x19, x20,[sp, #16]

    adrp    x2, .Lone
    add 	x2, x2,:lo12:.Lone
	ldr	   	x3, [x2]

	ldp		x4, x5,[x1]
	ldp		x6, x7,[x1, #16]

    adrp    x14, .Lpoly+8
    add 	x14, x14,:lo12:.Lpoly+8
	ldr	   	x14, [x14]

    adrp    x15, .Lpoly+24
    add 	x15, x15,:lo12:.Lpoly+24
	ldr	   	x15, [x15]
	
	bl		ECP_Sm2MulMont

	ldp		x19, x20,[sp, #16]
	ldp		x29, x30,[sp], #32
AARCH64_AUTIASP
	ret
.size	ECP_Sm2FromMont,.-ECP_Sm2FromMont

.type	ECP_Sm2MulMont,%function
.align	4
ECP_Sm2MulMont:
AARCH64_PACIASP

	// a[0~3] * b[0]
	mul		x8, x4, x3
	umulh	x16, x4, x3
	mul		x9, x5, x3
	umulh	x17, x5, x3
	mul		x10, x6, x3
	umulh	x19, x6, x3
	mul		x11, x7, x3
	umulh	x20, x7, x3

	adds	x9, x9, x16
	adcs	x10, x10, x17
	adcs	x11, x11, x19
	adc		x12, xzr, x20
	ldr		x3,	[x2, #8] // get b[1]

	// begin 1st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32

	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	mov		x13, xzr
	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adcs	x11, x12, x20
	adc		x12, x13, xzr

	// lo(a[0~3]) * b[1]
	mul		x16, x4, x3
	mul		x17, x5, x3
	mul		x19, x6, x3
	mul		x20, x7, x3

	adds	x8, x8, x16
	adcs	x9, x9, x17
	adcs	x10, x10, x19
	adcs	x11, x11, x20
	adc		x12, x12, xzr

	// hi(a[0~3]) * b[1]
	umulh	x16, x4, x3
	umulh	x17, x5, x3
	umulh	x19, x6, x3
	umulh	x20, x7, x3

	adds	x9, x9, x16
	adcs	x10, x10, x17
	adcs	x11, x11, x19
	adcs	x12, x12, x20
	adc		x13, xzr, xzr

	ldr		x3,	[x2, #8*2] // get b[2]

	// begin 2st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adcs	x11, x12, x20
	adc		x12, x13, xzr

    // lo(a[0~3] * b[2])
	mul		x16, x4, x3
	mul		x17, x5, x3
	mul		x19, x6, x3
	mul		x20, x7, x3

	adds	x8, x8, x16
	adcs	x9, x9, x17
	adcs	x10, x10, x19
	adcs	x11, x11, x20
	adc		x12, x12, xzr

    // hi(a[0~3] * b[2])
	umulh	x16, x4, x3
	umulh	x17, x5, x3
	umulh	x19, x6, x3
	umulh	x20, x7, x3

	adds	x9, x9, x16
	adcs	x10, x10, x17
	adcs	x11, x11, x19
	adcs	x12, x12, x20
	adc		x13, xzr, xzr

	ldr		x3,[x2, #8*3]       // get b[3]

	// begin 3st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adcs	x11, x12, x20
	adc		x12, x13, xzr

    // lo(a[0~3] * b[3])
	mul		x16, x4, x3
	mul		x17, x5, x3
	mul		x19, x6, x3
	mul		x20, x7, x3

	adds	x8, x8, x16
	adcs	x9, x9, x17
	adcs	x10, x10, x19
	adcs	x11, x11, x20
	adc		x12, x12, xzr

    // hi(a[0~3] * b[3])
	umulh	x16, x4, x3
	umulh	x17, x5, x3
	umulh	x19, x6, x3
	umulh	x20, x7, x3

	adds	x9, x9, x16
	adcs	x10, x10, x17
	adcs	x11, x11, x19
	adcs	x12, x12, x20
	adc		x13, xzr, xzr

	lsl		x19, x8, #32
	lsr		x20, x8, #32

	// begin 4st reduce
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adcs	x11, x12, x20
	adc		x12, x13, xzr

	// for cal res - p
	adds	x16, x8, #1 // - (0xffffffffffffffff) = (+1)
	sbcs	x17, x9, x14
	adcs	x19, x10, xzr
	sbcs	x20, x11, x15
	sbcs	xzr, x12, xzr

	csel	x8, x8, x16, lo
	csel	x9, x9, x17, lo
	csel	x10, x10, x19, lo
	csel	x11, x11, x20, lo
	stp		x8, x9,[x0]
	stp		x10, x11,[x0, #8*2]

AARCH64_AUTIASP
	ret
.size	ECP_Sm2MulMont,.-ECP_Sm2MulMont

.type	ECP_Sm2SqrMont,%function
.align	4
ECP_Sm2SqrMont:
AARCH64_PACIASP

	// a[1~3] * a[0]
	mul		x9, x5, x4
	umulh	x17, x5, x4
	mul		x10, x6, x4
	umulh	x19, x6, x4
	mul		x11, x7, x4
	umulh	x12, x7, x4

	adds	x10, x10, x17
	adcs	x11, x11, x19
	adc		x12, x12, xzr

	// a[2~3] * a[1]
	mul		x16, x6, x5
	umulh	x17, x6, x5
	mul		x19, x7, x5
	umulh	x20, x7, x5

	// a[3] * a[2]
	mul		x13, x7, x6
	umulh	x1, x7, x6

	adds	x17, x17, x19
	adc		x19, x20, xzr

	adds	x11, x11, x16
	adcs	x12, x12, x17
	adcs	x13, x13, x19
	adc		x1, x1, xzr

	// a[0] * a[0]
	mul		x8, x4, x4
	umulh	x4, x4, x4
	// a[1] * a[1]
	mul		x17, x5, x5
	umulh	x5, x5, x5

	adds	x9, x9, x9
	adcs	x10, x10, x10

	adcs	x11, x11, x11
	adcs	x12, x12, x12
	adcs	x13, x13, x13
	adcs	x1, x1, x1
	adc		x2, xzr, xzr

	// a[2] * a[2]
	mul		x19, x6, x6
	umulh	x6, x6, x6
	// a[3] * a[3]
	mul		x20, x7, x7
	umulh	x7, x7, x7

	adds	x9, x9, x4
	adcs	x10, x10, x17
	adcs	x11, x11, x5
	adcs	x12, x12, x19
	adcs	x13, x13, x6
	adcs	x1, x1, x20
	adc		x2, x2, x7

	// begin 1st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adc		x11, xzr, x20

	// begin 2st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adc		x11, xzr, x20

	// begin 3st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adc		x11, xzr, x20

	// begin 4st reduce
	lsl		x19, x8, #32
	lsr		x20, x8, #32
	subs	x16, x8, x19
	sbcs	x17, xzr, x20
	sbcs	x19, xzr, x19
	sbc		x20, x8, x20

	adds	x8, x9, x16
	adcs	x9, x10, x17
	adcs	x10, x11, x19
	adc		x11, xzr, x20

	adds	x8, x8, x12
	adcs	x9, x9, x13
	adcs	x10, x10, x1
	adcs	x11, x11, x2
	adc		x12, xzr, xzr

	// for cal res - p
	adds	x16, x8, #1
	sbcs	x17, x9, x14
	adcs	x19, x10, xzr
	sbcs	x20, x11, x15
	sbcs	xzr, x12, xzr

	csel	x8, x8, x16, lo
	csel	x9, x9, x17, lo
	csel	x10, x10, x19, lo
	csel	x11, x11, x20, lo
	stp		x8, x9,[x0]
	stp		x10, x11,[x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2SqrMont,.-ECP_Sm2SqrMont

.type	ECP_Sm2AddCore,%function
.align	4
ECP_Sm2AddCore:
AARCH64_PACIASP
	adds	x8, x8, x16
	adcs	x9, x9, x17
	adcs	x10, x10, x19
	adcs	x11, x11, x20
	adc		x1, xzr, xzr

	// sum - p
	adds	x16, x8, #1
	sbcs	x17, x9, x14  // x14 = 0xffffffff00000000
	adcs	x19, x10, xzr
	sbcs	x20, x11, x15 // x15 = 0xfffffffeffffffff
	sbcs	xzr, x1, xzr

	csel	x8, x8, x16,lo
	csel	x9, x9, x17,lo
	csel	x10, x10, x19,lo
	csel	x11, x11, x20,lo
	stp		x8, x9, [x0]
	stp		x10, x11, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2AddCore,.-ECP_Sm2AddCore

.type	ECP_Sm2DivBy2Core,%function
.align	4
ECP_Sm2DivBy2Core:
AARCH64_PACIASP
	subs	x16, x8, #1
	adcs	x17, x9, x14
	sbcs	x19, x10, xzr
	adcs	x20, x11, x15
	adc		x1, xzr, xzr
	tst		x8, #1

	csel	x8, x8, x16, eq
	csel	x9, x9, x17, eq
	csel	x10, x10, x19, eq
	csel	x11, x11, x20 ,eq
	csel	x1, xzr, x1, eq

	lsr		x8, x8, #1
	orr		x8, x8, x9, lsl#63
	lsr		x9, x9, #1
	orr		x9, x9, x10, lsl#63
	lsr		x10, x10, #1
	orr		x10, x10, x11, lsl#63
	lsr		x11, x11, #1
	orr		x11, x11, x1, lsl#63
	stp		x8, x9,[x0]
	stp		x10, x11, [x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2DivBy2Core,.-ECP_Sm2DivBy2Core

.type	ECP_Sm2SubAB,%function
.align	4
ECP_Sm2SubAB:

AARCH64_PACIASP
	ldp		x16, x17,[x2]
	ldp		x19, x20,[x2, #16]
	subs	x8, x8, x16
	sbcs	x9, x9, x17
	sbcs	x10, x10, x19
	sbcs	x11, x11, x20
	csetm	x16, cc

	adds	x8, x8, x16
	and		x17, x16, x14
	adcs	x9, x9, x17
	adcs	x10, x10, x16
	and		x19, x16, x15
	adc		x11, x11, x19
	stp		x8, x9,[x0]
	stp		x10, x11,[x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2SubAB,.-ECP_Sm2SubAB

.type	ECP_Sm2SubBA,%function
.align	4
ECP_Sm2SubBA:
AARCH64_PACIASP
	ldp		x16, x17,[x2]
	ldp		x19, x20,[x2, #16]
	subs	x8, x16, x8
	sbcs	x9, x17, x9
	sbcs	x10, x19, x10
	sbcs	x11, x20, x11
	csetm	x16, cc

	adds	x8, x8, x16
	and		x17, x16, x14
	adcs	x9, x9, x17
	adcs	x10, x10, x16
	and		x19, x16, x15
	adc		x11, x11, x19
	stp		x8, x9,[x0]
	stp		x10, x11,[x0, #16]
AARCH64_AUTIASP
	ret
.size	ECP_Sm2SubBA,.-ECP_Sm2SubBA

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
.type	ECP_Sm2PointDoubleMont,%function
.align	4
ECP_Sm2PointDoubleMont:
AARCH64_PACIASP
	stp		x29, x30,[sp, #-80]!
	mov		x29, sp
	stp		x19, x20,[sp, #16]
	stp		x21, x22,[sp, #32]
	sub		sp, sp, #32*4

.Lpoint_double:
	ldp		x8, x9,[x1, #32]        // a->y
	ldp		x10, x11,[x1, #32+16]

	mov		x21, x0
	mov		x22, x1 // backup point a

    adrp    x14, .Lpoly+8
    add 	x14, x14,:lo12:.Lpoly+8 // p[1]
	ldr	   	x14, [x14]

    adrp    x15, .Lpoly+24
    add 	x15, x15,:lo12:.Lpoly+24 // p[3]
	ldr	   	x15, [x15]

	mov		x16, x8
	mov		x17, x9
	mov		x19, x10
	mov		x20, x11
	ldp		x4, x5, [x22, #64]        // a->z
	ldp		x6, x7, [x22, #64+16]
	mov		x0, sp
	bl		ECP_Sm2AddCore        // s = 2 * a->y

	add		x0, sp, #64
	bl		ECP_Sm2SqrMont        // zsqr = (a->z)^2

	ldp		x16, x17, [x22]
	ldp		x19, x20, [x22, #16]
	mov		x4, x8
	mov		x5, x9
	mov		x6, x10
	mov		x7, x11
	add		x0, sp, #32
	bl		ECP_Sm2AddCore        // m = a->x + zsqr

	add		x2, x22, #0
	mov		x8, x4
	mov		x9, x5
	ldp		x4, x5,[sp, #0]
	mov		x10, x6
	mov		x11, x7
	ldp		x6, x7,[sp, #16]
	add		x0, sp, #64
	bl		ECP_Sm2SubBA       // zsqr = a->x - zsqr

	add		x0, sp, #0
	bl		ECP_Sm2SqrMont        // s = s^2

	ldr		x3, [x22, #32]
	ldp		x4, x5,[x22, #64]
	ldp		x6, x7,[x22, #64+16]
	add		x2, x22, #32               // a->y
	add		x0, sp, #96
	bl		ECP_Sm2MulMont        // res_z = a->z * a->y

	mov		x16, x8
	mov		x17, x9
	ldp		x4, x5, [sp, #0]
	mov		x19, x10
	mov		x20, x11
	ldp		x6, x7, [sp, #16]
	add		x0, x21, #64
	bl		ECP_Sm2AddCore        // res_z = 2 * res_z

	add		x0, sp, #96
	bl		ECP_Sm2SqrMont        // res_y = s^2

	ldr		x3, [sp, #64]
	ldp		x4, x5, [sp, #32]
	ldp		x6, x7, [sp, #32+16]
	add		x0, x21, #32
	bl		ECP_Sm2DivBy2Core     // res_y = res_y / 2

	add		x2, sp, #64
	add		x0, sp, #32
	bl		ECP_Sm2MulMont        // m = m * zsqr

	mov		x16, x8
	mov		x17, x9
	mov		x19, x10
	mov		x20, x11
	mov		x4, x8
	mov		x5, x9
	mov		x6, x10
	mov		x7, x11
	add		x0, sp, #32
	bl		ECP_Sm2AddCore
	mov		x16, x4
	mov		x17, x5
	ldr		x3, [x22]
	mov		x19, x6
	ldp		x4, x5, [sp, #0]
	mov		x20, x7
	ldp		x6, x7, [sp, #16]
	bl		ECP_Sm2AddCore        // m = 3 * m

	mov		x2, x22
	add		x0, sp, #0
	bl		ECP_Sm2MulMont        // s = s * a->x

	mov		x16, x8
	mov		x17, x9
	ldp		x4, x5, [sp, #32]
	mov		x19, x10
	mov		x20, x11
	ldp		x6, x7, [sp, #32+16]
	add		x0, sp, #96
	bl		ECP_Sm2AddCore        // tmp = 2 * s

	mov		x0, x21
	bl		ECP_Sm2SqrMont        // res_x = m^2

	add		x2, sp, #96
	bl		ECP_Sm2SubAB       // res_x = res_x - tmp

	add		x2, sp, #0
	add		x0, sp, #0
	bl		ECP_Sm2SubBA       // s = s - res_x

	ldr		x3, [sp, #32]
	mov		x4, x8
	mov		x5, x9
	mov		x6, x10
	mov		x7, x11
	add		x2, sp, #32
	bl		ECP_Sm2MulMont        // s = s * m

	add		x2, x21, #32
	add		x0, x21, #32
	bl		ECP_Sm2SubAB       // res_y = s - res_y

	mov		sp, x29
	ldp		x19, x20,[x29, #16]
	ldp		x21, x22,[x29, #32]
	ldp		x29, x30,[sp], #80
AARCH64_AUTIASP
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
.type	ECP_Sm2PointAddMont,%function
.align	4
ECP_Sm2PointAddMont:
AARCH64_PACIASP
	stp		x29, x30,[sp, #-80]!
	mov		x29, sp
	stp		x19, x20,[sp, #16]
	stp		x21, x22,[sp, #32]
	stp		x23, x24,[sp, #48]
	stp		x25, x26,[sp, #64]
	sub		sp,sp, #32*12

	ldp		x4, x5,[x2, #64]
	ldp		x6, x7,[x2, #64+16]
	mov		x21, x0
	mov		x22, x1 // backup points
	mov		x23, x2

    adrp    x14, .Lpoly+8
    add 	x14, x14,:lo12:.Lpoly+8                // p[1]
	ldr	   	x14, [x14]

    adrp    x15, .Lpoly+24
    add 	x15, x15,:lo12:.Lpoly+24               // p[3]
	ldr	   	x15, [x15]


	orr		x16, x4, x5
	orr		x19, x6, x7
	orr		x25, x16, x19
	cmp		x25, #0
	csetm	x25, ne 				// check the point is(x, y, 0)
	add		x0, sp, #128
	bl		ECP_Sm2SqrMont     // z1sqr = z1^2

	ldp		x4, x5,[x22, #64]
	ldp		x6, x7,[x22, #64+16]
	orr		x16, x4, x5
	orr		x19, x6, x7
	orr		x24, x16, x19
	cmp		x24, #0
	csetm	x24, ne 				// check the point is(x, y, 0)

	add		x0, sp, #224
	bl		ECP_Sm2SqrMont     // z2sqr = z2^2

	ldr		x3, [x23, #64]
	ldp		x4, x5,[sp, #128]
	ldp		x6, x7,[sp, #128+16]
	add		x2, x23, #64
	add		x0,sp, #320
	bl		ECP_Sm2MulMont        // s2 = z1^3

	ldr		x3,[x22, #64]
	ldp		x4, x5,[sp, #224]
	ldp		x6, x7,[sp, #224+16]
	add		x2, x22, #64
	add		x0,sp, #352
	bl		ECP_Sm2MulMont        // s2 = y2 * z1^3

	ldr		x3,[x22, #32]
	ldp		x4, x5,[sp, #320]
	ldp		x6, x7,[sp, #320+16]
	add		x2, x22, #32
	add		x0,sp, #320
	bl		ECP_Sm2MulMont

	ldr		x3,[x23, #32]
	ldp		x4, x5,[sp, #352]
	ldp		x6, x7,[sp, #352+16]
	add		x2, x23, #32
	add		x0,sp, #352
	bl		ECP_Sm2MulMont

	add		x2,sp, #320
	ldr		x3,[sp, #128]
	ldp		x4, x5,[x22]
	ldp		x6, x7,[x22, #16]
	add		x0,sp, #96
	bl		ECP_Sm2SubAB

	orr		x8, x8, x9
	orr		x10, x10, x11
	orr		x26, x8, x10

	add		x2,sp, #128
	add		x0,sp, #256
	bl		ECP_Sm2MulMont

	ldr		x3,[sp, #224]
	ldp		x4, x5,[x23]
	ldp		x6, x7,[x23, #16]
	add		x2,sp, #224
	add		x0,sp, #288
	bl		ECP_Sm2MulMont

	add		x2,sp, #256
	ldp		x4, x5,[sp, #96]
	ldp		x6, x7,[sp, #96+16]
	add		x0,sp, #192
	bl		ECP_Sm2SubAB

	orr		x8, x8, x9
	orr		x10, x10, x11
	orr		x8, x8, x10
	tst		x8, x8
	b.ne	.Ladd_proceed

	tst		x24, x25
	b.eq	.Ladd_proceed

	tst		x26, x26
	b.eq	.Ladd_double

	stp		xzr, xzr,[x21]
	stp		xzr, xzr,[x21, #16]
	stp		xzr, xzr,[x21, #32]
	stp		xzr, xzr,[x21, #48]
	stp		xzr, xzr,[x21, #64]
	stp		xzr, xzr,[x21, #80]
	b	.Ladd_done

.align	4
.Ladd_double:
	mov		x1, x22
	mov		x0, x21
	ldp		x23, x24,[x29, #48]
	ldp		x25, x26,[x29, #64]
	add		sp,sp, #32*(12-4)
	b		.Lpoint_double

.align	4
.Ladd_proceed:
	add		x0,sp, #128
	bl		ECP_Sm2SqrMont

	ldr		x3,[x22, #64]
	ldp		x4, x5,[sp, #192]
	ldp		x6, x7,[sp, #192+16]
	add		x2, x22, #64
	add		x0,sp, #64
	bl		ECP_Sm2MulMont

	ldp		x4, x5,[sp, #192]
	ldp		x6, x7,[sp, #192+16]
	add		x0,sp, #224
	bl		ECP_Sm2SqrMont

	ldr		x3,[x23, #64]
	ldp		x4, x5,[sp, #64]
	ldp		x6, x7,[sp, #64+16]
	add		x2, x23, #64
	add		x0,sp, #64
	bl		ECP_Sm2MulMont

	ldr		x3,[sp, #192]
	ldp		x4, x5,[sp, #224]
	ldp		x6, x7,[sp, #224+16]
	add		x2,sp, #192
	add		x0,sp, #160
	bl		ECP_Sm2MulMont

	ldr		x3,[sp, #224]
	ldp		x4, x5,[sp, #256]
	ldp		x6, x7,[sp, #256+16]
	add		x2,sp, #224
	add		x0,sp, #288
	bl		ECP_Sm2MulMont

	mov		x16, x8
	mov		x17, x9
	mov		x19, x10
	mov		x20, x11
	add		x0,sp, #224
	bl		ECP_Sm2AddCore

	add		x2,sp, #128
	add		x0,sp, #0
	bl		ECP_Sm2SubBA

	add		x2,sp, #160
	bl		ECP_Sm2SubAB

	add		x2,sp, #288
	ldr		x3,[sp, #160]
	ldp		x4, x5,[sp, #320]
	ldp		x6, x7,[sp, #320+16]
	add		x0,sp, #32
	bl		ECP_Sm2SubBA

	add		x2,sp, #160
	add		x0,sp, #352
	bl		ECP_Sm2MulMont

	ldr		x3,[sp, #96]
	ldp		x4, x5,[sp, #32]
	ldp		x6, x7,[sp, #32+16]
	add		x2,sp, #96
	add		x0,sp, #32
	bl		ECP_Sm2MulMont

	add		x2,sp, #352
	bl		ECP_Sm2SubAB

	ldp		x4, x5,[sp, #0]
	ldp		x6, x7,[sp, #16]
	ldp		x16, x17,[x23]
	ldp		x19, x20,[x23, #16]
	ldp		x8, x9,[x22, #0]

	cmp		x24, #0
	csel	x16, x4, x16,ne
	csel	x17, x5, x17,ne
	csel	x19, x6, x19,ne
	csel	x20, x7, x20,ne

	cmp		x25, #0
	csel	x8, x16, x8,ne
	csel	x9, x17, x9,ne
	csel	x10, x19, x10,ne
	csel	x11, x20, x11,ne

	stp		x8, x9,[x21, #0]
	stp		x10, x11,[x21, #16]

	ldp		x10, x11,[x22, #16]
	ldp		x4, x5,[sp, #32]
	ldp		x6, x7,[sp, #48]
	ldp		x16, x17,[x23, #32]
	ldp		x19, x20,[x23, #48]
	ldp		x8, x9,[x22, #32]

	cmp		x24, #0
	csel	x16, x4, x16,ne
	csel	x17, x5, x17,ne
	csel	x19, x6, x19,ne
	csel	x20, x7, x20,ne

	cmp		x25, #0
	csel	x8, x16, x8,ne
	csel	x9, x17, x9,ne
	csel	x10, x19, x10,ne
	csel	x11, x20, x11,ne

	stp		x8, x9,[x21, #32]
	stp		x10, x11,[x21, #32+16]

	ldp		x10, x11,[x22, #32+16]
	ldp		x8, x9,  [x22, #64]

	ldp		x16, x17,[x23, #32+32]
	ldp		x19, x20,[x23, #32+48]
	ldp		x4, x5,[sp, #32+32]
	ldp		x6, x7,[sp, #32+48]

	cmp		x24, #0
	ldp		x10, x11,[x22, #64+16]
	csel	x16, x4, x16,ne
	csel	x17, x5, x17,ne
	csel	x19, x6, x19,ne
	csel	x20, x7, x20,ne

	cmp		x25, #0
	csel	x8, x16, x8, ne
	csel	x9, x17, x9, ne
	csel	x10, x19, x10, ne
	csel	x11, x20, x11, ne

	stp		x8, x9,[x21, #64]
	stp		x10, x11,[x21, #64+16]

.Ladd_done:
	mov		sp, x29
	ldp		x19, x20,[x29, #16]
	ldp		x21, x22,[x29, #32]
	ldp		x23, x24,[x29, #48]
	ldp		x25, x26,[x29, #64]
	ldp		x29, x30,[sp], #80
AARCH64_AUTIASP
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
.type	ECP_Sm2PointAddAffineMont,%function
.align	4
ECP_Sm2PointAddAffineMont:
AARCH64_PACIASP
	stp		x29, x30,[sp, #-80]!
	mov		x29, sp
	stp		x19, x20,[sp, #16]
	stp		x21, x22,[sp, #32]
	stp		x23, x24,[sp, #48]
	stp		x25, x26,[sp, #64]
	sub		sp, sp, #32*10

	mov		x21, x0	 // backup r
	mov		x22, x1	 // point a
	mov		x23, x2	 // point b

    adrp    x14, .Lpoly+8
    add 	x14, x14,:lo12:.Lpoly+8
	ldr	   	x14,[x14]

    adrp    x15, .Lpoly+24
    add 	x15, x15,:lo12:.Lpoly+24
	ldr	   	x15,[x15]

	ldp		x4, x5,[x1, #64]	// &(a->z[0]), a->z[0] is marked as z1[0]
	ldp		x6, x7,[x1, #64+16] // &(a->z[2])

	orr		x16, x4, x5
	orr		x19, x6, x7
	orr		x24, x16, x19
	cmp		x24, #0
	csetm	x24, ne   // check is (x, y 0)

	ldp		x8, x9, [x2]         // &(b->x[0])
	ldp		x10, x11, [x2, #16]	 // &(b->x[2])
	ldp		x16, x17, [x2, #32]	 // &(b->y[0])
	ldp		x19, x20, [x2, #48]	 // &(b->y[2])

	orr		x8, x8, x9
	orr		x10, x10, x11
	orr		x16, x16, x17
	orr		x19, x19, x20
	orr		x8, x8, x10
	orr		x16, x16, x19
	orr		x25, x8, x16
	cmp		x25, #0
	csetm	x25, ne   // check is (x, y 0)

	add		x0, sp, #128
	bl		ECP_Sm2SqrMont     // zsqr = z1^2

	mov		x4, x8
	mov		x5, x9
	mov		x6, x10
	mov		x7, x11

	ldr		x3, [x23]
	mov		x2, x23
	add		x0, sp, #96
	bl		ECP_Sm2MulMont        // u2 = z1^2 * x2

	mov		x2, x22
	ldr		x3, [x22, #64]
	ldp		x4, x5, [sp, #128]
	ldp		x6, x7, [sp, #128+16]
	add		x0,sp, #160
	bl		ECP_Sm2SubAB

	add		x2, x22, #64
	add		x0,sp, #128
	bl		ECP_Sm2MulMont

	ldr		x3,[x22, #64]
	ldp		x4, x5,[sp, #160]
	ldp		x6, x7,[sp, #160+16]
	add		x2, x22, #64
	add		x0,sp, #64
	bl		ECP_Sm2MulMont

	ldr		x3,[x23, #32]
	ldp		x4, x5,[sp, #128]
	ldp		x6, x7,[sp, #128+16]
	add		x2, x23, #32
	add		x0,sp, #128
	bl		ECP_Sm2MulMont

	add		x2, x22, #32
	ldp		x4, x5,[sp, #160]
	ldp		x6, x7,[sp, #160+16]
	add		x0,sp, #192
	bl		ECP_Sm2SubAB

	add		x0,sp, #224
	bl		ECP_Sm2SqrMont

	ldp		x4, x5,[sp, #192]
	ldp		x6, x7,[sp, #192+16]
	add		x0,sp, #288
	bl		ECP_Sm2SqrMont

	ldr		x3,[sp, #160]
	ldp		x4, x5,[sp, #224]
	ldp		x6, x7,[sp, #224+16]
	add		x2,sp, #160
	add		x0,sp, #256
	bl		ECP_Sm2MulMont

	ldr		x3,[x22]
	ldp		x4, x5,[sp, #224]
	ldp		x6, x7,[sp, #224+16]
	mov		x2, x22
	add		x0,sp, #96
	bl		ECP_Sm2MulMont

	mov		x16, x8
	mov		x17, x9
	mov		x19, x10
	mov		x20, x11
	add		x0,sp, #224
	bl		ECP_Sm2AddCore

	add		x2,sp, #288
	add		x0,sp, #0
	bl		ECP_Sm2SubBA

	add		x2,sp, #256
	bl		ECP_Sm2SubAB

	add		x2,sp, #96
	ldr		x3,[x22, #32]
	ldp		x4, x5,[sp, #256]
	ldp		x6, x7,[sp, #256+16]
	add		x0,sp, #32
	bl		ECP_Sm2SubBA

	add		x2, x22, #32
	add		x0,sp, #128
	bl		ECP_Sm2MulMont

	ldr		x3,[sp, #192]
	ldp		x4, x5,[sp, #32]
	ldp		x6, x7,[sp, #32+16]
	add		x2,sp, #192
	add		x0,sp, #32
	bl		ECP_Sm2MulMont

	add		x2,sp, #128
	bl		ECP_Sm2SubAB

	ldp		x4, x5,[sp, #0]
	ldp		x6, x7,[sp, #16]
	ldp		x16, x17,[x23]
	ldp		x19, x20,[x23, #16]

	ldp		x8, x9,[x22, #0]
	cmp		x24, #0
	ldp		x10, x11,[x22, #16]

	csel	x16, x4, x16, ne
	csel	x17, x5, x17, ne
	csel	x19, x6, x19, ne
	csel	x20, x7, x20, ne

	cmp		x25, #0
	csel	x8, x16, x8,ne
	csel	x9, x17, x9,ne
	csel	x10, x19, x10,ne
	csel	x11, x20, x11,ne

	ldp		x4, x5,[sp, #32]
	ldp		x6, x7,[sp, #48]
	ldp		x16, x17,[x23, #32]
	ldp		x19, x20,[x23, #48]
	stp		x8, x9,[x21, #0]
	stp		x10, x11,[x21, #16]


	ldp		x8, x9,[x22, #32]
	cmp		x24, #0
	ldp		x10, x11,[x22, #32+16]
	csel	x16, x4, x16,ne
	csel	x17, x5, x17,ne
	csel	x19, x6, x19,ne
	csel	x20, x7, x20,ne

	cmp		x25, #0
	csel	x8, x16, x8,ne
	csel	x9, x17, x9,ne
	csel	x10, x19, x10,ne
	csel	x11, x20, x11,ne
	stp		x8, x9,[x21, #32]
	stp		x10, x11,[x21, #32+16]

	ldp		x4, x5,[sp, #32+32]
	ldp		x6, x7,[sp, #32+48]

    adrp    x23, .Lone_mont
    add 	x23,x23,:lo12:.Lone_mont
	ldp		x16, x17,[x23]
	ldp		x19, x20,[x23, #16]

	ldp		x8, x9,[x22, #64]
	ldp		x10, x11,[x22, #64+16]

	cmp		x24, #0
	csel	x16, x4, x16, ne
	csel	x17, x5, x17, ne
	csel	x19, x6, x19, ne
	csel	x20, x7, x20, ne

	cmp		x25, #0
	csel	x8, x16, x8, ne
	csel	x9, x17, x9, ne
	csel	x10, x19, x10, ne
	csel	x11, x20, x11, ne

	stp		x8, x9, [x21, #64]
	stp		x10, x11, [x21, #64+16]

	mov		sp, x29
	ldp		x19, x20,[x29, #16]
	ldp		x21, x22,[x29, #32]
	ldp		x23, x24,[x29, #48]
	ldp		x25, x26,[x29, #64]
	ldp		x29, x30,[sp], #80
AARCH64_AUTIASP
	ret
.size	ECP_Sm2PointAddAffineMont,.-ECP_Sm2PointAddAffineMont
#endif
