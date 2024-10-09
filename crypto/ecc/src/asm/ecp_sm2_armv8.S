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
.file	"ecp_sm2_armv8.S"
.text

#define	s0 x7
#define	s1 x8
#define	s2 x9
#define	s3 x10
#define	s4 x11
#define	s5 x12
#define	s6 x13
#define	s7 x14

# The polynomial
.align	4
.Lpoly:
.quad	0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff
# The order of polynomial
.Lord:
.quad	0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff

### Right shift: in >> 1 ###
# void ECP_Sm2BnRshift1(uint64_t *a)
# 1-bit right shift
# a		%x0
.globl	ECP_Sm2BnRshift1
.type	ECP_Sm2BnRshift1, @function
.align	4
ECP_Sm2BnRshift1:

	# Load inputs
	ldp x9, x10, [x0]
	ldp x11, x12, [x0, #16]


	# Right shift
	extr x9, x10, x9, #1
	extr x10, x11, x10, #1
	extr x11, x12, x11, #1
	lsr  x12, x12, #1

	# Store results
	stp x9, x10, [x0]
	stp x11, x12, [x0, #16]

	ret
.size ECP_Sm2BnRshift1, .-ECP_Sm2BnRshift1


### Modular div by 2: res = in/2 mod p ###
# void ECP_Sm2DivBy2(uint64_t *r, const uint64_t *a)
# Modular div by 2
# r		%x0
# a		%x1
.globl	ECP_Sm2DivBy2
.type	ECP_Sm2DivBy2, @function
.align	4
ECP_Sm2DivBy2:
	eor x13, x13, x13
	eor x15, x15, x15

	# Load inputs
	ldp x9, x10, [x1]
	ldp x11, x12, [x1, #16]

	mov x14, x9

	# Add polynomial
	ldr x2, .Lpoly
	ldr x3, .Lpoly+8
	ldr x4, .Lpoly+16
	ldr x5, .Lpoly+24
	adds x9, x9, x2
	adcs x10, x10, x3
	adcs x11, x11, x4
	adcs x12, x12, x5
	adcs x13, x13, xzr

	# Parity check
	tst x14, #1
	b.ne .not_equal_1
	ldp x9, x10, [x1]
	ldp x11, x12, [x1, #16]
	mov x13, x15

.not_equal_1:
	extr x9, x10, x9, #1
	extr x10, x11, x10, #1
	extr x11, x12, x11, #1
	extr x12, x13, x12, #1

	# Store results
	stp x9, x10, [x0]
	stp x11, x12, [x0, #16]

	ret
.size ECP_Sm2DivBy2, .-ECP_Sm2DivBy2


### Modular mul by 3: r = 3*a mod p ###
# void ECP_Sm2MulBy3(uint64_t *r, const uint64_t *a)
# Modular mul by 3
# r		%rdi
# a		%rsi
.globl	ECP_Sm2MulBy3
.type	ECP_Sm2MulBy3, @function
.align	4
ECP_Sm2MulBy3:
	# Load inputs
	ldp x3, x4, [x1]
	ldp x5, x6, [x1, #16]

	# 2*a
	adds x3, x3, x3
	adcs x4, x4, x4
	adcs x5, x5, x5
	adcs x6, x6, x6
	adcs x7, xzr, xzr

	mov x8, x3
	mov x9, x4
	mov x10, x5
	mov x11, x6

	# Sub polynomial
	adrp    x2, .Lpoly
    add	    x2, x2, :lo12:.Lpoly
	ldp x12, x13, [x2]
	ldp x14, x15, [x2, #16]
	subs x3, x3, x12
	sbcs x4, x4, x13
	sbcs x5, x5, x14
	sbcs x6, x6, x15
	sbcs x7, x7, xzr

	csel x3, x3, x8, cs
	csel x4, x4, x9, cs
	csel x5, x5, x10, cs
	csel x6, x6, x11, cs
	eor x7, x7, x7

	# 3*a
	ldp x12, x13, [x1]
	ldp x14, x15, [x1, #16]
	adds x3, x3, x12
	adcs x4, x4, x13
	adcs x5, x5, x14
	adcs x6, x6, x15
	adcs x7, xzr, xzr

	mov x8, x3
	mov x9, x4
	mov x10, x5
	mov x11, x6

	# Sub polynomial
	adrp x2, .Lpoly
    add	x2, x2, :lo12:.Lpoly
	ldp x12, x13, [x2]
	ldp x14, x15, [x2, #16]
	subs x3, x3, x12
	sbcs x4, x4, x13
	sbcs x5, x5, x14
	sbcs x6, x6, x15
	sbcs x7, x7, xzr

	csel x3, x3, x8, cs
	csel x4, x4, x9, cs
	csel x5, x5, x10, cs
	csel x6, x6, x11, cs

	# Store results
	stp x3, x4, [x0]
	stp x5, x6, [x0, #16]

	ret
.size ECP_Sm2MulBy3, .-ECP_Sm2MulBy3

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
.globl	ECP_Sm2Add
.type	ECP_Sm2Add, @function
.align	4
ECP_Sm2Add:
	bn_mod_add(.Lpoly);
	ret
.size ECP_Sm2Add, .-ECP_Sm2Add

### Modular sub: r = a-b mod p ###
.globl	ECP_Sm2Sub
.type	ECP_Sm2Sub, @function
.align	4

ECP_Sm2Sub:
	bn_mod_sub(.Lpoly);
	ret
.size ECP_Sm2Sub, .-ECP_Sm2Sub

### Modular add: r = a+b mod n/p, where n = ord(p) ###
.globl	ECP_Sm2AddModOrd
.type	ECP_Sm2AddModOrd, @function
.align	4
ECP_Sm2AddModOrd:
	bn_mod_add(.Lord);
	ret
.size ECP_Sm2AddModOrd, .-ECP_Sm2AddModOrd

### Modular sub: r = a-b mod n/p, where n = ord(p) ###
.globl	ECP_Sm2SubModOrd
.type	ECP_Sm2SubModOrd, @function
.align	4
ECP_Sm2SubModOrd:
	bn_mod_sub(.Lord);
	ret
.size ECP_Sm2SubModOrd, .-ECP_Sm2SubModOrd

.macro	RDC
	# registers map
	# x3  x4  x5  x6  x15
	# rsi rax rcx rdx rbx

	# r = a mod p256
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
	# until r < p256
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

	ret
.size ECP_Sm2Sqr, .-ECP_Sm2Sqr
