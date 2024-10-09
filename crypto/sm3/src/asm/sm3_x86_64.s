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
#ifdef HITLS_CRYPTO_SM3

.file	"sm3_x86_64.s"
.text

.set	A,%r8d
.set	B,%r9d
.set	C,%r10d
.set	D,%r11d
.set	E,%r12d
.set	F,%r13d
.set	G,%r14d
.set	H,%r15d

.set	STATE,%rdi
.set	DATA,%rsi
.set	NUM,%rdx

.set	ADDR,%rax
.set	BOOL_OUT,%eax
.set	SS1,%ebx
.set	SS2,%eax

.set	X0,%xmm0
.set	X1,%xmm1
.set	X2,%xmm2
.set	X3,%xmm3
.set	X4,%xmm4
.set	X5,%xmm5
.set	X6,%xmm6
.set	X7,%xmm7
.set	R16,%xmm13
.set	R24,%xmm14
.set	SHUFFLEMASK,%xmm15

.macro	FF0		X Y Z
	# X ^ Y ^ Z
	movl	\X,%eax
	xorl	\Y,%eax
	xorl	\Z,%eax
.endm

.macro	FF1		X Y Z
	# (X & Y) | (X & Z) | (Y & Z)
	# = (X & (Y | Z)) | (Y & Z)
	movl	\Y,%eax
	movl	%eax,%ebx
	orl		\Z,%eax
	andl	\Z,%ebx
	andl	\X,%eax
	orl		%ebx,%eax
.endm

.macro	GG0		X Y Z
	FF0		\X \Y \Z
.endm

.macro	GG1		X Y Z
	# (X & Y) | (~X & Z)
	movl	\X,%ebx
	andn	\Z,%ebx,%eax
	andl	\Y,%ebx
	orl		%ebx,%eax
.endm

.macro	P0	X
	rorx	$15,\X,%eax
	rorx	$23,\X,%ebx
	xorl	%eax,\X
	xorl	%ebx,\X
.endm

.macro	P1	X
	rorx	$9,\X,%eax
	rorx	$17,\X,%ebx
	xorl	%eax,\X
	xorl	%ebx,\X
.endm

.macro	ROUND	FF GG Ar Br Cr Dr Er Fr Gr Hr TJ
	# A <<< 12
	rorx	$20,\Ar,%eax
	# SS1 (%ebx) <- ((A <<< 12) + E + (Tj <<< (jmod32))) <<< 7
	# pre-computed TJ = Tj <<< (jmod32)
	movl	%eax,%ebx
	addl	\Er,%ebx
	addl	$\TJ,%ebx
	rorx	$25,%ebx,SS1
	# SS2 (%eax) <- SS1 ^ (A <<< 12)
	xorl	SS1,SS2
	# TT1 (D) <- FF(A,B,C) + D + SS2 + W(i)'
	# TT2 (H) <- GG(E,F,G) + H + SS1 + W(i)
	addl	SS2,\Dr
	addl	SS1,\Hr
	# FF(A,B,C)
	\FF		\Ar \Br \Cr
	addl	BOOL_OUT,\Dr
	# GG(E,F,G)
	\GG		\Er \Fr \Gr
	addl	BOOL_OUT,\Hr
	# B <- B <<< 9
	rorx	$23,\Br,\Br
	# F <- F <<< 19
	rorx	$13,\Fr,\Fr
	# P0(TT2)
	P0		\Hr
.endm

.macro	ROUND_00_15	Ar Br Cr Dr Er Fr Gr Hr TJ WADDR WPADDR
	# H <- H + W(i)
	# D <- D + W(i)'
	addl	\WADDR(%rsp),\Hr
	addl	\WPADDR(%rsp),\Dr
	ROUND	FF0 GG0 \Ar \Br \Cr \Dr \Er \Fr \Gr \Hr \TJ
.endm

.macro	ROUND_16_63	Ar Br Cr Dr Er Fr Gr Hr TJ WADDR WPADDR
	# H <- H + W(i)
	# D <- D + W(i)'
	addl	\WADDR(%rsp),\Hr
	addl	\WPADDR(%rsp),\Dr
	ROUND	FF1 GG1 \Ar \Br \Cr \Dr \Er \Fr \Gr \Hr \TJ
.endm

.macro	ROTATE	IN OUT LEFT RIGHT
	vpslld		$\LEFT,\IN,%xmm6
	vpsrld		$\RIGHT,\IN,%xmm7
	vpxor		%xmm6,%xmm7,\OUT
.endm

.macro	WORD_SCHEDULER_00_11	I
	# W'(i) <- W(i) ^ W(i+4)
	# i = 0, ... ,11
	movl	\I(%rsp), %ecx			# load W(i)
	xorl	\I+4*4(%rsp),%ecx		# W'(i) <- W(i) ^ W(i+4)
	movl	%ecx,284(%rsp)			# store W(i)'
.endm

.macro	WORD_SCHEDULER_12_63	I
	# W(i) <- P1( W(i-16) ^ W(i-9) ^ ( W(i-3) <<< 15 ) ) ^ ( W(i-13) <<< 7 ) ^ W(i-6)
	# i = 12, ... ,63
	rorx	$17,\I+13*4(%rsp),%ecx	# W(i-3)
	xorl	\I(%rsp),%ecx			# W(i-16)
	xorl	\I+7*4(%rsp),%ecx		# W(i-9)
	P1		%ecx
	rorx	$25,\I+3*4(%rsp),%eax	# W(i-13)
	xorl	\I+10*4(%rsp),%eax		# W(i-6)
	xorl	%eax,%ecx
	# Store W(i) and W'(i)
	movl	%ecx,\I+16*4(%rsp)		# store W(i)
	xorl	\I+12*4(%rsp),%ecx		# W'(i) <- W(i) ^ W(i+4)
	movl	%ecx,284(%rsp)			# store W(i)'
.endm

.macro	LOAD_WORD_FOR_SCHEDULER		START
	vmovdqu		\START(%rsp),X0
	vmovdqu		\START+12(%rsp),X1
	vmovdqu		\START+28(%rsp),X2
	vmovdqu		\START+40(%rsp),X3
	vmovdqu		\START+48(%rsp),X4
	vmovdqu		\START+52(%rsp),X5
.endm

.macro	LOAD_WORD_FOR_SCHEDULER_FAST	START W0 W1 W2 W3 W4 W5
	vmovdqu		\START+12(%rsp),\W1
	vmovdqu		\START+48(%rsp),\W4
	vmovdqu		\START+52(%rsp),\W5
.endm

.macro	MESSAGE_SCHEDULER	START W0 W1 W2 W3 W4 W5
	vpxor		\W2,\W0,\W0
	ROTATE		\W5,\W2,15,17
	vpxor		\W2,\W0,\W0

	# P1
	vpshufb		R16,\W0,X6
	vpshufb		R24,\W0,X7
	vpxor		X6,X7,X7
	ROTATE		X7,X7,31,1
	vpxor		X7,\W0,\W0
	ROTATE		\W1,\W2,7,25
	vpxor		\W2,\W0,\W0
	vpxor		\W3,\W0,\W0
	# W'(i) <- W(i) ^ W(i+4)
	vpxor		\W0,\W4,\W4

	vmovdqu		\W0,\START+64(%rsp)
	vmovdqu		\W4,284(%rsp)
.endm

.macro	MESSAGE_SCHEDULER_FAST	START W0 W1 W2 W3 W4 W5
	LOAD_WORD_FOR_SCHEDULER_FAST	\START \W0 \W1 \W2 \W3 \W4 \W5
	MESSAGE_SCHEDULER	\START \W0 \W1 \W2 \W3 \W4 \W5
.endm


##### SM3 #####
# void SM3_CompressSIMD(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
# state|out		%rdi	32 bytes
# p				%rsi
# num			%rdx
.globl	SM3_CompressSIMD
.type	SM3_CompressSIMD, @function
.align	64
SM3_CompressSIMD:
	testq	NUM,NUM
	jz		.Lsm3_avx_ret
	
	# Store Registers
	subq	$348,%rsp
	movq	%rbx,300(%rsp)
	movq	%rbp,8+300(%rsp)
	movq	%r12,16+300(%rsp)
	movq	%r13,24+300(%rsp)
	movq	%r14,32+300(%rsp)
	movq	%r15,40+300(%rsp)

.Lsm3_avx_init:
	leaq		MASKS(%rip),ADDR
	vmovdqa		(ADDR),SHUFFLEMASK
	vmovdqa		16(ADDR),R16
	vmovdqa		32(ADDR),R24

.Lsm3_avx_update:
	# Load Data (Big Endian)
	vmovdqu	(DATA),%xmm0
	vmovdqu	16(DATA),%xmm1
	vmovdqu	32(DATA),%xmm2
	vmovdqu	48(DATA),%xmm3
	vpshufb	SHUFFLEMASK,%xmm0,%xmm0
	vpshufb	SHUFFLEMASK,%xmm1,%xmm1
	vpshufb	SHUFFLEMASK,%xmm2,%xmm2
	vpshufb	SHUFFLEMASK,%xmm3,%xmm3
	vmovdqu	%xmm0,(%rsp)
	vmovdqu	%xmm1,16(%rsp)
	vmovdqu	%xmm2,32(%rsp)
	vmovdqu	%xmm3,48(%rsp)
	vpxor	%xmm1,%xmm0,%xmm0
	vpxor	%xmm2,%xmm1,%xmm1
	vpxor	%xmm3,%xmm2,%xmm2

	# Load State
	movl	(STATE),A
	movl	4(STATE),B
	movl	8(STATE),C
	movl	12(STATE),D
	movl	16(STATE),E
	movl	20(STATE),F
	movl	24(STATE),G
	movl	28(STATE),H
	
	# ROUND 0-11
	vmovdqu	%xmm0,284(%rsp)
	ROUND_00_15	A B C D E F G H	0x79CC4519 0 284
	ROUND_00_15	D A B C H E F G 0xF3988A32 4 288
	ROUND_00_15	C D A B G H E F 0xE7311465 8 292
	ROUND_00_15	B C D A F G H E 0xCE6228CB 12 296
	vmovdqu	%xmm1,284(%rsp)
	ROUND_00_15	A B C D E F G H	0x9CC45197 16 284
	ROUND_00_15	D A B C H E F G 0x3988A32F 20 288
	ROUND_00_15	C D A B G H E F 0x7311465E 24 292
	ROUND_00_15	B C D A F G H E 0xE6228CBC 28 296
	vmovdqu	%xmm2,284(%rsp)
	ROUND_00_15	A B C D E F G H	0xCC451979 32 284
	ROUND_00_15	D A B C H E F G 0x988A32F3 36 288
	ROUND_00_15	C D A B G H E F 0x311465E7 40 292
	ROUND_00_15	B C D A F G H E 0x6228CBCE 44 296
	# ROUND 12-15
	LOAD_WORD_FOR_SCHEDULER	0
	MESSAGE_SCHEDULER	0 X0 X1 X2 X3 X4 X5
	ROUND_00_15	A B C D E F G H	0xC451979C 48 284
	ROUND_00_15	D A B C H E F G 0x88A32F39 52 288
	ROUND_00_15	C D A B G H E F 0x11465E73 56 292
	MESSAGE_SCHEDULER_FAST	12 X1 X0 X3 X5 X4 X2
	ROUND_00_15	B C D A F G H E 0x228CBCE6 60 284
	# ROUND 16-63
	ROUND_16_63	A B C D E F G H	0x9D8A7A87 64 288
	ROUND_16_63	D A B C H E F G 0x3B14F50F 68 292
	MESSAGE_SCHEDULER_FAST	24 X0 X1 X5 X2 X4 X3
	ROUND_16_63	C D A B G H E F 0x7629EA1E 72 284
	ROUND_16_63	B C D A F G H E 0xEC53D43C 76 288
	ROUND_16_63	A B C D E F G H	0xD8A7A879 80 292
	MESSAGE_SCHEDULER_FAST	36 X1 X0 X2 X3 X4 X5
	ROUND_16_63	D A B C H E F G 0xB14F50F3 84 284
	ROUND_16_63	C D A B G H E F 0x629EA1E7 88 288
	ROUND_16_63	B C D A F G H E 0xC53D43CE 92 292
	MESSAGE_SCHEDULER_FAST	48 X0 X1 X3 X5 X4 X2
	ROUND_16_63	A B C D E F G H	0x8A7A879D 96 284
	ROUND_16_63	D A B C H E F G 0x14F50F3B 100 288
	ROUND_16_63	C D A B G H E F 0x29EA1E76 104 292
	MESSAGE_SCHEDULER_FAST	60 X1 X0 X5 X2 X4 X3
	ROUND_16_63	B C D A F G H E 0x53D43CEC 108 284
	ROUND_16_63	A B C D E F G H	0xA7A879D8 112 288
	ROUND_16_63	D A B C H E F G 0x4F50F3B1 116 292
	MESSAGE_SCHEDULER_FAST	72 X0 X1 X2 X3 X4 X5
	ROUND_16_63	C D A B G H E F 0x9EA1E762 120 284
	ROUND_16_63	B C D A F G H E 0x3D43CEC5 124 288
	ROUND_16_63	A B C D E F G H	0x7A879D8A 128 292
	MESSAGE_SCHEDULER_FAST	84 X1 X0 X3 X5 X4 X2
	ROUND_16_63	D A B C H E F G 0xF50F3B14 132 284
	ROUND_16_63	C D A B G H E F 0xEA1E7629 136 288
	ROUND_16_63	B C D A F G H E 0xD43CEC53 140 292
	MESSAGE_SCHEDULER_FAST	96 X0 X1 X5 X2 X4 X3
	ROUND_16_63	A B C D E F G H	0xA879D8A7 144 284
	ROUND_16_63	D A B C H E F G 0x50F3B14F 148 288
	ROUND_16_63	C D A B G H E F 0xA1E7629E 152 292
	MESSAGE_SCHEDULER_FAST	108 X1 X0 X2 X3 X4 X5
	ROUND_16_63	B C D A F G H E 0x43CEC53D 156 284
	ROUND_16_63	A B C D E F G H	0x879D8A7A 160 288
	ROUND_16_63	D A B C H E F G 0x0F3B14F5 164 292
	MESSAGE_SCHEDULER_FAST	120 X0 X1 X3 X5 X4 X2
	ROUND_16_63	C D A B G H E F 0x1E7629EA 168 284
	ROUND_16_63	B C D A F G H E 0x3CEC53D4 172 288
	ROUND_16_63	A B C D E F G H	0x79D8A7A8 176 292
	MESSAGE_SCHEDULER_FAST	132 X1 X0 X5 X2 X4 X3
	ROUND_16_63	D A B C H E F G 0xF3B14F50 180 284
	ROUND_16_63	C D A B G H E F 0xE7629EA1 184 288
	ROUND_16_63	B C D A F G H E 0xCEC53D43 188 292
	MESSAGE_SCHEDULER_FAST	144 X0 X1 X2 X3 X4 X5
	ROUND_16_63	A B C D E F G H	0x9D8A7A87 192 284
	ROUND_16_63	D A B C H E F G 0x3B14F50F 196 288
	ROUND_16_63	C D A B G H E F 0x7629EA1E 200 292
	MESSAGE_SCHEDULER_FAST	156 X1 X0 X3 X5 X4 X2
	ROUND_16_63	B C D A F G H E 0xEC53D43C 204 284
	ROUND_16_63	A B C D E F G H	0xD8A7A879 208 288
	ROUND_16_63	D A B C H E F G 0xB14F50F3 212 292
	MESSAGE_SCHEDULER_FAST	168 X0 X1 X5 X2 X4 X3
	ROUND_16_63	C D A B G H E F 0x629EA1E7 216 284
	ROUND_16_63	B C D A F G H E 0xC53D43CE 220 288
	ROUND_16_63	A B C D E F G H	0x8A7A879D 224 292
	MESSAGE_SCHEDULER_FAST	180 X1 X0 X2 X3 X4 X5
	ROUND_16_63	D A B C H E F G 0x14F50F3B 228 284
	ROUND_16_63	C D A B G H E F 0x29EA1E76 232 288
	ROUND_16_63	B C D A F G H E 0x53D43CEC 236 292
	MESSAGE_SCHEDULER_FAST	192 X0 X1 X3 X5 X4 X2
	ROUND_16_63	A B C D E F G H	0xA7A879D8 240 284
	ROUND_16_63	D A B C H E F G 0x4F50F3B1 244 288
	ROUND_16_63	C D A B G H E F 0x9EA1E762 248 292
	WORD_SCHEDULER_12_63	204
	ROUND_16_63	B C D A F G H E 0x3D43CEC5 252 284

	xorl	A,(STATE)
	xorl	B,4(STATE)
	xorl	C,8(STATE)
	xorl	D,12(STATE)
	xorl	E,16(STATE)
	xorl	F,20(STATE)
	xorl	G,24(STATE)
	xorl	H,28(STATE)

	leaq	64(DATA),DATA
	decq	NUM
	jz		.Lsm3_avx_final
	jmp		.Lsm3_avx_update

.Lsm3_avx_final:
	vzeroall

	# Clear Context
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	# Restore Registers
	movq	300(%rsp),%rbx
	movq	8+300(%rsp),%rbp
	movq	16+300(%rsp),%r12
	movq	24+300(%rsp),%r13
	movq	32+300(%rsp),%r14
	movq	40+300(%rsp),%r15
	addq	$348,%rsp

.Lsm3_avx_ret:
	ret
.size	SM3_CompressSIMD, .-SM3_CompressSIMD

##### SM3 #####
# void SM3_CompressAsm(uint32_t state[8], const uint8_t *data, uint32_t blockCnt)
# state|out		%rdi	32 bytes
# p				%rsi
# num			%rdx
.globl	SM3_CompressAsm
.type	SM3_CompressAsm, @function
.align	64
SM3_CompressAsm:
	testq	NUM,NUM
	jz		.Lsm3_ret
	
	# Store Registers
	subq	$348,%rsp
	movq	%rbx,300(%rsp)
	movq	%rbp,8+300(%rsp)
	movq	%r12,16+300(%rsp)
	movq	%r13,24+300(%rsp)
	movq	%r14,32+300(%rsp)
	movq	%r15,40+300(%rsp)

.Lsm3_loop:
	# Load Data (Big Endian)
	movl	(DATA),%r8d
	movl	4(DATA),%r9d
	movl	8(DATA),%r10d
	movl	12(DATA),%r11d
	movbe	%r8d,(%rsp)
	movbe	%r9d,4(%rsp)
	movbe	%r10d,8(%rsp)
	movbe	%r11d,12(%rsp)
	movl	16(DATA),%r8d
	movl	20(DATA),%r9d
	movl	24(DATA),%r10d
	movl	28(DATA),%r11d
	movbe	%r8d,16(%rsp)
	movbe	%r9d,20(%rsp)
	movbe	%r10d,24(%rsp)
	movbe	%r11d,28(%rsp)
	movl	32(DATA),%r8d
	movl	36(DATA),%r9d
	movl	40(DATA),%r10d
	movl	44(DATA),%r11d
	movbe	%r8d,32(%rsp)
	movbe	%r9d,36(%rsp)
	movbe	%r10d,40(%rsp)
	movbe	%r11d,44(%rsp)
	movl	48(DATA),%r8d
	movl	52(DATA),%r9d
	movl	56(DATA),%r10d
	movl	60(DATA),%r11d
	movbe	%r8d,48(%rsp)
	movbe	%r9d,52(%rsp)
	movbe	%r10d,56(%rsp)
	movbe	%r11d,60(%rsp)

	# Load State
	movl	(STATE),A
	movl	4(STATE),B
	movl	8(STATE),C
	movl	12(STATE),D
	movl	16(STATE),E
	movl	20(STATE),F
	movl	24(STATE),G
	movl	28(STATE),H
	
	# ROUND 0-11
	WORD_SCHEDULER_00_11	0
	ROUND_00_15	A B C D E F G H	0x79CC4519 0 284
	WORD_SCHEDULER_00_11	4
	ROUND_00_15	D A B C H E F G 0xF3988A32 4 284
	WORD_SCHEDULER_00_11	8
	ROUND_00_15	C D A B G H E F 0xE7311465 8 284
	WORD_SCHEDULER_00_11	12
	ROUND_00_15	B C D A F G H E 0xCE6228CB 12 284
	WORD_SCHEDULER_00_11	16
	ROUND_00_15	A B C D E F G H	0x9CC45197 16 284
	WORD_SCHEDULER_00_11	20
	ROUND_00_15	D A B C H E F G 0x3988A32F 20 284
	WORD_SCHEDULER_00_11	24
	ROUND_00_15	C D A B G H E F 0x7311465E 24 284
	WORD_SCHEDULER_00_11	28
	ROUND_00_15	B C D A F G H E 0xE6228CBC 28 284
	WORD_SCHEDULER_00_11	32
	ROUND_00_15	A B C D E F G H	0xCC451979 32 284
	WORD_SCHEDULER_00_11	36
	ROUND_00_15	D A B C H E F G 0x988A32F3 36 284
	WORD_SCHEDULER_00_11	40
	ROUND_00_15	C D A B G H E F 0x311465E7 40 284
	WORD_SCHEDULER_00_11	44
	ROUND_00_15	B C D A F G H E 0x6228CBCE 44 284
	# ROUND 12-15
	WORD_SCHEDULER_12_63	0
	ROUND_00_15	A B C D E F G H	0xC451979C 48 284
	WORD_SCHEDULER_12_63	4
	ROUND_00_15	D A B C H E F G 0x88A32F39 52 284
	WORD_SCHEDULER_12_63	8
	ROUND_00_15	C D A B G H E F 0x11465E73 56 284
	WORD_SCHEDULER_12_63	12
	ROUND_00_15	B C D A F G H E 0x228CBCE6 60 284
	# ROUND 16-63
	WORD_SCHEDULER_12_63	16
	ROUND_16_63	A B C D E F G H	0x9D8A7A87 64 284
	WORD_SCHEDULER_12_63	20
	ROUND_16_63	D A B C H E F G 0x3B14F50F 68 284
	WORD_SCHEDULER_12_63	24
	ROUND_16_63	C D A B G H E F 0x7629EA1E 72 284
	WORD_SCHEDULER_12_63	28
	ROUND_16_63	B C D A F G H E 0xEC53D43C 76 284
	WORD_SCHEDULER_12_63	32
	ROUND_16_63	A B C D E F G H	0xD8A7A879 80 284
	WORD_SCHEDULER_12_63	36
	ROUND_16_63	D A B C H E F G 0xB14F50F3 84 284
	WORD_SCHEDULER_12_63	40
	ROUND_16_63	C D A B G H E F 0x629EA1E7 88 284
	WORD_SCHEDULER_12_63	44
	ROUND_16_63	B C D A F G H E 0xC53D43CE 92 284
	WORD_SCHEDULER_12_63	48
	ROUND_16_63	A B C D E F G H	0x8A7A879D 96 284
	WORD_SCHEDULER_12_63	52
	ROUND_16_63	D A B C H E F G 0x14F50F3B 100 284
	WORD_SCHEDULER_12_63	56
	ROUND_16_63	C D A B G H E F 0x29EA1E76 104 284
	WORD_SCHEDULER_12_63	60
	ROUND_16_63	B C D A F G H E 0x53D43CEC 108 284
	WORD_SCHEDULER_12_63	64
	ROUND_16_63	A B C D E F G H	0xA7A879D8 112 284
	WORD_SCHEDULER_12_63	68
	ROUND_16_63	D A B C H E F G 0x4F50F3B1 116 284
	WORD_SCHEDULER_12_63	72
	ROUND_16_63	C D A B G H E F 0x9EA1E762 120 284
	WORD_SCHEDULER_12_63	76
	ROUND_16_63	B C D A F G H E 0x3D43CEC5 124 284
	WORD_SCHEDULER_12_63	80
	ROUND_16_63	A B C D E F G H	0x7A879D8A 128 284
	WORD_SCHEDULER_12_63	84
	ROUND_16_63	D A B C H E F G 0xF50F3B14 132 284
	WORD_SCHEDULER_12_63	88
	ROUND_16_63	C D A B G H E F 0xEA1E7629 136 284
	WORD_SCHEDULER_12_63	92
	ROUND_16_63	B C D A F G H E 0xD43CEC53 140 284
	WORD_SCHEDULER_12_63	96
	ROUND_16_63	A B C D E F G H	0xA879D8A7 144 284
	WORD_SCHEDULER_12_63	100
	ROUND_16_63	D A B C H E F G 0x50F3B14F 148 284
	WORD_SCHEDULER_12_63	104
	ROUND_16_63	C D A B G H E F 0xA1E7629E 152 284
	WORD_SCHEDULER_12_63	108
	ROUND_16_63	B C D A F G H E 0x43CEC53D 156 284
	WORD_SCHEDULER_12_63	112
	ROUND_16_63	A B C D E F G H	0x879D8A7A 160 284
	WORD_SCHEDULER_12_63	116
	ROUND_16_63	D A B C H E F G 0x0F3B14F5 164 284
	WORD_SCHEDULER_12_63	120
	ROUND_16_63	C D A B G H E F 0x1E7629EA 168 284
	WORD_SCHEDULER_12_63	124
	ROUND_16_63	B C D A F G H E 0x3CEC53D4 172 284
	WORD_SCHEDULER_12_63	128
	ROUND_16_63	A B C D E F G H	0x79D8A7A8 176 284
	WORD_SCHEDULER_12_63	132
	ROUND_16_63	D A B C H E F G 0xF3B14F50 180 284
	WORD_SCHEDULER_12_63	136
	ROUND_16_63	C D A B G H E F 0xE7629EA1 184 284
	WORD_SCHEDULER_12_63	140
	ROUND_16_63	B C D A F G H E 0xCEC53D43 188 284
	WORD_SCHEDULER_12_63	144
	ROUND_16_63	A B C D E F G H	0x9D8A7A87 192 284
	WORD_SCHEDULER_12_63	148
	ROUND_16_63	D A B C H E F G 0x3B14F50F 196 284
	WORD_SCHEDULER_12_63	152
	ROUND_16_63	C D A B G H E F 0x7629EA1E 200 284
	WORD_SCHEDULER_12_63	156
	ROUND_16_63	B C D A F G H E 0xEC53D43C 204 284
	WORD_SCHEDULER_12_63	160
	ROUND_16_63	A B C D E F G H	0xD8A7A879 208 284
	WORD_SCHEDULER_12_63	164
	ROUND_16_63	D A B C H E F G 0xB14F50F3 212 284
	WORD_SCHEDULER_12_63	168
	ROUND_16_63	C D A B G H E F 0x629EA1E7 216 284
	WORD_SCHEDULER_12_63	172
	ROUND_16_63	B C D A F G H E 0xC53D43CE 220 284
	WORD_SCHEDULER_12_63	176
	ROUND_16_63	A B C D E F G H	0x8A7A879D 224 284
	WORD_SCHEDULER_12_63	180
	ROUND_16_63	D A B C H E F G 0x14F50F3B 228 284
	WORD_SCHEDULER_12_63	184
	ROUND_16_63	C D A B G H E F 0x29EA1E76 232 284
	WORD_SCHEDULER_12_63	188
	ROUND_16_63	B C D A F G H E 0x53D43CEC 236 284
	WORD_SCHEDULER_12_63	192
	ROUND_16_63	A B C D E F G H	0xA7A879D8 240 284
	WORD_SCHEDULER_12_63	196
	ROUND_16_63	D A B C H E F G 0x4F50F3B1 244 284
	WORD_SCHEDULER_12_63	200
	ROUND_16_63	C D A B G H E F 0x9EA1E762 248 284
	WORD_SCHEDULER_12_63	204
	ROUND_16_63	B C D A F G H E 0x3D43CEC5 252 284

	xorl	A,(STATE)
	xorl	B,4(STATE)
	xorl	C,8(STATE)
	xorl	D,12(STATE)
	xorl	E,16(STATE)
	xorl	F,20(STATE)
	xorl	G,24(STATE)
	xorl	H,28(STATE)

	leaq	64(DATA),DATA
	decq	NUM
	jz		.Lsm3_final
	jmp		.Lsm3_loop

.Lsm3_final:
	# Clear Context
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	# Restore Registers
	movq	300(%rsp),%rbx
	movq	8+300(%rsp),%rbp
	movq	16+300(%rsp),%r12
	movq	24+300(%rsp),%r13
	movq	32+300(%rsp),%r14
	movq	40+300(%rsp),%r15
	addq	$348,%rsp

.Lsm3_ret:
	ret
.size	SM3_CompressAsm, .-SM3_CompressAsm

.section	.rodata
.align	64
MASKS:
# .shuffle_mask: (%rax)
.byte	3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12
# left rotations
# .r16: 16(%rax)
.byte	2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13
# .r24: 32(%rax)
.byte	1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12

#endif
