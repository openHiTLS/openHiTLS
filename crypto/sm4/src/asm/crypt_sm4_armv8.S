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

#include "crypt_arm.h"
.arch	armv8-a+crypto

rk0       .req  v12
rk1       .req  v13
rka       .req  v14
rkb       .req  v15
rk2       .req  v20
rkc       .req  v21

vtmp0     .req  v0
vtmp1     .req  v1
vtmp2     .req  v2
vtmp3     .req  v3

vtmp4     .req  v24
vtmp5     .req  v25
vtmp6     .req  v22
vtmp7     .req  v23

data0     .req  v4
data1     .req  v5
data2     .req  v6
data3     .req  v7

datax0     .req  v8
datax1     .req  v9
datax2     .req  v10
datax3     .req  v11

vtmpx0     .req  v12
vtmpx1     .req  v13
vtmpx2     .req  v14
vtmpx3     .req  v15

data10     .req  v16
data11     .req  v17
data12     .req  v18
data13     .req  v19

MaskV     .req  v26
TAHMatV   .req  v27
TALMatV   .req  v28
ATAHMatV  .req  v29
ATALMatV  .req  v30
ANDMaskV  .req  v31

MaskQ      .req q26
TAHMatQ    .req q27
TALMatQ    .req q28
ATAHMatQ   .req q29
ATALMatQ   .req q30
ANDMaskQ   .req q31
vtmp5q     .req q25
vtmp6q     .req q22
vtmp7q     .req q23

inp      .req   x0
outp     .req   x1
blocks   .req   w2
rks      .req   x3

wtmp0   .req    w7
wtmp1   .req    w8
wtmp2   .req    w9

ptr     .req    x10
counter .req    w11

word0   .req    w12 
word1   .req    w13 
word2   .req    w14 
word3   .req    w15 

xword1  .req    x13  
tbox0   .req    x19
tbox1   .req    x20
tbox2   .req    x21
tbox3   .req    x22

len     .req   x2
ivp     .req   x4
ctr     .req   w5
ivec    .req   v3
ivec1   .req   v15

.section .rodata
.align 4
.Ltbox1:
.word	0xd55b5b8e, 0x924242d0, 0xeaa7a74d, 0xfdfbfb06, 0xcf3333fc, 0xe2878765, 0x3df4f4c9, 0xb5dede6b, 0x1658584e
.word	0xb4dada6e, 0x14505044, 0xc10b0bca, 0x28a0a088, 0xf8efef17, 0x2cb0b09c, 0x05141411, 0x2bacac87, 0x669d9dfb
.word	0x986a6af2, 0x77d9d9ae, 0x2aa8a882, 0xbcfafa46, 0x04101014, 0xc00f0fcf, 0xa8aaaa02, 0x45111154, 0x134c4c5f
.word	0x269898be, 0x4825256d, 0x841a1a9e, 0x0618181e, 0x9b6666fd, 0x9e7272ec, 0x4309094a, 0x51414110, 0xf7d3d324
.word	0x934646d5, 0xecbfbf53, 0x9a6262f8, 0x7be9e992, 0x33ccccff, 0x55515104, 0x0b2c2c27, 0x420d0d4f, 0xeeb7b759
.word	0xcc3f3ff3, 0xaeb2b21c, 0x638989ea, 0xe7939374, 0xb1cece7f, 0x1c70706c, 0xaba6a60d, 0xca2727ed, 0x08202028
.word	0xeba3a348, 0x975656c1, 0x82020280, 0xdc7f7fa3, 0x965252c4, 0xf9ebeb12, 0x74d5d5a1, 0x8d3e3eb3, 0x3ffcfcc3
.word	0xa49a9a3e, 0x461d1d5b, 0x071c1c1b, 0xa59e9e3b, 0xfff3f30c, 0xf0cfcf3f, 0x72cdcdbf, 0x175c5c4b, 0xb8eaea52
.word	0x810e0e8f, 0x5865653d, 0x3cf0f0cc, 0x1964647d, 0xe59b9b7e, 0x87161691, 0x4e3d3d73, 0xaaa2a208, 0x69a1a1c8
.word	0x6aadadc7, 0x83060685, 0xb0caca7a, 0x70c5c5b5, 0x659191f4, 0xd96b6bb2, 0x892e2ea7, 0xfbe3e318, 0xe8afaf47
.word	0x0f3c3c33, 0x4a2d2d67, 0x71c1c1b0, 0x5759590e, 0x9f7676e9, 0x35d4d4e1, 0x1e787866, 0x249090b4, 0x0e383836
.word	0x5f797926, 0x628d8def, 0x59616138, 0xd2474795, 0xa08a8a2a, 0x259494b1, 0x228888aa, 0x7df1f18c, 0x3bececd7
.word	0x01040405, 0x218484a5, 0x79e1e198, 0x851e1e9b, 0xd7535384, 0x00000000, 0x4719195e, 0x565d5d0b, 0x9d7e7ee3
.word	0xd04f4f9f, 0x279c9cbb, 0x5349491a, 0x4d31317c, 0x36d8d8ee, 0x0208080a, 0xe49f9f7b, 0xa2828220, 0xc71313d4
.word	0xcb2323e8, 0x9c7a7ae6, 0xe9abab42, 0xbdfefe43, 0x882a2aa2, 0xd14b4b9a, 0x41010140, 0xc41f1fdb, 0x38e0e0d8
.word	0xb7d6d661, 0xa18e8e2f, 0xf4dfdf2b, 0xf1cbcb3a, 0xcd3b3bf6, 0xfae7e71d, 0x608585e5, 0x15545441, 0xa3868625
.word	0xe3838360, 0xacbaba16, 0x5c757529, 0xa6929234, 0x996e6ef7, 0x34d0d0e4, 0x1a686872, 0x54555501, 0xafb6b619
.word	0x914e4edf, 0x32c8c8fa, 0x30c0c0f0, 0xf6d7d721, 0x8e3232bc, 0xb3c6c675, 0xe08f8f6f, 0x1d747469, 0xf5dbdb2e
.word	0xe18b8b6a, 0x2eb8b896, 0x800a0a8a, 0x679999fe, 0xc92b2be2, 0x618181e0, 0xc30303c0, 0x29a4a48d, 0x238c8caf
.word	0xa9aeae07, 0x0d343439, 0x524d4d1f, 0x4f393976, 0x6ebdbdd3, 0xd6575781, 0xd86f6fb7, 0x37dcdceb, 0x44151551
.word	0xdd7b7ba6, 0xfef7f709, 0x8c3a3ab6, 0x2fbcbc93, 0x030c0c0f, 0xfcffff03, 0x6ba9a9c2, 0x73c9c9ba, 0x6cb5b5d9
.word	0x6db1b1dc, 0x5a6d6d37, 0x50454515, 0x8f3636b9, 0x1b6c6c77, 0xadbebe13, 0x904a4ada, 0xb9eeee57, 0xde7777a9
.word	0xbef2f24c, 0x7efdfd83, 0x11444455, 0xda6767bd, 0x5d71712c, 0x40050545, 0x1f7c7c63, 0x10404050, 0x5b696932
.word	0xdb6363b8, 0x0a282822, 0xc20707c5, 0x31c4c4f5, 0x8a2222a8, 0xa7969631, 0xce3737f9, 0x7aeded97, 0xbff6f649
.word	0x2db4b499, 0x75d1d1a4, 0xd3434390, 0x1248485a, 0xbae2e258, 0xe6979771, 0xb6d2d264, 0xb2c2c270, 0x8b2626ad
.word	0x68a5a5cd, 0x955e5ecb, 0x4b292962, 0x0c30303c, 0x945a5ace, 0x76ddddab, 0x7ff9f986, 0x649595f1, 0xbbe6e65d
.word	0xf2c7c735, 0x0924242d, 0xc61717d1, 0x6fb9b9d6, 0xc51b1bde, 0x86121294, 0x18606078, 0xf3c3c330, 0x7cf5f589
.word	0xefb3b35c, 0x3ae8e8d2, 0xdf7373ac, 0x4c353579, 0x208080a0, 0x78e5e59d, 0xedbbbb56, 0x5e7d7d23, 0x3ef8f8c6
.word	0xd45f5f8b, 0xc82f2fe7, 0x39e4e4dd, 0x49212168

.Ltbox2:
.word	0x5b5b8ed5, 0x4242d092, 0xa7a74dea, 0xfbfb06fd, 0x3333fccf, 0x878765e2, 0xf4f4c93d, 0xdede6bb5, 0x58584e16
.word	0xdada6eb4, 0x50504414, 0x0b0bcac1, 0xa0a08828, 0xefef17f8, 0xb0b09c2c, 0x14141105, 0xacac872b, 0x9d9dfb66
.word	0x6a6af298, 0xd9d9ae77, 0xa8a8822a, 0xfafa46bc, 0x10101404, 0x0f0fcfc0, 0xaaaa02a8, 0x11115445, 0x4c4c5f13
.word	0x9898be26, 0x25256d48, 0x1a1a9e84, 0x18181e06, 0x6666fd9b, 0x7272ec9e, 0x09094a43, 0x41411051, 0xd3d324f7
.word	0x4646d593, 0xbfbf53ec, 0x6262f89a, 0xe9e9927b, 0xccccff33, 0x51510455, 0x2c2c270b, 0xd0d4f42,  0xb7b759ee
.word	0x3f3ff3cc, 0xb2b21cae, 0x8989ea63, 0x939374e7, 0xcece7fb1, 0x70706c1c, 0xa6a60dab, 0x2727edca, 0x20202808
.word	0xa3a348eb, 0x5656c197, 0x02028082, 0x7f7fa3dc, 0x5252c496, 0xebeb12f9, 0xd5d5a174, 0x3e3eb38d, 0xfcfcc33f
.word	0x9a9a3ea4, 0x1d1d5b46, 0x1c1c1b07, 0x9e9e3ba5, 0xf3f30cff, 0xcfcf3ff0, 0xcdcdbf72, 0x5c5c4b17, 0xeaea52b8
.word	0x0e0e8f81, 0x65653d58, 0xf0f0cc3c, 0x64647d19, 0x9b9b7ee5, 0x16169187, 0x3d3d734e, 0xa2a208aa, 0xa1a1c869
.word	0xadadc76a, 0x06068583, 0xcaca7ab0, 0xc5c5b570, 0x9191f465, 0x6b6bb2d9, 0x2e2ea789, 0xe3e318fb, 0xafaf47e8
.word	0x3c3c330f, 0x2d2d674a, 0xc1c1b071, 0x59590e57, 0x7676e99f, 0xd4d4e135, 0x7878661e, 0x9090b424, 0x3838360e
.word	0x7979265f, 0x8d8def62, 0x61613859, 0x474795d2, 0x8a8a2aa0, 0x9494b125, 0x8888aa22, 0xf1f18c7d, 0xececd73b
.word	0x04040501, 0x8484a521, 0xe1e19879, 0x1e1e9b85, 0x535384d7, 0x00000000, 0x19195e47, 0x5d5d0b56, 0x7e7ee39d
.word	0x4f4f9fd0, 0x9c9cbb27, 0x49491a53, 0x31317c4d, 0xd8d8ee36, 0x08080a02, 0x9f9f7be4, 0x828220a2, 0x1313d4c7
.word	0x2323e8cb, 0x7a7ae69c, 0xabab42e9, 0xfefe43bd, 0x2a2aa288, 0x4b4b9ad1, 0x01014041, 0x1f1fdbc4, 0xe0e0d838
.word	0xd6d661b7, 0x8e8e2fa1, 0xdfdf2bf4, 0xcbcb3af1, 0x3b3bf6cd, 0xe7e71dfa, 0x8585e560, 0x54544115, 0x868625a3
.word	0x838360e3, 0xbaba16ac, 0x7575295c, 0x929234a6, 0x6e6ef799, 0xd0d0e434, 0x6868721a, 0x55550154, 0xb6b619af
.word	0x4e4edf91, 0xc8c8fa32, 0xc0c0f030, 0xd7d721f6, 0x3232bc8e, 0xc6c675b3, 0x8f8f6fe0, 0x7474691d, 0xdbdb2ef5
.word	0x8b8b6ae1, 0xb8b8962e, 0x0a0a8a80, 0x9999fe67, 0x2b2be2c9, 0x8181e061, 0x0303c0c3, 0xa4a48d29, 0x8c8caf23
.word	0xaeae07a9, 0x3434390d, 0x4d4d1f52, 0x3939764f, 0xbdbdd36e, 0x575781d6, 0x6f6fb7d8, 0xdcdceb37, 0x15155144
.word	0x7b7ba6dd, 0xf7f709fe, 0x3a3ab68c, 0xbcbc932f, 0x0c0c0f03, 0xffff03fc, 0xa9a9c26b, 0xc9c9ba73, 0xb5b5d96c
.word	0xb1b1dc6d, 0x6d6d375a, 0x45451550, 0x3636b98f, 0x6c6c771b, 0xbebe13ad, 0x4a4ada90, 0xeeee57b9, 0x7777a9de
.word	0xf2f24cbe, 0xfdfd837e, 0x44445511, 0x6767bdda, 0x71712c5d, 0x05054540, 0x7c7c631f, 0x40405010, 0x6969325b
.word	0x6363b8db, 0x2828220a, 0x0707c5c2, 0xc4c4f531, 0x2222a88a, 0x969631a7, 0x3737f9ce, 0xeded977a, 0xf6f649bf
.word	0xb4b4992d, 0xd1d1a475, 0x434390d3, 0x48485a12, 0xe2e258ba, 0x979771e6, 0xd2d264b6, 0xc2c270b2, 0x2626ad8b
.word	0xa5a5cd68, 0x5e5ecb95, 0x2929624b, 0x30303c0c, 0x5a5ace94, 0xddddab76, 0xf9f9867f, 0x9595f164, 0xe6e65dbb
.word	0xc7c735f2, 0x24242d09, 0x1717d1c6, 0xb9b9d66f, 0x1b1bdec5, 0x12129486, 0x60607818, 0xc3c330f3, 0xf5f5897c
.word	0xb3b35cef, 0xe8e8d23a, 0x7373acdf, 0x3535794c, 0x8080a020, 0xe5e59d78, 0xbbbb56ed, 0x7d7d235e, 0xf8f8c63e
.word	0x5f5f8bd4, 0x2f2fe7c8, 0xe4e4dd39, 0x21216849

.Ltbox3:
.word	0x5b8ed55b, 0x42d09242, 0xa74deaa7, 0xfb06fdfb, 0x33fccf33, 0x8765e287, 0xf4c93df4, 0xde6bb5de, 0x584e1658
.word	0xda6eb4da, 0x50441450, 0x0bcac10b, 0xa08828a0, 0xef17f8ef, 0xb09c2cb0, 0x14110514, 0xac872bac, 0x9dfb669d
.word	0x6af2986a, 0xd9ae77d9, 0xa8822aa8, 0xfa46bcfa, 0x10140410, 0x0fcfc00f, 0xaa02a8aa, 0x11544511, 0x4c5f134c
.word	0x98be2698, 0x256d4825, 0x1a9e841a, 0x181e0618, 0x66fd9b66, 0x72ec9e72, 0x094a4309, 0x41105141, 0xd324f7d3
.word	0x46d59346, 0xbf53ecbf, 0x62f89a62, 0xe9927be9, 0xccff33cc, 0x51045551, 0x2c270b2c, 0x0d4f420d, 0xb759eeb7
.word	0x3ff3cc3f, 0xb21caeb2, 0x89ea6389, 0x9374e793, 0xce7fb1ce, 0x706c1c70, 0xa60daba6, 0x27edca27, 0x20280820
.word	0xa348eba3, 0x56c19756, 0x02808202, 0x7fa3dc7f, 0x52c49652, 0xeb12f9eb, 0xd5a174d5, 0x3eb38d3e, 0xfcc33ffc
.word	0x9a3ea49a, 0x1d5b461d, 0x1c1b071c, 0x9e3ba59e, 0xf30cfff3, 0xcf3ff0cf, 0xcdbf72cd, 0x5c4b175c, 0xea52b8ea
.word	0x0e8f810e, 0x653d5865, 0xf0cc3cf0, 0x647d1964, 0x9b7ee59b, 0x16918716, 0x3d734e3d, 0xa208aaa2, 0xa1c869a1
.word	0xadc76aad, 0x06858306, 0xca7ab0ca, 0xc5b570c5, 0x91f46591, 0x6bb2d96b, 0x2ea7892e, 0xe318fbe3, 0xaf47e8af
.word	0x3c330f3c, 0x2d674a2d, 0xc1b071c1, 0x590e5759, 0x76e99f76, 0xd4e135d4, 0x78661e78, 0x90b42490, 0x38360e38
.word	0x79265f79, 0x8def628d, 0x61385961, 0x4795d247, 0x8a2aa08a, 0x94b12594, 0x88aa2288, 0xf18c7df1, 0xecd73bec
.word	0x04050104, 0x84a52184, 0xe19879e1, 0x1e9b851e, 0x5384d753, 0x00000000, 0x195e4719, 0x5d0b565d, 0x7ee39d7e
.word	0x4f9fd04f, 0x9cbb279c, 0x491a5349, 0x317c4d31, 0xd8ee36d8, 0x080a0208, 0x9f7be49f, 0x8220a282, 0x13d4c713
.word	0x23e8cb23, 0x7ae69c7a, 0xab42e9ab, 0xfe43bdfe, 0x2aa2882a, 0x4b9ad14b, 0x01404101, 0x1fdbc41f, 0xe0d838e0
.word	0xd661b7d6, 0x8e2fa18e, 0xdf2bf4df, 0xcb3af1cb, 0x3bf6cd3b, 0xe71dfae7, 0x85e56085, 0x54411554, 0x8625a386
.word	0x8360e383, 0xba16acba, 0x75295c75, 0x9234a692, 0x6ef7996e, 0xd0e434d0, 0x68721a68, 0x55015455, 0xb619afb6
.word	0x4edf914e, 0xc8fa32c8, 0xc0f030c0, 0xd721f6d7, 0x32bc8e32, 0xc675b3c6, 0x8f6fe08f, 0x74691d74, 0xdb2ef5db
.word	0x8b6ae18b, 0xb8962eb8, 0x0a8a800a, 0x99fe6799, 0x2be2c92b, 0x81e06181, 0x03c0c303, 0xa48d29a4, 0x8caf238c
.word	0xae07a9ae, 0x34390d34, 0x4d1f524d, 0x39764f39, 0xbdd36ebd, 0x5781d657, 0x6fb7d86f, 0xdceb37dc, 0x15514415
.word	0x7ba6dd7b, 0xf709fef7, 0x3ab68c3a, 0xbc932fbc, 0x0c0f030c, 0xff03fcff, 0xa9c26ba9, 0xc9ba73c9, 0xb5d96cb5
.word	0xb1dc6db1, 0x6d375a6d, 0x45155045, 0x36b98f36, 0x6c771b6c, 0xbe13adbe, 0x4ada904a, 0xee57b9ee, 0x77a9de77
.word	0xf24cbef2, 0xfd837efd, 0x44551144, 0x67bdda67, 0x712c5d71, 0x05454005, 0x7c631f7c, 0x40501040, 0x69325b69
.word	0x63b8db63, 0x28220a28, 0x07c5c207, 0xc4f531c4, 0x22a88a22, 0x9631a796, 0x37f9ce37, 0xed977aed, 0xf649bff6
.word	0xb4992db4, 0xd1a475d1, 0x4390d343, 0x485a1248, 0xe258bae2, 0x9771e697, 0xd264b6d2, 0xc270b2c2, 0x26ad8b26
.word	0xa5cd68a5, 0x5ecb955e, 0x29624b29, 0x303c0c30, 0x5ace945a, 0xddab76dd, 0xf9867ff9, 0x95f16495, 0xe65dbbe6
.word	0xc735f2c7, 0x242d0924, 0x17d1c617, 0xb9d66fb9, 0x1bdec51b, 0x12948612, 0x60781860, 0xc330f3c3, 0xf5897cf5
.word	0xb35cefb3, 0xe8d23ae8, 0x73acdf73, 0x35794c35, 0x80a02080, 0xe59d78e5, 0xbb56edbb, 0x7d235e7d, 0xf8c63ef8
.word	0x5f8bd45f, 0x2fe7c82f, 0xe4dd39e4, 0x21684921

.Ltbox4:
.word	0x8ed55b5b, 0xd0924242, 0x4deaa7a7, 0x06fdfbfb, 0xfccf3333, 0x65e28787, 0xc93df4f4, 0x6bb5dede, 0x4e165858
.word	0x6eb4dada, 0x44145050, 0xcac10b0b, 0x8828a0a0, 0x17f8efef, 0x9c2cb0b0, 0x11051414, 0x872bacac, 0xfb669d9d
.word	0xf2986a6a, 0xae77d9d9, 0x822aa8a8, 0x46bcfafa, 0x14041010, 0xcfc00f0f, 0x02a8aaaa, 0x54451111, 0x5f134c4c
.word	0xbe269898, 0x6d482525, 0x9e841a1a, 0x1e061818, 0xfd9b6666, 0xec9e7272, 0x4a430909, 0x10514141, 0x24f7d3d3
.word	0xd5934646, 0x53ecbfbf, 0xf89a6262, 0x927be9e9, 0xff33cccc, 0x04555151, 0x270b2c2c, 0x4f420d0d, 0x59eeb7b7
.word	0xf3cc3f3f, 0x1caeb2b2, 0xea638989, 0x74e79393, 0x7fb1cece, 0x6c1c7070, 0x0daba6a6, 0xedca2727, 0x28082020
.word	0x48eba3a3, 0xc1975656, 0x80820202, 0xa3dc7f7f, 0xc4965252, 0x12f9ebeb, 0xa174d5d5, 0xb38d3e3e, 0xc33ffcfc
.word	0x3ea49a9a, 0x5b461d1d, 0x1b071c1c, 0x3ba59e9e, 0x0cfff3f3, 0x3ff0cfcf, 0xbf72cdcd, 0x4b175c5c, 0x52b8eaea
.word	0x8f810e0e, 0x3d586565, 0xcc3cf0f0, 0x7d196464, 0x7ee59b9b, 0x91871616, 0x734e3d3d, 0x08aaa2a2, 0xc869a1a1
.word	0xc76aadad, 0x85830606, 0x7ab0caca, 0xb570c5c5, 0xf4659191, 0xb2d96b6b, 0xa7892e2e, 0x18fbe3e3, 0x47e8afaf
.word	0x330f3c3c, 0x674a2d2d, 0xb071c1c1, 0x0e575959, 0xe99f7676, 0xe135d4d4, 0x661e7878, 0xb4249090, 0x360e3838
.word	0x265f7979, 0xef628d8d, 0x38596161, 0x95d24747, 0x2aa08a8a, 0xb1259494, 0xaa228888, 0x8c7df1f1, 0xd73becec
.word	0x05010404, 0xa5218484, 0x9879e1e1, 0x9b851e1e, 0x84d75353, 0x00000000, 0x5e471919, 0x0b565d5d, 0xe39d7e7e
.word	0x9fd04f4f, 0xbb279c9c, 0x1a534949, 0x7c4d3131, 0xee36d8d8, 0x0a020808, 0x7be49f9f, 0x20a28282, 0xd4c71313
.word	0xe8cb2323, 0xe69c7a7a, 0x42e9abab, 0x43bdfefe, 0xa2882a2a, 0x9ad14b4b, 0x40410101, 0xdbc41f1f, 0xd838e0e0
.word	0x61b7d6d6, 0x2fa18e8e, 0x2bf4dfdf, 0x3af1cbcb, 0xf6cd3b3b, 0x1dfae7e7, 0xe5608585, 0x41155454, 0x25a38686
.word	0x60e38383, 0x16acbaba, 0x295c7575, 0x34a69292, 0xf7996e6e, 0xe434d0d0, 0x721a6868, 0x01545555, 0x19afb6b6
.word	0xdf914e4e, 0xfa32c8c8, 0xf030c0c0, 0x21f6d7d7, 0xbc8e3232, 0x75b3c6c6, 0x6fe08f8f, 0x691d7474, 0x2ef5dbdb
.word	0x6ae18b8b, 0x962eb8b8, 0x8a800a0a, 0xfe679999, 0xe2c92b2b, 0xe0618181, 0xc0c30303, 0x8d29a4a4, 0xaf238c8c
.word	0x07a9aeae, 0x390d3434, 0x1f524d4d, 0x764f3939, 0xd36ebdbd, 0x81d65757, 0xb7d86f6f, 0xeb37dcdc, 0x51441515
.word	0xa6dd7b7b, 0x09fef7f7, 0xb68c3a3a, 0x932fbcbc, 0x0f030c0c, 0x03fcffff, 0xc26ba9a9, 0xba73c9c9, 0xd96cb5b5
.word	0xdc6db1b1, 0x375a6d6d, 0x15504545, 0xb98f3636, 0x771b6c6c, 0x13adbebe, 0xda904a4a, 0x57b9eeee, 0xa9de7777
.word	0x4cbef2f2, 0x837efdfd, 0x55114444, 0xbdda6767, 0x2c5d7171, 0x45400505, 0x631f7c7c, 0x50104040, 0x325b6969
.word	0xb8db6363, 0x220a2828, 0xc5c20707, 0xf531c4c4, 0xa88a2222, 0x31a79696, 0xf9ce3737, 0x977aeded, 0x49bff6f6
.word	0x992db4b4, 0xa475d1d1, 0x90d34343, 0x5a124848, 0x58bae2e2, 0x71e69797, 0x64b6d2d2, 0x70b2c2c2, 0xad8b2626
.word	0xcd68a5a5, 0xcb955e5e, 0x624b2929, 0x3c0c3030, 0xce945a5a, 0xab76dddd, 0x867ff9f9, 0xf1649595, 0x5dbbe6e6
.word	0x35f2c7c7, 0x2d092424, 0xd1c61717, 0xd66fb9b9, 0xdec51b1b, 0x94861212, 0x78186060, 0x30f3c3c3, 0x897cf5f5
.word	0x5cefb3b3, 0xd23ae8e8, 0xacdf7373, 0x794c3535, 0xa0208080, 0x9d78e5e5, 0x56edbbbb, 0x235e7d7d, 0xc63ef8f8
.word	0x8bd45f5f, 0xe7c82f2f, 0xdd39e4e4, 0x68492121

#ifdef HITLS_BIG_ENDIAN
.Lxts_magic:
	.quad	0x0101010101010101,0x0101010101010187

.Lsbox_magic:
    .dword 0x0306090c0f020508,0x0b0e0104070a0d00
    .dword 0x22581a6002783a40,0x62185a2042387a00
    .dword 0xc10bb67c4a803df7,0x15df62a89e54e923
    .dword 0x1407c6d56c7fbead,0xb9aa6b78c1d21300
    .dword 0xe383c1a1fe9edcbc,0x6404462679195b3b
    .dword 0x0E0D0C0F0A09080B,0x0605040702010003
    .dword 0x0D0C0F0E09080B0A,0x0504070601000302
    .dword 0x0C0F0E0D080B0A09,0x0407060500030201
#else
.Lxts_magic:
	.quad	0x0101010101010187,0x0101010101010101

.Lsbox_magic:
    .dword 0x0b0e0104070a0d00,0x0306090c0f020508
    .dword 0x62185a2042387a00,0x22581a6002783a40
    .dword 0x15df62a89e54e923,0xc10bb67c4a803df7
    .dword 0xb9aa6b78c1d21300,0x1407c6d56c7fbead
    .dword 0x6404462679195b3b,0xe383c1a1fe9edcbc
    .dword 0x0605040702010003,0x0E0D0C0F0A09080B
    .dword 0x0504070601000302,0x0D0C0F0E09080B0A
    .dword 0x0407060500030201,0x0C0F0E0D080B0A09
#endif

.macro LoadSbox
	adrp	x15,.Lsbox_magic
	add	x15,x15,:lo12:.Lsbox_magic
    ldr MaskQ,      [x15]
    ldr TAHMatQ,    [x15, #16]
    ldr TALMatQ,    [x15, #32]
    ldr ATAHMatQ,   [x15, #48]
    ldr ATALMatQ,   [x15, #64]
    ldr vtmp5q,     [x15, #80]
    ldr vtmp6q,     [x15, #96]
    ldr vtmp7q,     [x15, #112]
.endm

.macro round x1, x2, x3, x4, rk
	eor	word0,\x2, \x3
	eor	word0, word0, \rk
	eor	word0, word0, \x4

	and	word1, word0, #0xff
	ldr	word1, [tbox0,xword1,lsl #2]
	eor	\x1, word1, \x1

	ubfx word1, word0,#8,#8
	ldr	word1, [tbox1, xword1, lsl #2]
	eor	\x1, word1, \x1

	ubfx word1, word0, #16, #8
	ldr	word1,[tbox2, xword1, lsl #2]
	eor	\x1, word1, \x1

	lsr	word1, word0, #24
	ldr	word1, [tbox3, xword1, lsl #2]
	eor	\x1, word1, \x1
.endm

.macro EncRound4 offset1, offset2
	ldp	word2, word3,[rks, \offset1]
	round w8, w9, w10, w11, word2
	round w9, w10, w11, w8, word3
	ldp	word2, word3,[rks, \offset2]
	round w10, w11, w8, w9, word2
	round w11, w8, w9, w10, word3
.endm

.macro EncRound
	EncRound4 0, 8
	EncRound4 16, 24
	EncRound4 32, 40
	EncRound4 48, 56
	EncRound4 64, 72
	EncRound4 80, 88
	EncRound4 96, 104
	EncRound4 112, 120
.endm

.macro transpose dat0s, dat1s, dat2s, dat3s, dat0d, dat1d, dat2d, dat3d, vt0s, vt1s, vt2s, vt3s, vt0d, vt1d, vt2d, vt3d
	zip1	\vt0s, \dat0s, \dat1s
	zip2	\vt1s, \dat0s, \dat1s
	zip1	\vt2s, \dat2s, \dat3s
	zip2	\vt3s, \dat2s, \dat3s
	zip1	\dat0d, \vt0d, \vt2d
	zip2	\dat1d, \vt0d, \vt2d
	zip1	\dat2d, \vt1d, \vt3d
	zip2	\dat3d, \vt1d, \vt3d
.endm

.macro Encrypt1blkNorevCtr
	mov	w8,ivec.s[0]
	mov	w9,ivec.s[1]
	mov	w10,ivec.s[2]
	mov	w11,ivec.s[3]
	EncRound
	mov	ivec.s[0],w11
	mov	ivec.s[1],w10
	mov	ivec.s[2],w9
	mov	ivec.s[3],w8
#ifndef HITLS_BIG_ENDIAN
	rev32 v3.16b,v3.16b
#endif
.endm

# matrix multiplication Mat*x = (lowerMat*x) ^ (higherMat*x)
.macro MulMatrix x, higherMat, lowerMat, tmp
	ushr	\tmp, \x, 4
	and		\x, \x, ANDMaskV.16b
	tbl		\x, {\lowerMat}, \x
	tbl		\tmp, {\higherMat}, \tmp
	eor		\x, \x, \tmp
.endm

# matrix multiplication Mat*x = (lowerMat*x) ^ (higherMat*x)
.macro MulMatrixOut x, higherMat, lowerMat, tmp, out
	ushr	\tmp, \x, 4
	and		\x, \x, ANDMaskV.16b
	tbl		\x, {\lowerMat}, \x
	tbl		\tmp, {\higherMat}, \tmp
	eor		\out, \x, \tmp
.endm

# Sbox operations for 4-lane of words
.macro Sbox dat, dat2
	movi ANDMaskV.16b, #0x0f
	// optimize Sbox using AESE instruction
	tbl	v0.16b, {\dat}, MaskV.16b
	MulMatrix v0.16b, TAHMatV.16b, TALMatV.16b, v24.16b

	eor v1.16b, v1.16b, v1.16b
	aese v0.16b, v1.16b
	
	MulMatrix v0.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b

	mov	\dat, v0.16b

	// linear transformation
	ushr	v0.4s, \dat2,32-2
	ushr	v1.4s, \dat2,32-10
	ushr	v2.4s, \dat2,32-18
	ushr	v3.4s, \dat2,32-24
	sli	v0.4s, \dat2,2
	sli	v1.4s, \dat2,10
	sli	v2.4s, \dat2,18
	sli	v3.4s, \dat2,24
	eor	v24.16b, v0.16b, \dat
	eor	v24.16b, v24.16b, v1.16b
	eor	\dat, v2.16b, v3.16b
	eor	\dat, \dat, v24.16b
.endm

# sm4 for 4-lanes of data, in neon registers data0/data1/data2/data3
.macro Sm44blks kptr
	ldp	wtmp0, wtmp1,[\kptr],8
	dup	rk0.4s, wtmp0
	dup	rk1.4s, wtmp1

	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	rka.16b, v6.16b, v7.16b
	eor	rk0.16b, v5.16b, rk0.16b
	eor	rk0.16b, rka.16b, rk0.16b

	Sbox rk0.16b, rk0.4s

	eor	v4.16b, v4.16b, rk0.16b

	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	rka.16b, rka.16b, v4.16b
	eor	rk1.16b, rka.16b, rk1.16b

	Sbox rk1.16b, rk1.4s

	ldp	wtmp0, wtmp1,[\kptr],8
	eor	v5.16b,v5.16b, rk1.16b

	dup	rk0.4s, wtmp0
	dup	rk1.4s, wtmp1

	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	rka.16b, v4.16b, v5.16b
	eor	rk0.16b, v7.16b, rk0.16b
	eor	rk0.16b, rka.16b, rk0.16b

	Sbox rk0.16b, rk0.4s

	eor	v6.16b, v6.16b, rk0.16b

	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	rka.16b, rka.16b, v6.16b
	eor	rk1.16b, rka.16b, rk1.16b

	Sbox rk1.16b, rk1.4s

	eor	v7.16b, v7.16b, rk1.16b
.endm


.macro Encrypt4blks
	mov	ptr, rks
	mov	counter,#8
10:
	Sm44blks ptr
	
	subs counter, counter,#1
	b.ne 10b
#ifndef HITLS_BIG_ENDIAN
	rev32	v3.16b,v4.16b
	rev32	v2.16b,v5.16b
	rev32	v1.16b,v6.16b
	rev32	v0.16b,v7.16b
#else
	mov	    v3.16b,v4.16b
	mov	    v2.16b,v5.16b
	mov	    v1.16b,v6.16b
	mov	    v0.16b,v7.16b
#endif
.endm

# Sbox operation for 8-lane of words
.macro SboxDouble dat datx
	movi ANDMaskV.16b, #0x0f
	// optimize Sbox using AESE instruction
	tbl	v0.16b, {rk0.16b}, MaskV.16b
	tbl	v1.16b, {rk1.16b}, MaskV.16b

	MulMatrix v0.16b, TAHMatV.16b, TALMatV.16b, v24.16b
	MulMatrix v1.16b, TAHMatV.16b, TALMatV.16b, v24.16b
	eor vtmp5.16b, vtmp5.16b, vtmp5.16b
	aese v0.16b,vtmp5.16b
	aese v1.16b,vtmp5.16b
	MulMatrixOut v0.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b, rk0.16b
	MulMatrixOut v1.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b, rk1.16b

	// linear transformation
	ushr	v0.4s,rk0.4s,32-2
	ushr	vtmp5.4s,rk1.4s,32-2
	ushr	v1.4s,rk0.4s,32-10
	ushr	v2.4s,rk0.4s,32-18
	ushr	v3.4s,rk0.4s,32-24
	sli	v0.4s,rk0.4s,2
	sli	vtmp5.4s,rk1.4s,2
	sli	v1.4s,rk0.4s,10
	sli	v2.4s,rk0.4s,18
	sli	v3.4s,rk0.4s,24
	eor	v24.16b,v0.16b,rk0.16b
	eor	v24.16b,v24.16b,v1.16b
	eor	rk0.16b,v2.16b,v3.16b
	eor	rk0.16b,rk0.16b,v24.16b
	ushr	v1.4s,rk1.4s,32-10
	ushr	v2.4s,rk1.4s,32-18
	ushr	v3.4s,rk1.4s,32-24
	sli	v1.4s,rk1.4s,10
	sli	v2.4s,rk1.4s,18
	sli	v3.4s,rk1.4s,24
	eor	v24.16b,vtmp5.16b,rk1.16b
	eor	v24.16b,v24.16b,v1.16b
	eor	rk1.16b,v2.16b,v3.16b
	eor	rk1.16b,rk1.16b,v24.16b
.endm


.macro SboxThree dat, datx, dat1
	movi	ANDMaskV.16b, #0x0f
	// optimize sbox using AESE instruction
	tbl	v0.16b, {\dat}, MaskV.16b
	tbl	v1.16b, {\datx}, MaskV.16b
	tbl	v2.16b, {\dat1}, MaskV.16b
	eor v3.16b, v3.16b, v3.16b

	MulMatrix v0.16b, TAHMatV.16b, TALMatV.16b, v24.16b
	MulMatrix v1.16b, TAHMatV.16b, TALMatV.16b, v24.16b

	aese v0.16b, v3.16b

	MulMatrix v2.16b, TAHMatV.16b, TALMatV.16b, v24.16b

	aese v1.16b, v3.16b
	aese v2.16b, v3.16b

	MulMatrixOut v0.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b, \dat
	MulMatrixOut v1.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b, \datx
	MulMatrixOut v2.16b, ATAHMatV.16b, ATALMatV.16b, v24.16b, \dat1

	// linear transformation
    tbl v0.16b, {\dat},  vtmp5.16b // shitf left 8
    tbl v1.16b, {\datx}, vtmp5.16b
    tbl v2.16b, {\dat1}, vtmp5.16b

    tbl v3.16b,  {\dat},   v22.16b // shitf left 16
    tbl v24.16b,    {\datx},  v22.16b
    tbl ANDMaskV.16b, {\dat1},  v22.16b

    eor v0.16b, v0.16b, \dat
    eor v1.16b, v1.16b, \datx
    eor v2.16b, v2.16b, \dat1

	eor v0.16b, v0.16b, v3.16b
    eor v1.16b, v1.16b, v24.16b
    eor v2.16b, v2.16b, ANDMaskV.16b

    shl v3.4s, v0.4s, #2  // shift left by 2 bits, equivalent to v12<<2 xor v12<<10 xor v12<<18
    sri v3.4s, v0.4s, #30
    shl v24.4s, v1.4s, #2
    sri v24.4s, v1.4s, #30
    shl ANDMaskV.4s, v2.4s, #2
    sri ANDMaskV.4s, v2.4s, #30

    tbl v0.16b, {\dat},  v23.16b  // shitf left 24
    tbl v1.16b, {\datx}, v23.16b
    tbl v2.16b, {\dat1}, v23.16b

	eor \dat, \dat, v3.16b
	eor \datx, \datx, v24.16b
	eor \dat1, \dat1, ANDMaskV.16b

    eor \dat, v0.16b, \dat
    eor \datx, v1.16b, \datx
    eor \dat1, v2.16b, \dat1
.endm

.macro Sm48blks kptr
	ldp	wtmp0, wtmp1,[\kptr],8

	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	dup	rk0.4s, wtmp0
	eor	rka.16b,v6.16b,v7.16b
	eor	rkb.16b,v10.16b,v11.16b
	eor	v0.16b,v5.16b,rk0.16b
	eor	v1.16b,v9.16b,rk0.16b
	eor	rk0.16b, rka.16b,v0.16b
	eor	rk1.16b, rkb.16b,v1.16b
	SboxDouble
	eor	v4.16b, v4.16b, rk0.16b
	eor	v8.16b,v8.16b, rk1.16b

	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	dup	rk1.4s, wtmp1
	eor	rka.16b,rka.16b,v4.16b
	eor	rkb.16b,rkb.16b,v8.16b
	eor	rk0.16b,rka.16b,rk1.16b
	eor	rk1.16b,rkb.16b,rk1.16b
	SboxDouble

	ldp	wtmp0, wtmp1,[\kptr],8
	eor	v5.16b,v5.16b,rk0.16b
	eor	v9.16b,v9.16b,rk1.16b

	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	dup	rk0.4s, wtmp0
	eor	rka.16b,v4.16b,v5.16b
	eor	rkb.16b,v8.16b,v9.16b
	eor	v0.16b,v7.16b,rk0.16b
	eor	v1.16b,v11.16b,rk0.16b
	eor	rk0.16b,rka.16b,v0.16b
	eor	rk1.16b,rkb.16b,v1.16b
	SboxDouble

	eor	v6.16b,v6.16b,rk0.16b
	eor	v10.16b,v10.16b,rk1.16b

	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	dup	rk1.4s, wtmp1
	eor	rka.16b,rka.16b,v6.16b
	eor	rkb.16b,rkb.16b,v10.16b
	eor	rk0.16b,rka.16b,rk1.16b
	eor	rk1.16b,rkb.16b,rk1.16b
	SboxDouble

	eor	v7.16b,v7.16b,rk0.16b
	eor	v11.16b,v11.16b,rk1.16b
.endm


.macro Sm412blks kptr
	ldp	wtmp0,wtmp1,[\kptr],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	dup	rk0.4s,wtmp0
	eor	rka.16b,v6.16b,v7.16b
	eor	rkb.16b,v10.16b,v11.16b
	eor	rkc.16b,v18.16b,v19.16b
	eor	v0.16b,v5.16b,rk0.16b
	eor	v1.16b,v9.16b,rk0.16b
	eor	v2.16b,v17.16b,rk0.16b
	eor	rk0.16b,rka.16b,v0.16b
	eor	rk1.16b,rkb.16b,v1.16b
	eor	rk2.16b,rkc.16b,v2.16b

	SboxThree rk0.16b, rk1.16b, rk2.16b

	eor	v4.16b,v4.16b,rk0.16b
	eor	v8.16b,v8.16b,rk1.16b
	eor	v16.16b,v16.16b,rk2.16b

	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	dup	rk1.4s,wtmp1
	eor	rka.16b,rka.16b,v4.16b
	eor	rkb.16b,rkb.16b,v8.16b
	eor	rkc.16b,rkc.16b,v16.16b
	eor	rk0.16b,rka.16b,rk1.16b
	eor	rk2.16b,rkc.16b,rk1.16b
	eor	rk1.16b,rkb.16b,rk1.16b

	SboxThree rk0.16b, rk1.16b, rk2.16b

	ldp	wtmp0,wtmp1,[\kptr],8
	eor	v5.16b,v5.16b,rk0.16b
	eor	v9.16b,v9.16b,rk1.16b
	eor	v17.16b,v17.16b,rk2.16b

	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	dup	rk0.4s,wtmp0
	eor	rka.16b,v4.16b,v5.16b
	eor	rkb.16b,v8.16b,v9.16b
	eor	rkc.16b,v16.16b,v17.16b
	eor	v0.16b,v7.16b,rk0.16b
	eor	v1.16b,v11.16b,rk0.16b
	eor	v2.16b,v19.16b,rk0.16b
	eor	rk0.16b,rka.16b,v0.16b
	eor	rk1.16b,rkb.16b,v1.16b
	eor	rk2.16b,rkc.16b,v2.16b

	SboxThree rk0.16b, rk1.16b, rk2.16b

	eor	v6.16b,v6.16b,rk0.16b
	eor	v10.16b,v10.16b,rk1.16b
	eor	v18.16b,v18.16b,rk2.16b

	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	dup	rk1.4s,wtmp1
	eor	rka.16b,rka.16b,v6.16b
	eor	rkb.16b,rkb.16b,v10.16b
	eor	rkc.16b,rkc.16b,v18.16b
	eor	rk0.16b,rka.16b,rk1.16b
	eor	rk2.16b,rkc.16b,rk1.16b
	eor	rk1.16b,rkb.16b,rk1.16b

	SboxThree rk0.16b, rk1.16b, rk2.16b

	eor	v7.16b,v7.16b,rk0.16b
	eor	v11.16b,v11.16b,rk1.16b
	eor	v19.16b,v19.16b,rk2.16b
.endm


.macro Encrypt8blks
	mov	ptr, rks
	mov	counter, #8
10:
	Sm48blks ptr

	subs counter, counter,#1
	b.ne	10b
#ifndef HITLS_BIG_ENDIAN
	rev32	v3.16b,v4.16b
	rev32	v2.16b,v5.16b
	rev32	v1.16b,v6.16b
	rev32	v0.16b,v7.16b
	rev32	v7.16b,v8.16b
	rev32	v6.16b,v9.16b
	rev32	v5.16b,v10.16b
	rev32	v4.16b,v11.16b
#else
	mov 	v3.16b,v4.16b
	mov 	v2.16b,v5.16b
	mov 	v1.16b,v6.16b
	mov 	v0.16b,v7.16b
	mov 	v7.16b,v8.16b
	mov 	v6.16b,v9.16b
	mov 	v5.16b,v10.16b
	mov 	v4.16b,v11.16b
#endif
.endm

.macro Encrypt12blks
	mov	ptr, rks
	mov	counter, #8
10:
	Sm412blks ptr

	subs	counter,counter,#1
	b.ne	10b
	// last reverse transform
#ifndef HITLS_BIG_ENDIAN
	rev32	v3.16b,v4.16b
	rev32	v2.16b,v5.16b
	rev32	v1.16b,v6.16b
	rev32	v0.16b,v7.16b

	rev32	v7.16b,v8.16b
	rev32	v6.16b,v9.16b
	rev32	v5.16b,v10.16b
	rev32	v4.16b,v11.16b

	rev32	v11.16b,v16.16b
	rev32	v10.16b,v17.16b
	rev32	v9.16b,v18.16b
	rev32	v8.16b,v19.16b
#else
	mov	v3.16b,v4.16b
	mov	v2.16b,v5.16b
	mov	v1.16b,v6.16b
	mov	v0.16b,v7.16b

	mov	v7.16b,v8.16b
	mov	v6.16b,v9.16b
	mov	v5.16b,v10.16b
	mov	v4.16b,v11.16b

	mov	v11.16b,v16.16b
	mov	v10.16b,v17.16b
	mov	v9.16b,v18.16b
	mov	v8.16b,v19.16b
#endif
.endm

.text
.type	Sm4Enc4blks,%function
.align	4
Sm4Enc4blks:
AARCH64_PACIASP
	Encrypt4blks
AARCH64_AUTIASP
	ret
.size	Sm4Enc4blks,.-Sm4Enc4blks

.type	Sm4Enc8blks,%function
.align	4
Sm4Enc8blks:
AARCH64_PACIASP
	Encrypt8blks
AARCH64_AUTIASP
	ret 
.size	Sm4Enc8blks,.-Sm4Enc8blks

.type	Sm4Enc12blks,%function
.align	4
Sm4Enc12blks:
AARCH64_PACIASP
	Encrypt12blks
AARCH64_AUTIASP
	ret 
.size	Sm4Enc12blks,.-Sm4Enc12blks

.globl	Vpsm4EcbEncrypt
.type	Vpsm4EcbEncrypt,%function
.align	5
Vpsm4EcbEncrypt:
AARCH64_PACIASP
	// convert length into blocks
	lsr	x2,x2,4
	stp	d8,d9,[sp,#-112]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]
	stp	x29,x30,[sp,#64]
	stp	x19,x20,[sp,#80]
	stp	x21,x22,[sp,#96]
	LoadSbox

.Lecb_12_blocks_process:
	cmp	blocks,#12
	b.lt  .Lecb_8_blocks_process
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp],#64
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[inp],#64
	ld4	{v16.4s,v17.4s,v18.4s,v19.4s},[inp],#64

#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b

	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b

	rev32	v16.16b,v16.16b
	rev32	v17.16b,v17.16b
	rev32	v18.16b,v18.16b
	rev32	v19.16b,v19.16b
#endif

	bl	Sm4Enc12blks
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	st4	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64
	st4	{v8.4s,v9.4s,v10.4s,v11.4s},[outp],#64
	subs    blocks,blocks,#12
	b.gt	.Lecb_12_blocks_process
	b	100f

.Lecb_8_blocks_process:
	cmp	blocks, #8
	b.lt	.Lecb_4_blocks_process
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
#endif
	bl	Sm4Enc8blks
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
	st4	{v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
	subs	blocks,blocks,#8
	b.gt	.Lecb_8_blocks_process
	b	100f
.Lecb_4_blocks_process:
	cmp	blocks,#4
	b.lt	1f
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b, v4.16b
	rev32	v5.16b, v5.16b
	rev32	v6.16b, v6.16b
	rev32	v7.16b, v7.16b
#endif
	bl	Sm4Enc4blks
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
	sub	blocks,blocks,#4
1:
	// process last block
	cmp	blocks,#1
	b.lt	100f
	b.gt	1f

	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4

	ldp	w8,w9,[inp],#8
	ldp	w10,w11,[inp],#8
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	EncRound
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	stp	w11,w10,[outp]
	stp	w9,w8,[outp,#8]
	b	100f
1:	// process last 2 blocks
	ld4	{v4.s,v5.s,v6.s,v7.s}[0],[inp],#16
	ld4	{v4.s,v5.s,v6.s,v7.s}[1],[inp],#16
	cmp	blocks,#2
	b.gt	1f
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	st4	{v0.s,v1.s,v2.s,v3.s}[0],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[1],[outp]
	b	100f // 
1:	//	process last 3 blocks
	ld4	{v4.s,v5.s,v6.s,v7.s}[2],[inp],#16
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	st4	{v0.s,v1.s,v2.s,v3.s}[0],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[1],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[2],[outp]
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	x29,x30,[sp,#64]
	ldp	x19,x20,[sp,#80]
	ldp	x21,x22,[sp,#96]
	ldp	d8,d9,[sp],#112
AARCH64_AUTIASP
	ret
.size	Vpsm4EcbEncrypt,.-Vpsm4EcbEncrypt


.globl	Vpsm4CbcEncrypt
.type	Vpsm4CbcEncrypt,%function
.align	5
Vpsm4CbcEncrypt:
AARCH64_PACIASP
	lsr	len,len,4
	stp	x29,x30,[sp,#-48]!
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]

	// load tbox
	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4

	cbz	w5,.Ldec

	// load iv
	ldp	w8,w9,[ivp]
	ldp	w10,w11,[ivp,#8]
.Lcbc_1_block_enc:
	subs	blocks,blocks,#1
	b.lt	2f
	ldp	w6,w7,[inp],#8
	ldp	w16,w17,[inp],#8
	eor	w8,w8,w6
	eor	w9,w9,w7
	eor	w10,w10,w16
	eor	w11,w11,w17
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	EncRound
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	// reverse to store
	mov	w6,w8
	mov	w8,w11
	mov	w11,w6
	mov	w7,w9
	mov	w9,w10
	mov	w10,w7

	stp	w8,w9,[outp],#8
	stp	w10,w11,[outp],#8
	b	.Lcbc_1_block_enc
2:
	// save back IV
	stp	w8,w9,[ivp]
	stp	w10,w11,[ivp,#8]

	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x29,x30,[sp],#48
AARCH64_AUTIASP
	ret

.Ldec:
	LoadSbox
	// decryption mode starts
	stp	d8,d9,[sp,#-64]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]

.Lcbc_12_blocks_dec:
	cmp	w2,#12
	b.lt	.Lcbc_8_blocks_dec
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[x0]
	add	x10,x0,#64
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[x10]
	add	x10,x10,#64
	ld4	{v16.4s,v17.4s,v18.4s,v19.4s},[x10]

#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
	rev32	v16.16b,v16.16b
	rev32	v17.16b,v17.16b
	rev32	v18.16b,v18.16b
	rev32	v19.16b,v19.16b
#endif
	bl	Sm4Enc12blks
	// transpose to xor iv
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d
	transpose v4.4s,v5.4s,v6.4s,v7.4s,v4.2d,v5.2d,v6.2d,v7.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d
	transpose v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d
	ld1	{ivec1.4s},[ivp]
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[inp],#64
	eor	v0.16b,v0.16b,ivec1.16b
	ld1 {v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v1.16b,v1.16b,v16.16b
	eor	v2.16b,v2.16b,v17.16b
	eor	v3.16b,v3.16b,v18.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64

	eor v4.16b,v4.16b,v19.16b
	eor v5.16b,v5.16b,v12.16b
	eor v6.16b,v6.16b,v13.16b
	eor v7.16b,v7.16b,v14.16b
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[inp],#64
	eor v8.16b,v8.16b,v15.16b
	eor v9.16b,v9.16b,v16.16b
	eor v10.16b,v10.16b,v17.16b
	eor v11.16b,v11.16b,v18.16b
	st1	{v8.4s,v9.4s,v10.4s,v11.4s},[outp],#64
	// save back iv
	st1	{v19.4s}, [ivp]

	subs    blocks,blocks,#12
	b.gt	.Lcbc_12_blocks_dec
	b	100f

.Lcbc_8_blocks_dec:
	cmp	blocks,#8
	b.lt	1f
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp]
	add	ptr, inp, #64
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[ptr]

#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
#endif
	bl	Sm4Enc8blks
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	transpose v4.4s,v5.4s,v6.4s,v7.4s,v4.2d,v5.2d,v6.2d,v7.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	ld1	{ivec1.4s},[ivp]
	ld1	{v8.4s,v9.4s,v10.4s,v11.4s},[inp],#64
	// note ivec1 and v15 are resuing the same register
	// care needs to be taken to avoid conflict
	eor	v0.16b,v0.16b,ivec1.16b
	ld1	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v1.16b,v1.16b,v8.16b
	eor	v2.16b,v2.16b,v9.16b
	eor	v3.16b,v3.16b,v10.16b
	// save back IV
	st1	{v15.4s}, [ivp]
	eor	v4.16b,v4.16b,v11.16b
	eor	v5.16b,v5.16b,v12.16b
	eor	v6.16b,v6.16b,v13.16b
	eor	v7.16b,v7.16b,v14.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64
	subs	blocks,blocks,#8
	b.gt	.Lcbc_8_blocks_dec
	b.eq	100f
1:
	ld1	{ivec1.4s},[ivp]
.Lcbc_4_blocks_dec:
	cmp	blocks,#4
	b.lt	1f
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[inp],#64
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,ivec1.16b
	eor	v1.16b,v1.16b,v4.16b
	orr	v15.16b,v7.16b,v7.16b
	eor	v2.16b,v2.16b,v5.16b
	eor	v3.16b,v3.16b,v6.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	// save back IV
	st1	{v7.4s}, [ivp]
	subs	blocks,blocks,#4
	b.gt	.Lcbc_4_blocks_dec
	b	100f
1:	// last block
	subs	blocks,blocks,#1
	b.lt	100f
	b.gt	1f
	// load iv
	ldp	w6,w7,[ivp]
	ldp	w16,w17,[ivp,#8]

	ldp	w8,w9,[inp]
	ldp	w10,w11,[inp,#8]
	// store back iv
	stp	w8,w9,[ivp]
	stp	w10,w11,[ivp,#8]
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	EncRound
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	eor	w11,w11,w6
	eor	w10,w10,w7
	eor	w9,w9,w16
	eor	w8,w8,w17
	stp	w11,w10,[outp],#8
	stp	w9,w8,[outp],#8
	b	100f
1:	// last two blocks
	ld4	{v4.s,v5.s,v6.s,v7.s}[0], [inp]
	add	ptr,inp,#16
	ld4	{v4.s,v5.s,v6.s,v7.s}[1],[ptr],#16
	subs	blocks,blocks,1
	b.gt	1f
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s},[inp],#32
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,ivec1.16b
	eor	v1.16b,v1.16b,v4.16b
	st1	{v0.4s,v1.4s},[outp],#32
	// save back IV
	st1	{v5.4s}, [ivp]
	b	100f
1:	//	last 3 blocks
	ld4	{v4.s,v5.s,v6.s,v7.s}[2],[ptr]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s,v6.4s},[inp],#48
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,ivec1.16b
	eor	v1.16b,v1.16b,v4.16b
	eor	v2.16b,v2.16b,v5.16b
	st1	{v0.4s,v1.4s,v2.4s},[outp],#48
	// save back IV
	st1	{v6.4s}, [ivp]
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	d8,d9,[sp],#64
	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x29,x30,[sp],#48
AARCH64_AUTIASP
	ret
.size	Vpsm4CbcEncrypt,.-Vpsm4CbcEncrypt


# void Vpsm4Ctr32EncryptBlocks(const uint8_t *in, uint8_t *out, uint64_t blocks, const uint32_t *key, uint8_t *iv);
.globl	Vpsm4Ctr32EncryptBlocks
.type	Vpsm4Ctr32EncryptBlocks,%function
.align	5
Vpsm4Ctr32EncryptBlocks:
AARCH64_PACIASP
	ld1	{ivec.4s},[ivp]
#ifndef HITLS_BIG_ENDIAN
	rev32	v3.16b,v3.16b
#endif
	LoadSbox
	cmp	blocks,#1
	b.ne	1f
	// fast processing for one single block without
	// context saving overhead
	stp	x19,x20,[sp,#-32]!
	stp	x21,x22,[sp,#16]
	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4

	Encrypt1blkNorevCtr

	ld1	{v4.4s},[inp]
	eor	v4.16b,v4.16b,ivec.16b
	st1	{v4.4s},[outp]
	ldp	x21,x22,[sp,#16]
	ldp	x19,x20,[sp],#32
	ldr ctr,[ivp,#12]
#ifndef HITLS_BIG_ENDIAN
	rev ctr,ctr
#endif
	add ctr,ctr,#1
#ifndef HITLS_BIG_ENDIAN
	rev ctr,ctr
#endif
	str ctr,[ivp,#12]
AARCH64_AUTIASP
	ret
1:
	stp	d8,d9,[sp,#-112]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]
	stp	x29,x30,[sp,#64]
	stp	x19,x20,[sp,#80]
	stp	x21,x22,[sp,#96]
	mov	word0, ivec.s[0]
	mov	word1, ivec.s[1]
	mov	word2, ivec.s[2]
	mov	ctr, ivec.s[3]
.Lctr32_4_blocks_process:
	cmp	blocks,#4
	b.lt	1f
	dup	v4.4s,word0
	dup	v5.4s,word1
	dup	v6.4s,word2
	mov	v7.s[0],w5
	add	ctr,ctr,#1
	mov	v7.s[1],ctr
	add	ctr,ctr,#1
	mov	v7.s[2],ctr
	add	ctr,ctr,#1
	mov	v7.s[3],ctr
	add	ctr,ctr,#1
	cmp	blocks,#8
	b.ge	.Lctr32_8_blocks_process
	bl	Sm4Enc4blks
	ld4	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v0.16b,v0.16b,v12.16b
	eor	v1.16b,v1.16b,v13.16b
	eor	v2.16b,v2.16b,v14.16b
	eor	v3.16b,v3.16b,v15.16b
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	subs	blocks,blocks,#4
	b.ne	.Lctr32_4_blocks_process
	b	100f
.Lctr32_8_blocks_process:
	dup	v8.4s,word0
	dup	v9.4s,word1
	dup	v10.4s,word2
	mov	v11.s[0],ctr
	add	ctr,ctr,#1
	mov	v11.s[1],ctr
	add	ctr,ctr,#1
	mov	v11.s[2],ctr
	add	ctr,ctr,#1
	mov	v11.s[3],ctr
	add	ctr,ctr,#1
	cmp	blocks,#12
	b.ge	.Lctr32_12_blocks_process
	bl	Sm4Enc8blks
	ld4	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[inp],#64
	eor	v0.16b,v0.16b,v12.16b
	eor	v1.16b,v1.16b,v13.16b
	eor	v2.16b,v2.16b,v14.16b
	eor	v3.16b,v3.16b,v15.16b
	eor	v4.16b,v4.16b,v8.16b
	eor	v5.16b,v5.16b,v9.16b
	eor	v6.16b,v6.16b,v10.16b
	eor	v7.16b,v7.16b,v11.16b
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	st4	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64
	subs	blocks,blocks,#8
	b.ne	.Lctr32_4_blocks_process
	b	100f
.Lctr32_12_blocks_process:
	dup	v16.4s,word0
	dup	v17.4s,word1
	dup	v18.4s,word2
	mov	v19.s[0],ctr
	add	ctr,ctr,#1
	mov	v19.s[1],ctr
	add	ctr,ctr,#1
	mov	v19.s[2],ctr
	add	ctr,ctr,#1
	mov	v19.s[3],ctr
	add	ctr,ctr,#1
	bl	Sm4Enc12blks
	ld4	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v0.16b,v0.16b,v12.16b
	eor	v1.16b,v1.16b,v13.16b
	eor	v2.16b,v2.16b,v14.16b
	eor	v3.16b,v3.16b,v15.16b
	st4	{v0.4s,v1.4s,v2.4s,v3.4s},[outp],#64
	ld4	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v4.16b,v4.16b,v12.16b
	eor	v5.16b,v5.16b,v13.16b
	eor	v6.16b,v6.16b,v14.16b
	eor	v7.16b,v7.16b,v15.16b
	st4	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64
	ld4	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v8.16b,v8.16b,v12.16b
	eor	v9.16b,v9.16b,v13.16b
	eor	v10.16b,v10.16b,v14.16b
	eor	v11.16b,v11.16b,v15.16b
	st4	{v8.4s,v9.4s,v10.4s,v11.4s},[outp],#64
	subs	blocks,blocks,#12
	b.ne	.Lctr32_4_blocks_process
	b	100f

1:	//	last block processing
	subs	blocks,blocks,#1
	b.lt	100f
	b.gt	1f
	mov	ivec.s[0],word0
	mov	ivec.s[1],word1
	mov	ivec.s[2],word2
	mov	ivec.s[3],ctr
	add	ctr,ctr,#1

	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4

	Encrypt1blkNorevCtr

	ld1	{v4.4s},[inp]
	eor	v4.16b,v4.16b,ivec.16b
	st1	{v4.4s},[outp]
	b	100f

1:	// last 2 blocks processing

	dup	v4.4s,word0
	dup	v5.4s,word1
	dup	v6.4s,word2
	mov	v7.s[0],ctr
	add	ctr,ctr,#1
	mov	v7.s[1],ctr
	subs	blocks,blocks,#1
	b.ne	1f
	add	ctr,ctr,#1
	bl	Sm4Enc4blks
	ld4	{v12.s,v13.s,v14.s,v15.s}[0],[inp],#16
	ld4	{v12.s,v13.s,v14.s,v15.s}[1],[inp],#16
	eor	v0.16b,v0.16b,v12.16b
	eor	v1.16b,v1.16b,v13.16b
	eor	v2.16b,v2.16b,v14.16b
	eor	v3.16b,v3.16b,v15.16b
	st4	{v0.s,v1.s,v2.s,v3.s}[0],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[1],[outp],#16
	b	100f

1:	//	last 3 blocks processing
	add	ctr,ctr,#1
	mov	v7.s[2],ctr
	add	ctr,ctr,#1
	bl	Sm4Enc4blks
	ld4	{v12.s,v13.s,v14.s,v15.s}[0],[inp],#16
	ld4	{v12.s,v13.s,v14.s,v15.s}[1],[inp],#16
	ld4	{v12.s,v13.s,v14.s,v15.s}[2],[inp],#16
	eor	v0.16b,v0.16b,v12.16b
	eor	v1.16b,v1.16b,v13.16b
	eor	v2.16b,v2.16b,v14.16b
	eor	v3.16b,v3.16b,v15.16b
	st4	{v0.s,v1.s,v2.s,v3.s}[0],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[1],[outp],#16
	st4	{v0.s,v1.s,v2.s,v3.s}[2],[outp],#16
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	x29,x30,[sp,#64]
	ldp	x19,x20,[sp,#80]
	ldp	x21,x22,[sp,#96]
	ldp	d8,d9,[sp],#112
#ifndef HITLS_BIG_ENDIAN
	rev ctr, ctr
#endif
	str ctr, [ivp,#12]
AARCH64_AUTIASP
	ret
.size	Vpsm4Ctr32EncryptBlocks,.-Vpsm4Ctr32EncryptBlocks

.globl	Vpsm4XtsCipher
.type	Vpsm4XtsCipher,%function
.align	5
Vpsm4XtsCipher:
AARCH64_PACIASP
	stp	x19, x20, [sp, #-0x10]!
	stp	x21, x22, [sp, #-0x10]!
	stp	x23, x24, [sp, #-0x10]!
	stp	x25, x26, [sp, #-0x10]!
	stp	x27, x28, [sp, #-0x10]!
	stp	x29, x30, [sp, #-0x10]!
	stp	d8, d9, [sp, #-0x10]!
	stp	d10, d11, [sp, #-0x10]!
	stp	d12, d13, [sp, #-0x10]!
	stp	d14, d15, [sp, #-0x10]!
	sub	sp, sp, #192
	mov	x24, sp
	mov	x26,x3
	mov	x27,x4
	mov	w28,w6
	ld1	{v16.4s}, [x5]
	LoadSbox

	and	x29,x2,#0x0F
	// convert length into blocks
	lsr	x2,x2,4
	cmp	x2,#1
	b.lt	.Lxts_cipher_return

	cmp	x29,0
	// If the encryption/decryption Length is N times of 16,
	// the all blocks are encrypted/decrypted in .xts_encrypt_blocks
	b.eq	.xts_encrypt_blocks

	// If the encryption/decryption length is not N times of 16,
	// the last two blocks are encrypted/decrypted in .last_2blks_tweak or .only_2blks_tweak
	// the other blocks are encrypted/decrypted in .xts_encrypt_blocks
	subs	x2,x2,#1
	b.eq	.only_2blks_tweak
.xts_encrypt_blocks:
	rbit	v16.16b,v16.16b
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	x12,v16.d[0]
	mov	x13,v16.d[1]
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
.Lxts_12_blocks_process:
	mov	x24, sp
	cmp	x2,#12
	b.lt	.Lxts_8_blocks_process
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and	w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
	eor	v7.16b, v7.16b, v19.16b
	ld1	{v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and	w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v17.16b
	eor	v10.16b, v10.16b, v18.16b
	eor	v11.16b, v11.16b, v19.16b
	ld1	{v0.4s,v1.4s,v2.4s,v3.4s},[x0],#64
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and	w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	eor	v2.16b, v2.16b, v18.16b
	eor	v3.16b, v3.16b, v19.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	mov	v16.16b,v0.16b
	mov	v17.16b,v1.16b
	mov	v18.16b,v2.16b
	mov	v19.16b,v3.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
	rev32	v16.16b,v16.16b
	rev32	v17.16b,v17.16b
	rev32	v18.16b,v18.16b
	rev32	v19.16b,v19.16b
#endif
	zip1	v0.4s,v4.4s,v5.4s
	zip2	v1.4s,v4.4s,v5.4s
	zip1	v2.4s,v6.4s,v7.4s
	zip2	v3.4s,v6.4s,v7.4s
	zip1	v4.2d,v0.2d,v2.2d
	zip2	v5.2d,v0.2d,v2.2d
	zip1	v6.2d,v1.2d,v3.2d
	zip2	v7.2d,v1.2d,v3.2d
	zip1	v0.4s,v8.4s,v9.4s
	zip2	v1.4s,v8.4s,v9.4s
	zip1	v2.4s,v10.4s,v11.4s
	zip2	v3.4s,v10.4s,v11.4s
	zip1	v8.2d,v0.2d,v2.2d
	zip2	v9.2d,v0.2d,v2.2d
	zip1	v10.2d,v1.2d,v3.2d
	zip2	v11.2d,v1.2d,v3.2d
	zip1	v0.4s,v16.4s,v17.4s
	zip2	v1.4s,v16.4s,v17.4s
	zip1	v2.4s,v18.4s,v19.4s
	zip2	v3.4s,v18.4s,v19.4s
	zip1	v16.2d,v0.2d,v2.2d
	zip2	v17.2d,v0.2d,v2.2d
	zip1	v18.2d,v1.2d,v3.2d
	zip2	v19.2d,v1.2d,v3.2d
	bl	Sm4Enc12blks
	zip1	v16.4s,v0.4s,v1.4s
	zip2	v17.4s,v0.4s,v1.4s
	zip1	v18.4s,v2.4s,v3.4s
	zip2	v19.4s,v2.4s,v3.4s
	zip1	v0.2d,v16.2d,v18.2d
	zip2	v1.2d,v16.2d,v18.2d
	zip1	v2.2d,v17.2d,v19.2d
	zip2	v3.2d,v17.2d,v19.2d
	zip1	v16.4s,v4.4s,v5.4s
	zip2	v17.4s,v4.4s,v5.4s
	zip1	v18.4s,v6.4s,v7.4s
	zip2	v19.4s,v6.4s,v7.4s
	zip1	v4.2d,v16.2d,v18.2d
	zip2	v5.2d,v16.2d,v18.2d
	zip1	v6.2d,v17.2d,v19.2d
	zip2	v7.2d,v17.2d,v19.2d
	zip1	v16.4s,v8.4s,v9.4s
	zip2	v17.4s,v8.4s,v9.4s
	zip1	v18.4s,v10.4s,v11.4s
	zip2	v19.4s,v10.4s,v11.4s
	zip1	v8.2d,v16.2d,v18.2d
	zip2	v9.2d,v16.2d,v18.2d
	zip1	v10.2d,v17.2d,v19.2d
	zip2	v11.2d,v17.2d,v19.2d
	mov	x24, sp
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	eor	v2.16b, v2.16b, v18.16b
	eor	v3.16b, v3.16b, v19.16b

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
	eor	v7.16b, v7.16b, v19.16b

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v17.16b
	eor	v10.16b, v10.16b, v18.16b
	eor	v11.16b, v11.16b, v19.16b

	// save the last tweak
	mov	v24.16b,v19.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
	st1	{v8.4s,v9.4s,v10.4s,v11.4s},[x1],#64
	subs	x2,x2,#12
	b.gt	.Lxts_12_blocks_process
	b	100f
.Lxts_8_blocks_process:
	mov	x24, sp
	cmp	x2,#8
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and		w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
	b.lt	.Lxts_4_blocks_process
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
	eor	v7.16b, v7.16b, v19.16b
	ld1	{v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24], #64
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and	w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v8.16b, v8.16b, v16.16b
	eor	v9.16b, v9.16b, v17.16b
	eor	v10.16b, v10.16b, v18.16b
	eor	v11.16b, v11.16b, v19.16b
	st1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
#endif
	zip1	v0.4s,v4.4s,v5.4s
	zip2	v1.4s,v4.4s,v5.4s
	zip1	v2.4s,v6.4s,v7.4s
	zip2	v3.4s,v6.4s,v7.4s
	zip1	v4.2d,v0.2d,v2.2d
	zip2	v5.2d,v0.2d,v2.2d
	zip1	v6.2d,v1.2d,v3.2d
	zip2	v7.2d,v1.2d,v3.2d
	zip1	v0.4s,v8.4s,v9.4s
	zip2	v1.4s,v8.4s,v9.4s
	zip1	v2.4s,v10.4s,v11.4s
	zip2	v3.4s,v10.4s,v11.4s
	zip1	v8.2d,v0.2d,v2.2d
	zip2	v9.2d,v0.2d,v2.2d
	zip1	v10.2d,v1.2d,v3.2d
	zip2	v11.2d,v1.2d,v3.2d
	bl	Sm4Enc8blks
	zip1	v8.4s,v0.4s,v1.4s
	zip2	v9.4s,v0.4s,v1.4s
	zip1	v10.4s,v2.4s,v3.4s
	zip2	v11.4s,v2.4s,v3.4s
	zip1	v0.2d,v8.2d,v10.2d
	zip2	v1.2d,v8.2d,v10.2d
	zip1	v2.2d,v9.2d,v11.2d
	zip2	v3.2d,v9.2d,v11.2d
	zip1	v8.4s,v4.4s,v5.4s
	zip2	v9.4s,v4.4s,v5.4s
	zip1	v10.4s,v6.4s,v7.4s
	zip2	v11.4s,v6.4s,v7.4s
	zip1	v4.2d,v8.2d,v10.2d
	zip2	v5.2d,v8.2d,v10.2d
	zip1	v6.2d,v9.2d,v11.2d
	zip2	v7.2d,v9.2d,v11.2d
	mov	x24, sp
	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	eor	v2.16b, v2.16b, v18.16b
	eor	v3.16b, v3.16b, v19.16b

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[x24],#64
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
	eor	v7.16b, v7.16b, v19.16b

	// save the last tweak
	mov	v24.16b,v19.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
	subs	x2,x2,#8
	b.gt	.Lxts_8_blocks_process
	b	100f
.Lxts_4_blocks_process:
	cmp	x2,#4
	b.lt	1f
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	rbit	v19.16b,v19.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
	eor	v7.16b, v7.16b, v19.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	zip1	v0.4s,v4.4s,v5.4s
	zip2	v1.4s,v4.4s,v5.4s
	zip1	v2.4s,v6.4s,v7.4s
	zip2	v3.4s,v6.4s,v7.4s
	zip1	v4.2d,v0.2d,v2.2d
	zip2	v5.2d,v0.2d,v2.2d
	zip1	v6.2d,v1.2d,v3.2d
	zip2	v7.2d,v1.2d,v3.2d
	bl	Sm4Enc4blks
	zip1	v4.4s,v0.4s,v1.4s
	zip2	v5.4s,v0.4s,v1.4s
	zip1	v6.4s,v2.4s,v3.4s
	zip2	v7.4s,v2.4s,v3.4s
	zip1	v0.2d,v4.2d,v6.2d
	zip2	v1.2d,v4.2d,v6.2d
	zip1	v2.2d,v5.2d,v7.2d
	zip2	v3.2d,v5.2d,v7.2d
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	eor	v2.16b, v2.16b, v18.16b
	eor	v3.16b, v3.16b, v19.16b
	st1	{v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
	sub	x2,x2,#4
	// save the last tweak
	mov	v24.16b,v19.16b
	mov	v16.d[0],x12
	mov	v16.d[1],x13
#ifdef HITLS_BIG_ENDIAN
	rev32	v16.16b,v16.16b
#endif
	mov	w7,0x87
	extr	x9,x19,x19,#32
	extr	x13,x19,x18,#63
	and	w8,w7,w9,asr#31
	eor	x12,x8,x18,lsl#1
	mov	v17.d[0],x14
	mov	v17.d[1],x15
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	mov	w7,0x87
	extr	x9,x13,x13,#32
	extr	x15,x13,x12,#63
	and	w8,w7,w9,asr#31
	eor	x14,x8,x12,lsl#1
	mov	v18.d[0],x16
	mov	v18.d[1],x17
#ifdef HITLS_BIG_ENDIAN
	rev32	v18.16b,v18.16b
#endif
	mov	w7,0x87
	extr	x9,x15,x15,#32
	extr	x17,x15,x14,#63
	and	w8,w7,w9,asr#31
	eor	x16,x8,x14,lsl#1
	mov	v19.d[0],x18
	mov	v19.d[1],x19
#ifdef HITLS_BIG_ENDIAN
	rev32	v19.16b,v19.16b
#endif
	mov	w7,0x87
	extr	x9,x17,x17,#32
	extr	x19,x17,x16,#63
	and	w8,w7,w9,asr#31
	eor	x18,x8,x16,lsl#1
1:
	// process last block
	cmp	x2,#1
	b.lt	100f
	b.gt	1f
	ld1	{v4.4s},[x0],#16
	rbit	v16.16b,v16.16b
	eor	v4.16b, v4.16b, v16.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	mov	x10,x3
	mov	w11,#8
	mov	w12,v4.s[0]
	mov	w13,v4.s[1]
	mov	w14,v4.s[2]
	mov	w15,v4.s[3]
10:
	ldp	w7,w8,[x10],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	w6,w14,w15
	eor	w9,w7,w13
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w12,w12,w6
	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	w6,w14,w15
	eor	w9,w12,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	ldp	w7,w8,[x10],8
	eor	w13,w13,w6
	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	w6,w12,w13
	eor	w9,w7,w15
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w14,w14,w6
	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	w6,w12,w13
	eor	w9,w14,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w15,w15,w6
	subs	w11,w11,#1
	b.ne	10b
	mov	v4.s[0],w15
	mov	v4.s[1],w14
	mov	v4.s[2],w13
	mov	v4.s[3],w12
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	eor	v4.16b, v4.16b, v16.16b
	st1	{v4.4s},[x1],#16
	// save the last tweak
	mov	v24.16b,v16.16b
	b	100f
1:	//	process last 2 blocks
	cmp	x2,#2
	b.gt	1f
	ld1	{v4.4s,v5.4s},[x0],#32
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
#endif
	zip1	v0.4s,v4.4s,v5.4s
	zip2	v1.4s,v4.4s,v5.4s
	zip1	v2.4s,v6.4s,v7.4s
	zip2	v3.4s,v6.4s,v7.4s
	zip1	v4.2d,v0.2d,v2.2d
	zip2	v5.2d,v0.2d,v2.2d
	zip1	v6.2d,v1.2d,v3.2d
	zip2	v7.2d,v1.2d,v3.2d
	bl	Sm4Enc4blks
	zip1	v4.4s,v0.4s,v1.4s
	zip2	v5.4s,v0.4s,v1.4s
	zip1	v6.4s,v2.4s,v3.4s
	zip2	v7.4s,v2.4s,v3.4s
	zip1	v0.2d,v4.2d,v6.2d
	zip2	v1.2d,v4.2d,v6.2d
	zip1	v2.2d,v5.2d,v7.2d
	zip2	v3.2d,v5.2d,v7.2d
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	st1	{v0.4s,v1.4s},[x1],#32
	// save the last tweak
	mov	v24.16b,v17.16b
	b	100f
1:	//	process last 3 blocks
	ld1	{v4.4s,v5.4s,v6.4s},[x0],#48
	rbit	v16.16b,v16.16b
	rbit	v17.16b,v17.16b
	rbit	v18.16b,v18.16b
	eor	v4.16b, v4.16b, v16.16b
	eor	v5.16b, v5.16b, v17.16b
	eor	v6.16b, v6.16b, v18.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
#endif
	zip1	v0.4s,v4.4s,v5.4s
	zip2	v1.4s,v4.4s,v5.4s
	zip1	v2.4s,v6.4s,v7.4s
	zip2	v3.4s,v6.4s,v7.4s
	zip1	v4.2d,v0.2d,v2.2d
	zip2	v5.2d,v0.2d,v2.2d
	zip1	v6.2d,v1.2d,v3.2d
	zip2	v7.2d,v1.2d,v3.2d
	bl	Sm4Enc4blks
	zip1	v4.4s,v0.4s,v1.4s
	zip2	v5.4s,v0.4s,v1.4s
	zip1	v6.4s,v2.4s,v3.4s
	zip2	v7.4s,v2.4s,v3.4s
	zip1	v0.2d,v4.2d,v6.2d
	zip2	v1.2d,v4.2d,v6.2d
	zip1	v2.2d,v5.2d,v7.2d
	zip2	v3.2d,v5.2d,v7.2d
	eor	v0.16b, v0.16b, v16.16b
	eor	v1.16b, v1.16b, v17.16b
	eor	v2.16b, v2.16b, v18.16b
	st1	{v0.4s,v1.4s,v2.4s},[x1],#48
	// save the last tweak
	mov	v24.16b,v18.16b
100:
	cmp	x29,0
	b.eq	.Lxts_cipher_return

// This branch calculates the last two tweaks, 
// while the encryption/decryption length is larger than 32
.last_2blks_tweak:
#ifdef HITLS_BIG_ENDIAN
	rev32	v24.16b,v24.16b
#endif
	rbit	v2.16b,v24.16b
	adrp    x26, .Lxts_magic
    add	    x26, x26, :lo12:.Lxts_magic
	ldr	    q0, [x26]
	shl	v17.16b, v2.16b, #1
	ext	v1.16b, v2.16b, v2.16b,#15
	ushr	v1.16b, v1.16b, #7
	mul	v1.16b, v1.16b, v0.16b
	eor	v17.16b, v17.16b, v1.16b
	rbit	v17.16b,v17.16b
	rbit	v2.16b,v17.16b
	adrp    x26, .Lxts_magic
    add	    x26, x26, :lo12:.Lxts_magic
	ldr	    q0, [x26]
	shl	v18.16b, v2.16b, #1
	ext	v1.16b, v2.16b, v2.16b,#15
	ushr	v1.16b, v1.16b, #7
	mul	v1.16b, v1.16b, v0.16b
	eor	v18.16b, v18.16b, v1.16b
	rbit	v18.16b,v18.16b
	b	.Lxts_check_dec


// This branch calculates the last two tweaks, 
// while the encryption/decryption length is equal to 32, who only need two tweaks
.only_2blks_tweak:
	mov	v17.16b,v16.16b
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
#endif
	rbit	v2.16b,v17.16b
	adrp    x26, .Lxts_magic
    add	    x26, x26, :lo12:.Lxts_magic
	ldr	q0, [x26]
	shl	v18.16b, v2.16b, #1
	ext	v1.16b, v2.16b, v2.16b,#15
	ushr	v1.16b, v1.16b, #7
	mul	v1.16b, v1.16b, v0.16b
	eor	v18.16b, v18.16b, v1.16b
	rbit	v18.16b,v18.16b
	b	.Lxts_check_dec


// Determine whether encryption or decryption is required.
// The last two tweaks need to be swapped for decryption.
.Lxts_check_dec:
	// encryption:1 decryption:0
	cmp	w28,1
	b.eq	.Lxts_prcess_last_2blks
	mov	v0.16B,v17.16b
	mov	v17.16B,v18.16b
	mov	v18.16B,v0.16b

.Lxts_prcess_last_2blks:
#ifdef HITLS_BIG_ENDIAN
	rev32	v17.16b,v17.16b
	rev32	v18.16b,v18.16b
#endif
	ld1	{v4.4s},[x0],#16
	eor	v4.16b, v4.16b, v17.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	mov	x10,x3
	mov	w11,#8
	mov	w12,v4.s[0]
	mov	w13,v4.s[1]
	mov	w14,v4.s[2]
	mov	w15,v4.s[3]
10:
	ldp	w7,w8,[x10],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	w6,w14,w15
	eor	w9,w7,w13
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w12,w12,w6
	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	w6,w14,w15
	eor	w9,w12,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	ldp	w7,w8,[x10],8
	eor	w13,w13,w6
	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	w6,w12,w13
	eor	w9,w7,w15
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w14,w14,w6
	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	w6,w12,w13
	eor	w9,w14,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w15,w15,w6
	subs	w11,w11,#1
	b.ne	10b
	mov	v4.s[0],w15
	mov	v4.s[1],w14
	mov	v4.s[2],w13
	mov	v4.s[3],w12
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	eor	v4.16b, v4.16b, v17.16b
	st1	{v4.4s},[x1],#16

	sub	x26,x1,16
.Lxts_loop:
	subs	x29,x29,1
	ldrb	w7,[x26,x29]
	ldrb	w8,[x0,x29]
	strb	w8,[x26,x29]
	strb	w7,[x1,x29]
	b.gt	.Lxts_loop
	ld1	{v4.4s}, [x26]
	eor	v4.16b, v4.16b, v18.16b
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	mov	x10,x3
	mov	w11,#8
	mov	w12,v4.s[0]
	mov	w13,v4.s[1]
	mov	w14,v4.s[2]
	mov	w15,v4.s[3]
10:
	ldp	w7,w8,[x10],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	w6,w14,w15
	eor	w9,w7,w13
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w12,w12,w6
	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	w6,w14,w15
	eor	w9,w12,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	ldp	w7,w8,[x10],8
	eor	w13,w13,w6
	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	w6,w12,w13
	eor	w9,w7,w15
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w14,w14,w6
	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	w6,w12,w13
	eor	w9,w14,w8
	eor	w6,w6,w9
	movi	v31.16b, #0x0f
	mov	v3.s[0],w6
	// optimize sbox using AESE instruction
	tbl	v0.16b, {v3.16b}, v26.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v28.16b}, v0.16b
	tbl	v2.16b, {v27.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v1.16b
	aese	v0.16b,v1.16b
	ushr	v2.16b, v0.16b, 4
	and	v0.16b, v0.16b, v31.16b
	tbl	v0.16b, {v30.16b}, v0.16b
	tbl	v2.16b, {v29.16b}, v2.16b
	eor	v0.16b, v0.16b, v2.16b

	mov	w7,v0.s[0]
	eor	w6,w7,w7,ror #32-2
	eor	w6,w6,w7,ror #32-10
	eor	w6,w6,w7,ror #32-18
	eor	w6,w6,w7,ror #32-24
	eor	w15,w15,w6
	subs	w11,w11,#1
	b.ne	10b
	mov	v4.s[0],w15
	mov	v4.s[1],w14
	mov	v4.s[2],w13
	mov	v4.s[3],w12
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
#endif
	eor	v4.16b, v4.16b, v18.16b
	st1	{v4.4s}, [x26]
.Lxts_cipher_return:
	add	sp, sp, #192
	ldp	d14, d15, [sp], #0x10
	ldp	d12, d13, [sp], #0x10
	ldp	d10, d11, [sp], #0x10
	ldp	d8, d9, [sp], #0x10
	ldp	x29, x30, [sp], #0x10
	ldp	x27, x28, [sp], #0x10
	ldp	x25, x26, [sp], #0x10
	ldp	x23, x24, [sp], #0x10
	ldp	x21, x22, [sp], #0x10
	ldp	x19, x20, [sp], #0x10
AARCH64_AUTIASP
	ret
.size	Vpsm4XtsCipher,.-Vpsm4XtsCipher

.globl	Vpsm4Cfb128Encrypt
.type	Vpsm4Cfb128Encrypt,%function
.align	5
Vpsm4Cfb128Encrypt:
AARCH64_PACIASP
	stp	x29,x30,[sp,#-80]!
	add	x29,sp,#0
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x8,[sp,#48]
	stp	x16,x17,[sp,#64]

	// load tbox
	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4

	// load num
	ldr	w23,[x5]
	cbz	w23,.Lcfb128_enc_update
.Lcfb128_enc_init:
	ldrb	w7,[ivp,x23]
	ldrb	w8,[inp]
	eor	w7,w7,w8
	strb	w7,[outp]
	strb	w7,[ivp,x23]

	add	inp,inp,#1
	add	outp,outp,#1
	add	w23,w23,#1
	sub	len,len,#1
	cmp	w23,#16
	b.eq	.Lcfb128_enc_init_final
	cbz	len,.Lcfb128_enc_ret
	b	.Lcfb128_enc_init
.Lcfb128_enc_init_final:
	mov	w23,#0
.Lcfb128_enc_update:
	cbz	len,.Lcfb128_enc_ret
	// load iv
	ldp	w8,w9,[ivp]
	ldp	w10,w11,[ivp,#8]
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	EncRound
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	// save back IV
	stp	w11,w10,[ivp]
	stp	w9,w8,[ivp,#8]

	cmp	len,#16
	b.lt	.Lcfb128_enc_final
	// xor with plain
	ldp	w6,w7,[inp],#8
	ldp	w16,w17,[inp],#8
	eor	w11,w11,w6
	eor	w10,w10,w7
	eor	w9,w9,w16
	eor	w8,w8,w17

	stp	w11,w10,[outp],#8
	stp	w9,w8,[outp],#8
	// save back IV
	stp	w11,w10,[ivp]
	stp	w9,w8,[ivp,#8]

	sub	len,len,#16
	b	.Lcfb128_enc_update
.Lcfb128_enc_final:
	ldrb	w7,[ivp,x23]
	ldrb	w8,[inp]
	eor	w7,w7,w8
	strb	w7,[outp]
	strb	w7,[ivp,x23]
	
	add	inp,inp,#1
	add	outp,outp,#1
	add	w23,w23,#1
	subs	len,len,#1
	b.ne	.Lcfb128_enc_final
.Lcfb128_enc_ret:
	// store num
	str	w23,[x5]

	// restore register
	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x23,x8,[sp,#48]
	ldp	x16,x17,[sp,#64]
	ldp	x29,x30,[sp],#80
AARCH64_AUTIASP
	ret
.size	Vpsm4Cfb128Encrypt,.-Vpsm4Cfb128Encrypt

# void Vpsm4Cfb128Decrypt(const uint8_t *in, uint8_t *out, uint64_t len, const uint32_t *key, uint8_t *iv, int *num);
.globl	Vpsm4Cfb128Decrypt
.type	Vpsm4Cfb128Decrypt,%function
.align	5
Vpsm4Cfb128Decrypt:
AARCH64_PACIASP
	stp	x29,x30,[sp,#-128]!
	stp	x19,x20,[sp,#16]
	stp	x21,x22,[sp,#32]
	stp	x23,x24,[sp,#48]
	stp	d8,d9,[sp,#64]
	stp	d10,d11,[sp,#80]
	stp	d12,d13,[sp,#96]
	stp	d14,d15,[sp,#112]

	// load tbox
	adrp	 x19, .Ltbox1
    add x19,x19,:lo12:.Ltbox1
	adrp	 x20, .Ltbox2
    add x20,x20,:lo12:.Ltbox2
	adrp	 x21, .Ltbox3
    add x21,x21,:lo12:.Ltbox3
	adrp	 x22, .Ltbox4
    add x22,x22,:lo12:.Ltbox4
	LoadSbox
// load num
	ldr	w23,[x5]
	cbz	w23,.Lcfb128_12_blocks_dec

.Lcfb128_dec_init:
	ldrb	w7,[ivp,x23]
	ldrb	w8,[inp]
	eor	w7,w7,w8
	strb	w7,[outp]
	// store in to iv
	strb	w8,[ivp,x23]
	
	add	inp,inp,#1
	add	outp,outp,#1
	subs len,len,#1
	add	w23,w23,#1
	and w23,w23,#15
	b.eq	100f
	cbz	w23,.Lcfb128_12_blocks_dec
	b	.Lcfb128_dec_init

.Lcfb128_12_blocks_dec:
	cmp	len,#192
	b.lt	.Lcfb128_8_blocks_dec

	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp]
	// append iv as last element
	ld4	{v4.s,v5.s,v6.s,v7.s}[3],[ivp]
	add	ptr,inp,#48
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[ptr]
	add	ptr,ptr,#64
	ld4	{v16.4s,v17.4s,v18.4s,v19.4s},[ptr]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b

	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b

	rev32	v16.16b,v16.16b
	rev32	v17.16b,v17.16b
	rev32	v18.16b,v18.16b
	rev32	v19.16b,v19.16b
#endif
	bl	Sm4Enc12blks

	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d
	transpose v4.4s,v5.4s,v6.4s,v7.4s,v4.2d,v5.2d,v6.2d,v7.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d
	transpose v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d,v16.4s,v17.4s,v18.4s,v19.4s,v16.2d,v17.2d,v18.2d,v19.2d

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[inp],#64
	ld1	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v0.16b,v0.16b,v17.16b
	eor	v1.16b,v1.16b,v18.16b
	eor	v2.16b,v2.16b,v19.16b
	eor	v3.16b,v3.16b,v16.16b
	// save plainText decrypted from iv as first one
	st1	{v3.4s},[outp],#16
	st1	{v0.4s,v1.4s,v2.4s},[outp],#48

	eor	v4.16b,v4.16b,v12.16b
	eor	v5.16b,v5.16b,v13.16b
	eor	v6.16b,v6.16b,v14.16b
	eor	v7.16b,v7.16b,v15.16b
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64

	ld1	{v16.4s,v17.4s,v18.4s,v19.4s},[inp],#64
	eor	v8.16b,v8.16b,v16.16b
	eor	v9.16b,v9.16b,v17.16b
	eor	v10.16b,v10.16b,v18.16b
	eor	v11.16b,v11.16b,v19.16b
	st1	{v8.4s,v9.4s,v10.4s,v11.4s},[outp],#64
	// save back IV
	st1	{v19.4s}, [ivp]
	
	subs	len,len,#192
	b.gt	.Lcfb128_12_blocks_dec
	b.eq	100f

.Lcfb128_8_blocks_dec:
	cmp	len,#128
	b.lt	.Lcfb128_4_blocks_dec

	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp]
	// append iv as last element
	ld4	{v4.s,v5.s,v6.s,v7.s}[3],[ivp]
	add	ptr,inp,#48
	ld4	{v8.4s,v9.4s,v10.4s,v11.4s},[ptr]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
	rev32	v8.16b,v8.16b
	rev32	v9.16b,v9.16b
	rev32	v10.16b,v10.16b
	rev32	v11.16b,v11.16b
#endif
	bl	Sm4Enc8blks
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	transpose v4.4s,v5.4s,v6.4s,v7.4s,v4.2d,v5.2d,v6.2d,v7.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d

	ld1	{v8.4s,v9.4s,v10.4s,v11.4s},[inp],#64
	ld1	{v12.4s,v13.4s,v14.4s,v15.4s},[inp],#64
	eor	v0.16b,v0.16b,v9.16b
	eor	v1.16b,v1.16b,v10.16b
	eor	v2.16b,v2.16b,v11.16b
	eor	v3.16b,v3.16b,v8.16b
	// save back IV
	st1	{v15.4s}, [ivp]
	eor	v4.16b,v4.16b,v12.16b
	eor	v5.16b,v5.16b,v13.16b
	eor	v6.16b,v6.16b,v14.16b
	eor	v7.16b,v7.16b,v15.16b
	st1	{v3.4s},[outp],#16
	st1	{v0.4s,v1.4s,v2.4s},[outp],#48
	st1	{v4.4s,v5.4s,v6.4s,v7.4s},[outp],#64
	subs	len,len,#128
	b.gt	.Lcfb128_8_blocks_dec
	b.eq	100f
.Lcfb128_4_blocks_dec:
	cmp	len,#64
	b.lt	.Llast_block
	ld4	{v4.4s,v5.4s,v6.4s,v7.4s},[inp]
	// append iv as last element
	ld4	{v4.s,v5.s,v6.s,v7.s}[3],[ivp]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s,v6.4s,v7.4s},[inp],#64
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,v5.16b
	eor	v1.16b,v1.16b,v6.16b
	eor	v2.16b,v2.16b,v7.16b
	eor	v3.16b,v3.16b,v4.16b
	st1	{v3.4s},[outp],#16
	st1	{v0.4s,v1.4s,v2.4s},[outp],#48
	// save back IV
	st1	{v7.4s}, [ivp]
	subs	len,len,#64
	b.gt	.Lcfb128_4_blocks_dec
	b.eq	100f

.Llast_block:	// last block
	cmp	len,#16
	b.gt	.Llast_2_blocks
1:
	// load in
	ldp	w6,w7,[inp]
	ldp	w16,w17,[inp,#8]
	// load iv
	ldp	w8,w9,[ivp]
	ldp	w10,w11,[ivp,#8]
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	EncRound
#ifndef HITLS_BIG_ENDIAN
	rev	w8,w8
	rev	w9,w9
	rev	w10,w10
	rev	w11,w11
#endif
	// save encrypted iv 
	stp	w11,w10,[ivp]
	stp	w9,w8,[ivp,#8]

	cmp	len,#16
	b.lt	.Lcfb128_dec_final

	stp	w6,w7,[ivp]
	stp	w16,w17,[ivp,#8]
	eor	w11,w11,w6
	eor	w10,w10,w7
	eor	w9,w9,w16
	eor	w8,w8,w17
	stp	w11,w10,[outp],#8
	stp	w9,w8,[outp],#8
	add	inp,inp,#16
	subs	len,len,#16
	b.gt	1b
	b.eq	100f
	b	.Lcfb128_dec_final
.Llast_2_blocks:	//	last two blocks
	ld4	{v4.s,v5.s,v6.s,v7.s}[0],[ivp]
	mov	ptr,inp
	ld4	{v4.s,v5.s,v6.s,v7.s}[1],[ptr],#16

	cmp	x2,#32
	b.gt	.Llast_3_blocks
	b.lt	1b
1:
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s},[inp],#32
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,v4.16b
	eor	v1.16b,v1.16b,v5.16b
	st1	{v0.4s,v1.4s},[outp],#32
	// save back IV
	st1	{v5.4s}, [ivp]
	subs	len,len,#32
	b.eq	100f
	b	.Llast_block
.Llast_3_blocks:	// last 3 blocks
	cmp	len,#48
	b.lt	1b
	ld4	{v4.s,v5.s,v6.s,v7.s}[2],[ptr]
#ifndef HITLS_BIG_ENDIAN
	rev32	v4.16b,v4.16b
	rev32	v5.16b,v5.16b
	rev32	v6.16b,v6.16b
	rev32	v7.16b,v7.16b
#endif
	bl	Sm4Enc4blks
	ld1	{v4.4s,v5.4s,v6.4s},[inp],#48
	transpose v0.4s,v1.4s,v2.4s,v3.4s,v0.2d,v1.2d,v2.2d,v3.2d,v8.4s,v9.4s,v10.4s,v11.4s,v8.2d,v9.2d,v10.2d,v11.2d
	eor	v0.16b,v0.16b,v4.16b
	eor	v1.16b,v1.16b,v5.16b
	eor	v2.16b,v2.16b,v6.16b
	st1	{v0.4s,v1.4s,v2.4s},[outp],#48
	// save back IV
	st1	{v6.4s}, [ivp]
	subs	len,len,#48
	b.eq	100f
	b	.Llast_block
.Lcfb128_dec_final:
	ldrb	w7,[ivp,x23]
	ldrb	w8,[inp]
	eor	w7,w7,w8
	strb	w7,[outp]
	// store in to iv
	strb	w8,[ivp,x23]

	add	inp,inp,#1
	add	outp,outp,#1
	add	w23,w23,#1
	subs	len,len,#1
	b.ne	.Lcfb128_dec_final
100:
	// store num
	str	w23,[x5]
	ldp	x19,x20,[sp,#16]
	ldp	x21,x22,[sp,#32]
	ldp	x23,x24,[sp,#48]
	ldp	d8,d9,[sp,#64]
	ldp	d10,d11,[sp,#80]
	ldp	d12,d13,[sp,#96]
	ldp	d14,d15,[sp,#112]
	ldp	x29,x30,[sp],#128
AARCH64_AUTIASP
	ret
.size	Vpsm4Cfb128Decrypt,.-Vpsm4Cfb128Decrypt

#endif
