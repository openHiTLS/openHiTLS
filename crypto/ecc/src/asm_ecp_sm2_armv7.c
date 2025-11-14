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
#if defined(HITLS_CRYPTO_CURVE_SM2_ARMV7) && defined(HITLS_THIRTY_TWO_BITS)
#include <stdint.h>
#include "securec.h"
#include "crypt_ecc.h"
#include "ecc_local.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_err_internal.h"
#include "asm_ecp_sm2_armv7.h"

/// The type representing a Non-Adjacent Form (NAF) for efficient scalar multiplication
typedef int8_t  Sm2Naf[SM2_BITS + 1];

static const Sm2Fp g_Sm2Zero = {0};

static const Sm2Fp g_Sm2One = {1};

// The following is the table of sm2 base points G: {G, [2^5]G, [2^10]G, [2^15]G, ...[2^255]G}.
//  Only used in the function ECP_Sm2PointGenCore, which uses optimal parameter (window width) w = 5 is used here.
// Thus, the number of points in this table is 256/5 + 1 = 52.
static const Sm2Point sm2_point_gen_table[52] = {
        {{0x334c74c7U, 0x715a4589U, 0xf2660be1U, 0x8fe30bbfU, 0x6a39c994U, 0x5f990446U, 0x1f198119U, 0x32c4ae2cU},
         {0x2139f0a0U, 0x02df32e5U, 0xc62a4740U, 0xd0a9877cU, 0x6b692153U, 0x59bdcee3U, 0xf4f6779cU, 0xbc3736a2U},{1}},
        {{0x6024666cU, 0xa32641e5U, 0x03e5565cU, 0x791734cdU, 0x817f2329U, 0xa6d5c2b5U, 0x0950d180U, 0x25d3debdU},
         {0x03fa10a2U, 0xd39e1003U, 0x20e208b4U, 0x04588951U, 0xdd5cb0e1U, 0xb938c406U, 0x679d61efU, 0x92d99a70U},{1}},
        {{0xa42c160fU, 0xd1952984U, 0x6957f8b1U, 0x76e1e965U, 0x2b712591U, 0x61c022aaU, 0x55c87aebU, 0x33fcaa40U},
         {0x4902c505U, 0xf2f3f62cU, 0x29622184U, 0x2e04362aU, 0x4ce8d974U, 0xf9a8906eU, 0x276d6c81U, 0x67a92a7cU},{1}},
        {{0x2a35430cU, 0xa4ab5e0bU, 0x5e68d45fU, 0xbdec579cU, 0xdaf74d4eU, 0x5ac4bcfdU, 0x525dd890U, 0x60a9a380U},
         {0x591628e4U, 0xb6cc29b6U, 0xac916355U, 0x55d2e0a1U, 0xb6b5974dU, 0x16665a96U, 0xc9ced98eU, 0xd66000faU},{1}},
        {{0x44608d09U, 0x06f4b5b6U, 0xe506ea02U, 0x1df17698U, 0x5197280bU, 0xb8e58155U, 0xd74af9ccU, 0x528d42bdU},
         {0xcb5b0e7eU, 0x05589f0bU, 0xc4732acaU, 0x245926acU, 0x0d751eefU, 0x56d6ab0bU, 0xcf902884U, 0x22dc58c3U},{1}},
        {{0x861543b3U, 0x42ed9aedU, 0x2bcd9feeU, 0xa6dac905U, 0x849882b8U, 0x9bb46dc7U, 0xf3ed580bU, 0x802725f4U},
         {0x690f2eebU, 0xb0315cbaU, 0xfc0f2e5eU, 0x7f4cf904U, 0xd2bf3bb2U, 0xda1e50b7U, 0xfeb4112cU, 0xf334dddfU},{1}},
        {{0xff711a97U, 0xb455b45dU, 0xf4a73224U, 0xc6cdee12U, 0xd6a5743fU, 0xc5ac0179U, 0xae0b27d5U, 0x204643bbU},
         {0x6f15f8adU, 0xcbe67edcU, 0xa9d93e24U, 0xf777a811U, 0x7d4fde9eU, 0xa6b4c286U, 0xad369e5fU, 0x50023795U},{1}},
        {{0x191938c2U, 0x559b2ef1U, 0x44e6619dU, 0x09041200U, 0xd49e8c08U, 0x9b412237U, 0xcb50d796U, 0xa9c7b33eU},
         {0x6d1a2066U, 0xce71beafU, 0x6e3699d4U, 0x05982d23U, 0x5bdd5dfdU, 0x7ef041f6U, 0x7e10e1dfU, 0x92f71df5U},{1}},
        {{0xc83969d3U, 0x5a8f38d7U, 0xf1fe9d22U, 0x802e5f11U, 0xb3706de1U, 0x971e2233U, 0x587e2bd4U, 0x76b6337dU},
         {0x9d9ac34cU, 0xa06d4dabU, 0xbd1f51efU, 0xfdd1886eU, 0x259078f7U, 0x753f34e2U, 0x0cacf396U, 0x8a15315bU},{1}},
        {{0xfd188206U, 0xbe072db0U, 0x1097ce4bU, 0x45af81aeU, 0x0ba0a6ecU, 0x762443e6U, 0x0e49afccU, 0x3b81ee49U},
         {0x2483a147U, 0x77b5743eU, 0x8c4ddc8fU, 0x0e8ad115U, 0x7bd9324dU, 0x842e4525U, 0x4cd7b6b7U, 0x8a092a5dU},{1}},
        {{0x4f570b6aU, 0xc75f6d92U, 0x53508ae9U, 0x6cd1f24dU, 0xecb82a51U, 0x4b970293U, 0x1e149e00U, 0xb5d00869U},
         {0x18181531U, 0x8ee79db9U, 0x48a9dd71U, 0x32736f11U, 0xcc482d2bU, 0x2978c080U, 0x7a504644U, 0xe8802fc4U},{1}},
        {{0xb9220b59U, 0xd53da44bU, 0xe0715921U, 0x59bf6fddU, 0xff3946ecU, 0xf73710e0U, 0x7c52f71bU, 0x6ae04ed3U},
         {0xa1faf0b9U, 0x4a05073fU, 0xa36bf1e1U, 0xc3d9df90U, 0x87107ba1U, 0xee87e936U, 0x85dc4393U, 0xfc4bd847U},{1}},
        {{0x1f95d502U, 0x12fee11cU, 0x68207a11U, 0x51cce12aU, 0x78469bdcU, 0xbfae8244U, 0x507f9715U, 0x08f49b31U},
         {0xe2da7430U, 0x0a2144aeU, 0x029b5aa1U, 0x2f6dbb99U, 0xb1a12fb7U, 0xf0ab1af5U, 0x90fefcb6U, 0x82ef4238U},{1}},
        {{0x35811666U, 0x152879e9U, 0x995f5ac8U, 0xaecd900dU, 0x546a77e4U, 0x55534f24U, 0x2c279791U, 0x86789762U},
         {0x22e2d858U, 0xbd0e28c6U, 0xb00e501dU, 0x1fe1c1caU, 0x51cd9476U, 0x5ebd9095U, 0xbc39a143U, 0x2cd775ebU},{1}},
        {{0x06918211U, 0x12e08a5dU, 0xd9f2cf00U, 0xa02d6febU, 0x6337c216U, 0x3f27b715U, 0x31ac0de1U, 0x29367efcU},
         {0xac540eefU, 0x52fef397U, 0x4b8a16ceU, 0x008dd518U, 0x7a7faff2U, 0x705d57faU, 0xbdba073bU, 0xe0848700U},{1}},
        {{0x45a2813fU, 0x23cddbf8U, 0x5a65211fU, 0xe6d5b06fU, 0x538e06edU, 0x4c73b3fcU, 0xb62a231cU, 0xc3373690U},
         {0xd454550cU, 0x04110e90U, 0x479e4032U, 0xc0cd5bb5U, 0x0ebd2db1U, 0xa5d05b8cU, 0x130cf00fU, 0x956fd51aU},{1}},
        {{0xc11d186fU, 0x92ec9fcbU, 0x6455f395U, 0xa82acf83U, 0xbe00af09U, 0x141a0d74U, 0x1a7255a2U, 0xee6dffb6U},
         {0xc784268cU, 0x6ea0ffd5U, 0xb8f5dd63U, 0x0d75990fU, 0xc5f89aa0U, 0xeba0e4eeU, 0xa1e82ea9U, 0x98d85a17U},{1}},
        {{0x6f19abcaU, 0x48bb2bc3U, 0xbec6147cU, 0xa3d46a50U, 0x10d5d8e3U, 0xcafc1074U, 0x7632efadU, 0x541346c7U},
         {0x5d66948eU, 0x8dc5cfeeU, 0xb76466ddU, 0x41b69047U, 0xb5f9a93eU, 0x7b098a7bU, 0x4bd1c525U, 0xcb365d00U},{1}},
        {{0xeb60f15bU, 0x96613a86U, 0xad689e96U, 0x6de318d4U, 0xfd3acfe9U, 0x89845897U, 0x16a222f3U, 0xf2e7a570U},
         {0xd2968fecU, 0x90a6d777U, 0xbcec00a9U, 0xababa0d2U, 0xcde70f2bU, 0xa6e827f2U, 0xf4bbea8cU, 0x288ff0e0U},{1}},
        {{0xa1ebcee6U, 0x5cd1a736U, 0x532fe3dcU, 0xbba9f2f3U, 0x8f5f9bbdU, 0xb535fd24U, 0xa2aac0a7U, 0xd65b2f39U},
         {0x3da27799U, 0xad5be053U, 0x1e8c75efU, 0xb5c846f4U, 0xda228245U, 0x4fc05fe4U, 0x685a3530U, 0xeab41a97U},{1}},
        {{0x44d11582U, 0x60ac0d90U, 0xd02f01e5U, 0x4e70869eU, 0xea488fc8U, 0xd06cd1baU, 0xc6af19b8U, 0x0f9c80beU},
         {0xd861b588U, 0x1193af79U, 0x3ebe0aebU, 0x6b20b1a0U, 0x5698176cU, 0x58204d8fU, 0x4ea59823U, 0x490239baU},{1}},
        {{0xdc7e14baU, 0x2ea81495U, 0x3030a628U, 0x4e693eceU, 0x6eb1b895U, 0xf0dd7987U, 0x660b60f0U, 0x83758eceU},
         {0x8d59179eU, 0xec1d5545U, 0xe63ff5beU, 0x59365825U, 0xf743eb07U, 0xca9a4796U, 0x1e998f38U, 0xe4abe309U},{1}},
        {{0x9a03b666U, 0x325986c2U, 0xeae151ebU, 0x54706aceU, 0x7613f0deU, 0x6a6e73beU, 0x5fc17c47U, 0xbaa075cdU},
         {0xadd29bf2U, 0x6fffcbc8U, 0x375d8c1aU, 0xfab07d54U, 0xc58af7b7U, 0x20d95b9aU, 0x1f4c7f39U, 0x6519f820U},{1}},
        {{0xd3de0466U, 0xf9627435U, 0x2617e30aU, 0x02b61dd6U, 0x22dd8d6fU, 0xf9b733a0U, 0x59549c34U, 0x9b399252U},
         {0x379080f5U, 0x4e7e4707U, 0x57ec3f59U, 0xe5c70940U, 0x5c54a538U, 0xdcb3d9a6U, 0x1d5942c4U, 0x565d0fc1U},{1}},
        {{0x5c42fab2U, 0x07c35567U, 0x0bffe00dU, 0x415bc04cU, 0xba0e588cU, 0xf2f7b28bU, 0x783a3766U, 0xa78eafeaU},
         {0x1316e511U, 0x7ba2defdU, 0xeda99eaeU, 0xcb726b9cU, 0xc3c8baf7U, 0x35adac35U, 0xde1e5c0cU, 0x9a444260U},{1}},
        {{0xa14dfe2aU, 0x4cab1d53U, 0xf29d5576U, 0xca10d5abU, 0x24220f9cU, 0x169782b5U, 0xc14d72c3U, 0x36f84412U},
         {0x7cf7efa3U, 0x1d7d5651U, 0xe4edfd1bU, 0x9643ee22U, 0xff7973beU, 0x10f770e4U, 0x6d1d597eU, 0x2a4501b5U},{1}},
        {{0x1af7b8bbU, 0xe12dc16bU, 0x53893679U, 0xe462afcaU, 0x256f1881U, 0x4bac5266U, 0xcc267ef7U, 0x4bac6898U},
         {0x44cbb149U, 0x9b72c54eU, 0x37092612U, 0x91118de4U, 0x973dfc2aU, 0xbd2bbf39U, 0x05995f72U, 0xf87a708dU},{1}},
        {{0x5eaca9f2U, 0xb986f6b1U, 0xbffdb5c5U, 0x35a741f2U, 0xab594e00U, 0x7fca371cU, 0x3c880137U, 0xcf7ee8c0U},
         {0x2f6a77daU, 0xed61d2c5U, 0x11c873acU, 0x3050b217U, 0xcc7853afU, 0x7eedf740U, 0xf9c473b6U, 0x7d387e25U},{1}},
        {{0xaa8b5d6dU, 0xaf352e7fU, 0xa85a4115U, 0x65a09effU, 0xbba73800U, 0x2f1bbbb1U, 0x2e30c20dU, 0xfa563d19U},
         {0x31cc2211U, 0xd170f488U, 0xacfe0007U, 0x5f6bd812U, 0x5b742cdfU, 0xba0d9d83U, 0x4a0fff6eU, 0x43c56da2U},{1}},
        {{0x41a343ceU, 0x367fde41U, 0x9a6c4f24U, 0xb1b93240U, 0x3911e128U, 0x20421845U, 0xe9c5698bU, 0x982295afU},
         {0x821e578cU, 0x634c3c14U, 0x23a501caU, 0xa70197b0U, 0x6849921eU, 0xc239f319U, 0x7c8b030cU, 0xccf6b624U},{1}},
        {{0xe1607724U, 0x75b61aa1U, 0xab0197e1U, 0x0638fbd2U, 0xf6ae0a9bU, 0x291c3437U, 0x9a7e9098U, 0xe42f40b0U},
         {0x64ebd2f6U, 0x942d68fbU, 0x328aea1dU, 0x79f4240fU, 0x21c8ca41U, 0xe2271abfU, 0xb9d94647U, 0xdb988493U},{1}},
        {{0x54fe6370U, 0xec93068eU, 0x96689b71U, 0x23e8f229U, 0xeb184703U, 0x33740d31U, 0x16418155U, 0xc84f7731U},
         {0x052c2c4fU, 0xbd0ba404U, 0xeb21b54dU, 0xd6c051c1U, 0xe06261f1U, 0x0ac0dd54U, 0x67754403U, 0x380245f2U},{1}},
        {{0x678337eeU, 0x834dbff6U, 0xfef0785aU, 0xc607e811U, 0xe30a298bU, 0xaaefc62bU, 0x326afad3U, 0xeb5ca335U},
         {0x84af54a8U, 0x9774fe13U, 0x785388b4U, 0xca4b6ef5U, 0x66f6c642U, 0x1346c82dU, 0xaa2d53ceU, 0xedcc0c2aU},{1}},
        {{0xec0b49b7U, 0x7adf1f6eU, 0xad564ce3U, 0xbfff9310U, 0xcec8d505U, 0xc5d423f9U, 0x587fffb1U, 0x90987a8eU},
         {0x24ad27efU, 0xe8544f00U, 0x397e7efdU, 0xfb62130bU, 0xb1f447a9U, 0x588431f2U, 0x8556da90U, 0xead0c17aU},{1}},
        {{0x4a5c9e86U, 0xe563507aU, 0x90a3f7daU, 0x3ed469faU, 0xdfacbe50U, 0xd9c1a904U, 0x8ec1396eU, 0xd3a9f972U},
         {0xd9402a08U, 0xdaa67a58U, 0x62506d6aU, 0xa936adefU, 0x5875a3dcU, 0xb9c19d61U, 0x27d24570U, 0x61df4bc4U},{1}},
        {{0x6f2c9baaU, 0x8de3f066U, 0xb94964a3U, 0xd61f2ec1U, 0x8808e1adU, 0x73449d5bU, 0xf0653260U, 0xc45b5423U},
         {0x2518bd75U, 0xf3e85d46U, 0x49a27e7fU, 0x284c2d58U, 0xc92aab81U, 0xe7271e78U, 0x31528559U, 0xe80f69ccU},{1}},
        {{0x8c366226U, 0x138a4d1aU, 0x102e0468U, 0x147b1c72U, 0x5fea946cU, 0xaefe9725U, 0x11baae83U, 0xac66b961U},
         {0xe454286eU, 0x5d9f2078U, 0x74d650f5U, 0x8f8e0535U, 0xe998a42eU, 0x90d24265U, 0x553579e6U, 0x8fb6390bU},{1}},
        {{0x0490e669U, 0x7725cf74U, 0x4c575843U, 0xcb58c73fU, 0x01cc6310U, 0x4e441529U, 0x0859e203U, 0xba982df2U},
         {0xd34d6b1fU, 0x392a81c3U, 0xb1e6070aU, 0x814c5f88U, 0x045056efU, 0xaaf3ddffU, 0x09890774U, 0xcb8953e5U},{1}},
        {{0x38dc9d2bU, 0xdee2b5d8U, 0x558c2991U, 0x5a05142dU, 0xb4f9d5c1U, 0xc2392c9bU, 0x2c3ff462U, 0x50c02ef4U},
         {0x4917e215U, 0x783e01b4U, 0xc153cb99U, 0xd602419cU, 0x20c898e8U, 0xdd932aabU, 0x0959ad3aU, 0xdf10d6aaU},{1}},
        {{0x158c9176U, 0x870d9541U, 0x7527d450U, 0x769f45e1U, 0x328f6de2U, 0xa74509d7U, 0x2ae5297fU, 0x6bae6f17U},
         {0x7891400fU, 0xbaece711U, 0xe989523dU, 0x191f2080U, 0x51a2c974U, 0xe5bf7d98U, 0x3b7de2d6U, 0x507c65e0U},{1}},
        {{0x9e595befU, 0x6ba80d6dU, 0xdcea2b33U, 0xbf74e3a2U, 0xaf37aec3U, 0x6caf1defU, 0x85a9d77eU, 0x05fb7d6fU},
         {0x900b2d09U, 0x6324953aU, 0x132852e7U, 0xb41d83e7U, 0x7108c827U, 0x1e1dd0e5U, 0xf9f4ebb0U, 0xee4afcb8U},{1}},
        {{0x6269454bU, 0xdcd8ade8U, 0xfe4974d3U, 0xeb7ca8d2U, 0x31b7b389U, 0x7ad07dd2U, 0x11aa92a1U, 0x817b19ecU},
         {0x4fcc0dc7U, 0xb5ada6e9U, 0xcd69d646U, 0x1833b9bdU, 0x96ef6f69U, 0x6f7908b6U, 0x7dff6cf8U, 0x5e5816f7U},{1}},
        {{0xacb4c0beU, 0xda3fd31eU, 0x6975e65bU, 0x6c4897a5U, 0x2f3782cdU, 0xce21ba7bU, 0xb2fb1245U, 0x87feecc2U},
         {0x560d4a58U, 0x20edf5aaU, 0x609cde9eU, 0x0bedfb01U, 0x43829dc3U, 0x2ec53f59U, 0xbd049076U, 0x01fa61eeU},{1}},
        {{0x37040556U, 0xf8e996c9U, 0x322fdcb2U, 0x965ab458U, 0xb9411d1dU, 0x4a21d0a2U, 0x7e6b3e61U, 0x20dc3a01U},
         {0x0804d010U, 0x143a57f2U, 0x537888a1U, 0x0d18f09aU, 0x6f7ceef0U, 0x08591429U, 0x6509d5f1U, 0x2bd03eecU},{1}},
        {{0x1faa54c7U, 0x43e59502U, 0x29447a71U, 0xc3119278U, 0xb9fd1ea7U, 0x751cbef4U, 0xee4e539dU, 0xecb35d16U},
         {0xf78ecf4fU, 0xe111dfd9U, 0x5f6d1bf3U, 0x679b2287U, 0xfe378d58U, 0x9f4249e0U, 0x075f6430U, 0x8563e4edU},{1}},
        {{0xdbea8b56U, 0xf099e607U, 0x1066aadeU, 0x45384e96U, 0x6e619c13U, 0xe812ce3aU, 0x5aef9ba2U, 0x4ddb9dbbU},
         {0x89d1e30aU, 0x306430faU, 0x2680bef0U, 0x36c52428U, 0x40eac595U, 0x9ad05721U, 0x730ed3caU, 0x81388541U},{1}},
        {{0x11be893dU, 0x39eac061U, 0xfb23d45cU, 0x63053090U, 0x9d2b3dbaU, 0x945f37feU, 0x6a4a021bU, 0x4e6d4a18U},
         {0x941fd695U, 0x2c29cd2fU, 0x12c3f6c1U, 0x3845a496U, 0x46f4abfdU, 0x8ce30f2dU, 0x5bd83deeU, 0x72279b20U},{1}},
        {{0x3e1e1356U, 0x6cbc2b98U, 0x0c50bb85U, 0x8a1788b6U, 0xb3a6e5c4U, 0x856700d0U, 0xc0404f94U, 0x326db9b3U},
         {0x4beb4290U, 0xf8a8b978U, 0x226a5bbeU, 0xd0d605f7U, 0xbad882c3U, 0x13188b88U, 0xbab6d0dcU, 0x80cc3a5cU},{1}},
        {{0x3d11fc00U, 0x568a5adaU, 0x4eb881a4U, 0xf1644901U, 0x16062f82U, 0xfdb9a3a5U, 0xc3a45f29U, 0x1eb2cc06U},
         {0xabb5a6b8U, 0x0551f4d6U, 0x37ca1cc5U, 0x7ac9d465U, 0xa4225f64U, 0xb1d327b4U, 0xcbf07cf9U, 0x2fe98d3cU},{1}},
        {{0x3ae3e7b1U, 0x2016a1b2U, 0x4804ed97U, 0xeeab4de6U, 0x346a0beaU, 0x3cbfff1dU, 0x514f1a81U, 0xe114fc93U},
         {0xa25a08a3U, 0x674c2170U, 0xa3e54b38U, 0xf3badc0dU, 0xe04ac730U, 0xc38b9c44U, 0xbe897bbbU, 0x0151b3acU},{1}},
        {{0xa9e1ebbbU, 0x107b4dfaU, 0xc4c3d95fU, 0xf7ee4d8aU, 0xd269ad96U, 0x3672ef04U, 0xd1ee162cU, 0xbf822abfU},
         {0xb0d35ffaU, 0x5aa76cc7U, 0x39a0a204U, 0x069afdbcU, 0xf3d1a9aeU, 0x7e734908U, 0xfdb04a51U, 0x10c4def6U},{1}},
        {{0x1529db42U, 0x48bb387aU, 0xdaeda1ebU, 0xa3fa4bfbU, 0xe779f44aU, 0x881158cfU, 0xb07c0513U, 0xdcb53eb5U},
         {0x0746e1aaU, 0x63d0aca2U, 0xbc547380U, 0x083d8d22U, 0xe5fd9181U, 0xf0ab2ad4U, 0xe629a820U, 0x571adb13U},{1}},
        };

static void ECP_Sm2FpSet(Sm2Fp r, const Sm2Fp a) {
    memcpy_s(r, sizeof(Sm2Fp), a, sizeof(Sm2Fp));
}

static int ECP_Sm2FpIsOdd(const Sm2Fp a){
    return (int) a[0] & 1;
}

static int ECP_Sm2FpIsEven(const Sm2Fp a){
    return (int) (a[0] & 1) ^ 1;
}

static int ECP_Sm2FpIsZero(const Sm2Fp a) {
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0;
}

static int ECP_Sm2FpIsOne(const Sm2Fp a){
    return a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0;
}

static int ECP_Sm2FpEqu(const Sm2Fp a, const Sm2Fp b) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5] && a[6] == b[6] && a[7] == b[7];
}

/**
 * @brief Computes multiplicative inverse modulo sm2_p, i.e., r ≡ a^-1 mod sm2_p.
 * @param [out] r The result number.
 * @param [in] q The number to invert.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 2.22
 */
static void ECP_Sm2FpInv(Sm2Fp r, const Sm2Fp q) {
    Sm2Fp u, v = {0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU}, a = {1}, c = {0};
    ECP_Sm2FpSet(u, q);
    while (ECP_Sm2FpIsOne(u) == 0 && ECP_Sm2FpIsOne(v) == 0) {
        while (ECP_Sm2FpIsEven(u)) {
            ECP_Sm2FpHaf(u, u);
            ECP_Sm2FpHaf(a, a);
        }
        while (ECP_Sm2FpIsEven(v)) {
            ECP_Sm2FpHaf(v, v);
            ECP_Sm2FpHaf(c, c);
        }
        if (ECP_Sm2FpCmp(u, v)) {
            ECP_Sm2FpSub(u, u, v);
            ECP_Sm2FpSub(a, a, c);
        } else {
            ECP_Sm2FpSub(v, v, u);
            ECP_Sm2FpSub(c, c, a);
        }
    }
    if (ECP_Sm2FpIsOne(u)) {
        ECP_Sm2FpSet(r, a);
    } else {
        ECP_Sm2FpSet(r, c);
    }
}


/**
 * @brief Computes multiplicative inverse modulo sm2_n, i.e., r ≡ a^-1 mod sm2_n.
 * @param [out] r The result number.
 * @param [in] q The number to invert.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 2.22
 */
static void ECP_Sm2FnInv(Sm2Fp r, const Sm2Fp q) {
    Sm2Fp u, v = {0x39D54123U, 0x53BBF409U, 0x21C6052BU, 0x7203DF6BU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU}, a = {1}, c = {0};
    ECP_Sm2FpSet(u, q);
    while (ECP_Sm2FpIsOne(u) == 0 && ECP_Sm2FpIsOne(v) == 0) {
        while (ECP_Sm2FpIsEven(u)) {
            ECP_Sm2FnHaf(u, u);
            ECP_Sm2FnHaf(a, a);
        }
        while (ECP_Sm2FpIsEven(v)) {
            ECP_Sm2FnHaf(v, v);
            ECP_Sm2FnHaf(c, c);
        }
        if (ECP_Sm2FpCmp(u, v)) {
            ECP_Sm2FnSub(u, u, v);
            ECP_Sm2FnSub(a, a, c);
        } else {
            ECP_Sm2FnSub(v, v, u);
            ECP_Sm2FnSub(c, c, a);
        }
    }
    if (ECP_Sm2FpIsOne(u)) {
        ECP_Sm2FpSet(r, a);
    } else {
        ECP_Sm2FpSet(r, c);
    }
}

static void ECP_Sm2FpNaf(Sm2Naf r, const uint8_t w, const Sm2Fp n) {
    if (w > 7)
        return;     // w > 7 is not supported unless the sm2_naf type definition is expanded from int8_t[257] to int[257]

    int i = SM2_BITS;
    Sm2Fp k, t;
    ECP_Sm2FpSet(k, n);
    while (ECP_Sm2FpCmp(k, g_Sm2One)) {
        if (ECP_Sm2FpIsOdd(k)) {
            ECP_Sm2FpSet(t, g_Sm2Zero);
            t[0] = k[0] & ((1 << w) - 1);
            if (t[0] >> (w - 1)) {
                t[0] = (1 << w) - t[0];
                r[i] = (int8_t) -t[0];
            } else {
                r[i] = (int8_t) t[0];
            }
            if (r[i] > 0)
                ECP_Sm2FpSub(k, k, t);
            else
                ECP_Sm2FpAdd(k, k, t);
        } else
            r[i] = 0;
        ECP_Sm2FpHaf(k, k);
        i--;
    }
    while (i >= 0) {
        r[i--] = 0;
    }
}

// Only used in ECP_Sm2PointGenCore which use optimal parameter (window width) w = 5 is used here.
// Thus, the number of windows is ⌈256/5⌉ = 52.
static void ECP_Sm2FpNafP(int8_t K[52], const Sm2Fp k) {
    Sm2Naf kn;
    ECP_Sm2FpNaf(kn, 2, k);
    int i, j = 0;
    for (i = SM2_BITS; i > 2; i = i-5){
        K[j++] = (int8_t) (kn[i] + (kn[i-1]<<1) + (kn[i-2]<<2) + (kn[i-3]<<3) + (kn[i-4]<<4));
    }
    K[j] = (int8_t) (kn[1] + (kn[0]<<1));
}

//**********************************************************************************************************************

static void ECP_Sm2PointCopy(Sm2Point *p, const Sm2Point *q) {
    memcpy_s(p, sizeof(Sm2Point), q, sizeof(Sm2Point));
}

static void ECP_Sm2PointSet(Sm2Point *p, const Sm2Fp x, const Sm2Fp y, const Sm2Fp z) {
    ECP_Sm2FpSet(p->x, x);
    ECP_Sm2FpSet(p->y, y);
    ECP_Sm2FpSet(p->z, z);
}

static void ECP_Sm2PointSetInfinity(Sm2Point *r) {
    ECP_Sm2PointSet(r, g_Sm2One, g_Sm2One, g_Sm2Zero);
}

static int ECP_Sm2PointAtInfinity(const Sm2Point *r){
    return ECP_Sm2FpIsZero(r->z);
}

/**
 * @brief Converts a jacobian point to affine coordinates.
 * @param [in] a Pointer to the jacobian point to convert.
 * @param [out] r Pointer to the resulting affine point.
 */
void ECP_Sm2PointToAffineCore(const Sm2Point *a, Sm2Point *r) {
    Sm2Fp t1, t2;
    ECP_Sm2FpInv(t1, a->z);
    ECP_Sm2FpSqr(t2, t1);
    ECP_Sm2FpMul(r->x, t2, a->x);
    ECP_Sm2FpMul(t2, t2, t1);
    ECP_Sm2FpMul(r->y, t2, a->y);
    ECP_Sm2FpSet(r->z, g_Sm2One);
}

/**
 * @brief Doubles a jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] a Pointer to the SM2jacobianPoint to be doubled.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2004-hmv
 */
static void ECP_Sm2PointDouCore(Sm2Point *r, const Sm2Point *a) {
    if (ECP_Sm2PointAtInfinity(a)) {
        ECP_Sm2PointCopy(r, a);
        return;
    }
    // A = 3(x1 - z1²) * (x1 + z1²)
    // B = 2Y1, z3 = B * z1, C = B²
    // D = C * x1, x3 = A² - 2D, (D - x3) * A - C²/2
    const uint32_t *x1 = a->x, *y1 = a->y, *z1 = a->z;
    Sm2Fp t1, t2, t3, x3, y3, z3;
    ECP_Sm2FpSqr(t1, z1);                     // t1 = z1²
    ECP_Sm2FpSub(t2, x1, t1);                 // t2 = x1 - z1²
    ECP_Sm2FpAdd(t1, x1, t1);                 // t1 = x1 + z1²
    ECP_Sm2FpMul(t2, t2, t1);                 // t2 = x1² - z1⁴
    ECP_Sm2FpDou(t3, t2);                     // t3 = 2(x1² - z1⁴)
    ECP_Sm2FpAdd(t2, t2, t3);                 // t2 = A = 3t2 = 3(x1² - z1⁴)
    ECP_Sm2FpDou(y3, y1);                     // y3 = B = 2y1
    ECP_Sm2FpMul(z3, y3, z1);                 // z3 = B * z1
    ECP_Sm2FpSqr(y3, y3);                     // y3 = C = B²
    ECP_Sm2FpMul(t3, y3, x1);                 // t3 = D = C * x1
    ECP_Sm2FpSqr(y3, y3);                     // y3 = C²
    ECP_Sm2FpHaf(y3, y3);                     // y3 = C²/2
    ECP_Sm2FpSqr(x3, t2);                     // x3 = A²
    ECP_Sm2FpDou(t1, t3);                     // t1 = 2D
    ECP_Sm2FpSub(x3, x3, t1);                 // x3 = A² - 2D
    ECP_Sm2FpSub(t1, t3, x3);                 // t1 = D - x3
    ECP_Sm2FpMul(t1, t1, t2);                 // t1 = (D - x3) * A
    ECP_Sm2FpSub(y3, t1, y3);                 // y3 = (D - x3) * A - C²/2
    ECP_Sm2PointSet(r, x3, y3, z3);
}

/**
 * @brief Adds two jacobian points.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] p Pointer to the first SM2jacobianPoint.
 * @param [in] q Pointer to the second SM2jacobianPoint.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
 */
static void ECP_Sm2PointAddCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q) {
    // Check if one of the points is the point at infinity
    if (ECP_Sm2PointAtInfinity(p)) {
        ECP_Sm2PointCopy(r, q);
        return;
    }
    if (ECP_Sm2PointAtInfinity(q)) {
        ECP_Sm2PointCopy(r, p);
        return;
    }

    const uint32_t *x1 = p->x, *y1 = p->y, *z1 = p->z;
    const uint32_t *x2 = q->x, *y2 = q->y, *z2 = q->z;
    Sm2Fp x3, y3, z3, u1, u2, s1, s2, h, n, h2, h3, u1h2, t1, t2;

    ECP_Sm2FpSqr(t1, z1);                     // t1 = z1²
    ECP_Sm2FpSqr(t2, z2);                     // t2 = z2²
    ECP_Sm2FpMul(u1, x1, t2);                 // u1 = x1 * z2²
    ECP_Sm2FpMul(u2, x2, t1);                 // u2 = x2 * z1²
    ECP_Sm2FpMul(t1, t1, z1);                 // t1 = z1³
    ECP_Sm2FpMul(t2, t2, z2);                 // t2 = z2³
    ECP_Sm2FpMul(s1, y1, t2);                 // s1 = y1 * z2³
    ECP_Sm2FpMul(s2, y2, t1);                 // s2 = y2 * z1³
    if (ECP_Sm2FpEqu(u1, u2)) {
        if (ECP_Sm2FpEqu(s1, s2))
            ECP_Sm2PointDouCore(r, p);
        else
            ECP_Sm2PointSetInfinity(r);
        return;
    }
    ECP_Sm2FpSub(h, u2, u1);                  // h = u2 - u1
    ECP_Sm2FpSub(n, s2, s1);                  // n = s2 - s1
    ECP_Sm2FpSqr(h2, h);                      // h2 = h²
    ECP_Sm2FpMul(h3, h2, h);                  // h3 = h³
    ECP_Sm2FpMul(u1h2, u1, h2);               // u1h2 = u1 * h²
    ECP_Sm2FpDou(t1, u1h2);                   // t1 = 2u1h2
    ECP_Sm2FpSqr(x3, n);                      // x3 = n²
    ECP_Sm2FpSub(x3, x3, h3);                 // x3 = n² - h3
    ECP_Sm2FpSub(x3, x3, t1);                 // x3 = n² - h3 - 2u1h2
    ECP_Sm2FpMul(t1, s1, h3);                 // t1 = s1 * h3
    ECP_Sm2FpSub(y3, u1h2, x3);               // y3 = u1h2 - x3
    ECP_Sm2FpMul(y3, y3, n);                  // y3 = n * (u1h2 - x3)
    ECP_Sm2FpSub(y3, y3, t1);                 // y3 = n * (u1h2 - x3) - s1 * h3
    ECP_Sm2FpMul(z3, z1, z2);                 // z3 = z1 * z2
    ECP_Sm2FpMul(z3, z3, h);                  // z3 = h * z1 * z2
    ECP_Sm2PointSet(r, x3, y3, z3);
}

/**
 * @brief Subtracts one jacobian point from another.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] p Pointer to the minuend SM2jacobianPoint.
 * @param [in] q Pointer to the subtrahend SM2jacobianPoint.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-1998-cmo-2
 */
static void ECP_Sm2PointSubCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q) {
    Sm2Point t;
    memcpy_s(t.x, sizeof(Sm2Fp), q->x, sizeof(Sm2Fp));
    memcpy_s(t.z, sizeof(Sm2Fp), q->z, sizeof(Sm2Fp));
    ECP_Sm2FpNeg(t.y, q->y);
    ECP_Sm2PointAddCore(r, p, &t);
}

/**
 * @brief Point addition, affine-jacobian coordinates
 * @param [out] r The result of the addition.
 * @param [in] p The jacobian point.
 * @param [in] q The affine point.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2004-hmv
 */
static void ECP_Sm2PointAddWithAffineCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q) {
    if (ECP_Sm2PointAtInfinity(p)) {
        ECP_Sm2PointCopy(r, q);
        return;
    }
    if (ECP_Sm2FpIsZero(q->x) && ECP_Sm2FpIsZero(q->y)) {
        ECP_Sm2PointCopy(r, p);
        return;
    }

    const uint32_t *x1 = p->x, *y1 = p->y, *z1 = p->z, *x2 = q->x, *y2 = q->y;
    Sm2Fp x3, y3, z3, t1, t2, t3, t4;

    ECP_Sm2FpSqr(t1, z1);                     // t1 = A = z1²
    ECP_Sm2FpMul(t2, t1, z1);                 // t2 = B = z1 * A
    ECP_Sm2FpMul(t1, t1, x2);                 // t1 = C = x2 * A
    ECP_Sm2FpMul(t2, t2, y2);                 // t2 = D = y2 * B
    ECP_Sm2FpSub(t1, t1, x1);                 // t1 = E = C - x1
    ECP_Sm2FpSub(t2, t2, y1);                 // t2 = F = D - y1
    if (ECP_Sm2FpEqu(t1, g_Sm2Zero)) {
        if (ECP_Sm2FpEqu(t2, g_Sm2Zero)) {
            Sm2Point t;
            ECP_Sm2PointSet(&t, x2, y2, g_Sm2One);
            ECP_Sm2PointDouCore(r, &t);
        } else {
            ECP_Sm2PointSetInfinity(r);
        }
        return;
    }
    ECP_Sm2FpMul(z3, z1, t1);                 // z3 = z1 * E
    ECP_Sm2FpSqr(t3, t1);                     // t3 = G = E²
    ECP_Sm2FpMul(t4, t3, t1);                 // t4 = H = E³
    ECP_Sm2FpMul(t3, t3, x1);                 // t3 = I = x1 * G
    ECP_Sm2FpDou(t1, t3);                     // t1 = 2I
    ECP_Sm2FpSqr(x3, t2);                     // x3 = F²
    ECP_Sm2FpSub(x3, x3, t1);                 // x3 = F² - 2I
    ECP_Sm2FpSub(x3, x3, t4);                 // x3 = F² - 2I - H
    ECP_Sm2FpSub(t3, t3, x3);                 // t3 = I - x3
    ECP_Sm2FpMul(t3, t3, t2);                 // t3 = (I - x3) * F
    ECP_Sm2FpMul(t4, t4, y1);                 // t4 = y1 * H
    ECP_Sm2FpSub(y3, t3, t4);                 // y3 = (I - x3) * F - y1 * H
    ECP_Sm2PointSet(r, x3, y3, z3);
}

/**
 * @brief Point subtraction, affine-jacobian coordinates
 * @param [out] r The result of the subtraction.
 * @param [in] p The jacobian point.
 * @param [in] q The affine point.
 * @ref https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2004-hmv
 */
static void ECP_Sm2PointSubWithAffineCore(Sm2Point *r, const Sm2Point *p, const Sm2Point *q) {
    Sm2Point t;
    memcpy_s(t.x, sizeof(Sm2Fp), q->x, sizeof(Sm2Fp));
    memcpy_s(t.z, sizeof(Sm2Fp), q->z, sizeof(Sm2Fp));
    ECP_Sm2FpNeg(t.y, q->y);
    ECP_Sm2PointAddWithAffineCore(r, p, &t);
}

/**
 * @brief Performs scalar multiplication on a jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] m Scalar for multiplication.
 * @param [in] p Pointer to the SM2jacobianPoint to be multiplied.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 3.23
 */
static void ECP_Sm2PointMultDoubleCore(Sm2Point *r, uint32_t m, const Sm2Point *p) {
    if (ECP_Sm2PointAtInfinity(p)) {
        ECP_Sm2PointSet(r, p->x, p->y, p->z); return;
    }

    Sm2Fp x, y, z, w, a, b, t;
    ECP_Sm2FpSet(x, p->x);
    ECP_Sm2FpSet(y, p->y);
    ECP_Sm2FpSet(z, p->z);
    ECP_Sm2FpDou(y, y);                   // y = 2y
    ECP_Sm2FpSqr(w, z);
    ECP_Sm2FpSqr(w, w);                   // w = z⁴
    while(m--) {
        ECP_Sm2FpSqr(a, x);
        ECP_Sm2FpSub(a, a, w);
        ECP_Sm2FpDou(t, a);
        ECP_Sm2FpAdd(a, a, t);            // a = 3(x² - w)
        ECP_Sm2FpSqr(b, y);
        ECP_Sm2FpMul(b, x, b);            // b = x * y²
        ECP_Sm2FpSqr(x, a);
        ECP_Sm2FpSub(x, x, b);
        ECP_Sm2FpSub(x, x, b);            // x = a² - 2b
        ECP_Sm2FpMul(z, z, y);            // z = z * y
        ECP_Sm2FpSqr(t, y);
        ECP_Sm2FpSqr(t, t);               // t = y⁴
        if (m)
            ECP_Sm2FpMul(w, w, t);        // w = w * y⁴
        ECP_Sm2FpSub(y, b, x);
        ECP_Sm2FpMul(y, y, a);
        ECP_Sm2FpDou(y, y);
        ECP_Sm2FpSub(y, y, t);            // y = 2(b-x) - y⁴
    }
    ECP_Sm2FpHaf(y, y);
    ECP_Sm2PointSet(r, x, y, z);
}

/**
 * @brief Multiplies a scalar with a given jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] k Scalar for multiplication.
 * @param [in] g Pointer to the SM2jacobianPoint to be multiplied.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 3.36
*/
static void ECP_Sm2PointMulCore(Sm2Point *r, const Sm2Fp k, const Sm2Point *g) {

    // compute the sm2_naf of k, The optimal parameter (window width) w = 4 is used here.
    static Sm2Naf K;
    ECP_Sm2FpNaf(K, 4, k);

    // compute the table of point g: {g, 3g, 5g, 7g, ...}
    ECP_Sm2PointCopy(&upt[0], g);
    ECP_Sm2PointDouCore(r, g);
    for (uint32_t i = 1; i < 8; i++) {
        ECP_Sm2PointAddCore(&upt[i], &upt[i - 1], r);
    }

    // compute the result
    uint32_t i = 0, j = 1;
    ECP_Sm2PointSetInfinity(r);
    do {
        if (K[i] == 0) {
            j++;
        } else {
            ECP_Sm2PointMultDoubleCore(r, j, r);
            if (K[i] > 0)
                ECP_Sm2PointAddCore(r, r, &upt[K[i] >> 1]);
            else
                ECP_Sm2PointSubCore(r, r, &upt[-K[i] >> 1]);
            j = 1;
        }
    } while (++i <= SM2_BITS);
    ECP_Sm2PointMultDoubleCore(r, j - 1, r);
}

/**
 * @brief Multiplies a scalar with a base jacobian point.
 * @param [out] r Pointer to the resulting SM2jacobianPoint.
 * @param [in] k Scalar used for the generation.
 * @ref "Guide to Elliptic Curve Cryptography" by Hankerson, Menezes and Vanstone, Algorithm 3.42.
*/
static void ECP_Sm2PointGenCore(Sm2Point *r, const Sm2Fp k) {

    // The optimal parameter (window width) w = 5 is used here. Thus, the number of windows is ⌈256/5⌉ = 52
    static Sm2Point a, b;
    static int8_t K[52];

    // set infinity point(1, 1, 0)
    ECP_Sm2PointSetInfinity(&a);
    ECP_Sm2PointSetInfinity(&b);

    // compute the sm2_naf of k
    ECP_Sm2FpNafP(K, k);

    // compute the result, the representation range for each Ki (width-w NAF(k)) is [-I, I], I = (2^{w+1} - 1) / 3 = 21.
    for (int j = 21; j > 0; j--) {
        for (int i = 0; i < 52; i++) {
            if (K[i] == j)
                ECP_Sm2PointAddWithAffineCore(&b, &b, &sm2_point_gen_table[i]);
            if (K[i] == -j)
                ECP_Sm2PointSubWithAffineCore(&b, &b, &sm2_point_gen_table[i]);
        }
        ECP_Sm2PointAddCore(&a, &a, &b);
    }
    ECP_Sm2PointCopy(r, &a);
}

static int32_t ECP_SM2FpGet(Sm2Fp dst, const BN_BigNum *src)
{
    if (src->size > SM2_LIMBS) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    ECP_Sm2FpSet(dst, g_Sm2Zero);
    if (BN_IsZero(src)) {
        return CRYPT_SUCCESS;
    }
    for (uint32_t i = 0; i < src->size; i++) {
        dst[i] = src->data[i];
    }
    return CRYPT_SUCCESS;
}

static int32_t ECP_SM2FpPut(const Sm2Fp src, BN_BigNum *dst)
{
    int32_t ret = BN_Extend(dst, SM2_LIMBS);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_Zeroize(dst);
    for (uint32_t i = 0; i < SM2_LIMBS; i++) {
        dst->data[i] = src[i];
        dst->size += dst->data != 0;
    }
    return CRYPT_SUCCESS;

}

static int32_t ECP_SM2PointGet(Sm2Point *dst, const ECC_Point *src)
{
    int32_t ret;
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->x, src->x), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->y, src->y), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpGet(dst->z, src->z), ret);
ERR:
    return ret;
}

static int32_t ECP_SM2PointPut(const Sm2Point *src, ECC_Point *dst)
{
    int32_t ret;
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->x, dst->x), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->y, dst->y), ret);
    GOTO_ERR_IF_EX(ECP_SM2FpPut(src->z, dst->z), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Mul(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *b, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = data;
    if (r == NULL || a == NULL || b == NULL || mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if ((mod->size > b->room) || (mod->size > a->room)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (a->size == 0 || b->size == 0) {
        return BN_Zeroize(r);
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp u, v;
    GOTO_ERR_IF(ECP_SM2FpGet(u, a), ret);
    GOTO_ERR_IF(ECP_SM2FpGet(v, b), ret);
    ECP_Sm2FpMul(u, u, v);
    GOTO_ERR_IF(ECP_SM2FpPut(u, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Sqr(BN_BigNum *r, const BN_BigNum *a, void *data, BN_Optimizer *opt)
{
    BN_BigNum *mod = (BN_BigNum *)data;
    if (r == NULL || a == NULL ||  mod == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // Ensure that no out-of-bounds access occurs.
    if (mod->size > a->room) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_SPACE_NOT_ENOUGH);
        return CRYPT_BN_SPACE_NOT_ENOUGH;
    }
    if (a->size == 0) {
        return BN_Zeroize(r);
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FpSqr(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2Inv(BN_BigNum *r, const BN_BigNum *a, const BN_BigNum *p, BN_Optimizer *opt)
{
    if (r == NULL || a == NULL || p == NULL || opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a) || BN_IsZero(p)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FpInv(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2OrderInv(const ECC_Para *para, BN_BigNum *r, const BN_BigNum *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_DIVISOR_ZERO);
        return CRYPT_BN_ERR_DIVISOR_ZERO;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    GOTO_ERR_IF(ECP_SM2FpGet(n, a), ret);
    ECP_Sm2FnInv(n, n);
    GOTO_ERR_IF(ECP_SM2FpPut(n, r), ret);
    if (BN_IsZero(r)) {
        BSL_ERR_PUSH_ERROR(CRYPT_BN_ERR_NO_INVERSE);
        return CRYPT_BN_ERR_NO_INVERSE;
    }
    return CRYPT_SUCCESS;
    ERR:
        return ret;
}

int32_t ECP_Sm2Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (r == NULL || a == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || a->id != CRYPT_ECC_SM2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    Sm2Fp t1, t2;
    GOTO_ERR_IF_EX(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2FpInv(t1, p.z);
    ECP_Sm2FpSqr(t2, t1);
    ECP_Sm2FpMul(p.x, t2, p.x);
    ECP_Sm2FpMul(t2, t2, t1);
    ECP_Sm2FpMul(p.y, t2, p.y);
    GOTO_ERR_IF_EX(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2Point2AffineWithInv(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const BN_BigNum *inv)
{
    if (para == NULL || r == NULL || a == NULL || inv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != a->id || para->id != r->id) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_IsZero(a->z)) {
        // Infinite point multiplied by z is meaningless.
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp n;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2FpGet(n, inv), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, a), ret);
    ECP_Sm2FpSqr(p.z, n);
    ECP_Sm2FnMul(p.x, p.z, q.x);
    ECP_Sm2FnMul(p.y, p.z, q.y);
    ECP_Sm2FnMul(p.y, p.y, n);
    ECP_Sm2FpSet(p.z, g_Sm2One);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointAdd(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a->z)) {
        // If point a is an infinity point, r = b
        return ECC_CopyPoint(r, b);
    }
    if (BN_IsZero(b->z)) {
        // If point b is an infinity point, r = a
        return ECC_CopyPoint(r, a);
    }
    if (BN_Cmp(a->x, b->x) == 0 && BN_Cmp(a->y, b->y) == 0 && BN_Cmp(a->z, b->z) == 0) {
        return para->method->pointDouble(para, r, a);
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, b), ret);
    ECP_Sm2PointAddCore(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2PointAddAffine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, const ECC_Point *b)
{
    if (para == NULL || r == NULL || a == NULL || b == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (BN_IsZero(a->z)) { // If point a is an infinity point, r = b
        return ECC_CopyPoint(r, b);
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, b), ret);
    ECP_Sm2PointAddWithAffineCore(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
    ERR:
        return ret;
}

int32_t ECP_Sm2PointDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2PointDouCore(&p, &p);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointMultDouble(const ECC_Para *para, ECC_Point *r, const ECC_Point *a, uint32_t m)
{
    if (para == NULL || r == NULL || a == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2PointGet(&p, a), ret);
    ECP_Sm2PointMultDoubleCore(&p, m, &p);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);
ERR:
    return ret;
}

int32_t ECP_Sm2PointMul(ECC_Para *para, ECC_Point *r, const BN_BigNum *scalar, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || scalar == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || (pt != NULL && (pt->id != CRYPT_ECC_SM2))) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (pt != NULL && BN_IsZero(pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }
    if (BN_IsZero(scalar)) {
        return BN_Zeroize(r->z);
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp k;
    Sm2Point p;
    GOTO_ERR_IF(ECP_SM2FpGet(k, scalar), ret);
    if (pt == NULL) {
        ECP_Sm2PointGenCore(&p, k);
    } else {
        GOTO_ERR_IF_EX(ECP_SM2PointGet(&p, pt), ret);
        ECP_Sm2PointMulCore(&p, k, &p);
    }
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF_EX(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}

int32_t ECP_Sm2PointMulFast(ECC_Para *para, ECC_Point *r, const BN_BigNum *k, const ECC_Point *pt)
{
    return ECP_Sm2PointMul(para, r, k, pt);
}

int32_t ECP_Sm2PointMulAdd(ECC_Para *para, ECC_Point *r, const BN_BigNum *k1, const BN_BigNum *k2, const ECC_Point *pt)
{
    if (para == NULL || r == NULL || k1 == NULL || k2 == NULL || pt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (para->id != CRYPT_ECC_SM2 || r->id != CRYPT_ECC_SM2 || pt->id != CRYPT_ECC_SM2) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_ERR_CURVE_ID);
        return CRYPT_ECC_POINT_ERR_CURVE_ID;
    }
    if (BN_Bits(k1) > SM2_BITS || BN_Bits(k1) > SM2_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_MUL_ERR_K_LEN);
        return CRYPT_ECC_POINT_MUL_ERR_K_LEN;
    }
    if (BN_IsZero(pt->z)) {
        BSL_ERR_PUSH_ERROR(CRYPT_ECC_POINT_AT_INFINITY);
        return CRYPT_ECC_POINT_AT_INFINITY;
    }

    int32_t ret = CRYPT_SUCCESS;
    Sm2Fp s, t;
    Sm2Point p, q;
    GOTO_ERR_IF(ECP_SM2FpGet(s, k1), ret);
    GOTO_ERR_IF(ECP_SM2FpGet(t, k2), ret);
    GOTO_ERR_IF(ECP_SM2PointGet(&q, pt), ret);
    ECP_Sm2PointGenCore(&p, s);
    ECP_Sm2PointMulCore(&q, t, &q);
    ECP_Sm2PointAddCore(&p, &p, &q);
    ECP_Sm2PointToAffineCore(&p, &p);
    GOTO_ERR_IF(ECP_SM2PointPut(&p, r), ret);

ERR:
    return ret;
}
#endif


