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
#ifdef HITLS_CRYPTO_CMVP

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "bsl_sal.h"

#define DRBG_PARAM_COUNT 6

typedef enum {
    CMVP_DRBG_INSTANTIATE,
    CMVP_DRBG_SEED,
    CMVP_DRBG_MAX,
} CMVP_DrbgState;

typedef struct {
    uint32_t id;
    const char *entropy;     // EntropyInput
    const char *nonce;       // Nonce
    const char *pers;        // PersonalizationString
    const char *entropySeed; // EntropyInputReseed
    const char *adinSeed;    // AdditionalInputReseed
    const char *adin1;       // AdditionalInput
    const char *adin2;       // AdditionalInput
    const char *retBits;     // ReturnedBits
} CMVP_DRBG_VECTOR;

typedef struct {
    CMVP_DrbgState state;
    CRYPT_RAND_AlgId id;
} CMVP_DRBG_SEEDCTX;

const CMVP_DRBG_VECTOR *g_currentTestVector = NULL;

/**
 * Test Vector Execution Order:
 *   1. Instantiate
 *   2. Reseed
 *   3. Generate Random Bits
 *   4. Generate Random Bits
 *   5. Uninstantiate
 * Data Source:
 *   https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Random-Number-Generators
 *   NON PR
 */
static const CMVP_DRBG_VECTOR DRBG_VECTOR[] = {
    // CRYPT_RAND_SHA1
    {
        .id = CRYPT_RAND_SHA1,
        .entropy = "48a1a97ccc49d7ccf6e378a2f16b0fcd",
        .nonce = "b091d2ec12a839fe",
        .pers = "3dc16c1add9cac4ebbb0b889e43b9e12",
        .entropySeed = "ba5da6791237243fea6050f5b99ecdf5",
        .adinSeed = "d123e38e4c97e82994a9717ac6f17c08",
        .adin1 = "800bed9729cfade6680dfe53ba0c1e28",
        .adin2 = "251e66b9e385ac1c17fb771b5dc76cf2",
        .retBits = "a1b2ee86a0f1dab79383133a62279908953a1c9a987760121119cc78b8512bd537a19db973ca397a"
                "dd9233786d5d41fffae98059048521e25284bc6fdb97f34e6a127acd410f50682846be569e9a6bc8"
    },
    // CRYPT_RAND_SHA224
    {
        .id = CRYPT_RAND_SHA224,
        .entropy = "184cbf7f1c462f27fc640ccf2aac1b26174ee41e42dcceaa",
        .nonce = "09f9d8acd06aba74b9f849f7",
        .pers = "5a5afe330e898ca94fad05b0e6b3f8146f46c90379a0b1eb",
        .entropySeed = "b5eb44d3515c74d2cbd28c4ac5edb5fb95846e74e8398ce5",
        .adinSeed = "a793fefe0f2ab3e9a0d1ddbc058d78369b03597f44099a81",
        .adin1 = "930ef8531a344fef957660cbb401583afa0f016b7023a9db",
        .adin2 = "2ee03b7314fb00e1e2616799c144cd58f051cde370588d70",
        .retBits = "22b856603db40f1b6d439d5b88fbe4734f7fdee15f4df47dfd418b362f23e48fef0f48f03d1a7b7b"
                "0de607c2a8288b1aaa01bc84646c322a88b2351855d7fa1b66b0b12baccbaa5ad6cc71833998f899"
                "8712bddf54ab8af329c55791b7576cf36ade4b921009ffe32a8d22ecf4747571"
    },
    // CRYPT_RAND_SHA256
    {
        .id = CRYPT_RAND_SHA256,
        .entropy = "6c623aea73bc8a59e28c6cd9c7c7ec8ca2e75190bd5dcae5978cf0c199c23f4f",
        .nonce = "e55db067a0ed537e66886b7cda02f772",
        .pers = "1e59d798810083d1ff848e90b25c9927e3dfb55a0888b0339566a9f9ca7542dc",
        .entropySeed = "9ab40164744c7d00c78b4196f6f917ec33d70030a0812cd4606c5a25387568a9",
        .adinSeed = "4e8bead7cbba7a7bc9ae1e1617222c4139661347599950e7225d1e2faa5d57f5",
        .adin1 = "dcb22a5d9f149858636f3ede2253e419816fb7b1103194451ed6a573a8fe6271",
        .adin2 = "8f9d5c78cdabc32e71ac3b3c49239caddf96053250f4fd92056efbd0be487d36",
        .retBits = "6e98a3b1f686f6ffa79355c9d8a5ab7f93312159d52659a2298315f10007c71adabc0b5ccb4164c0"
                "949fbdb221b43acdb62bed3099596f2d7bd5d0048173dd2360a543b234ab61a441ddb9299af84ca4"
                "5c6e618fd521366dbf509d4ec06174da924361d642b107e5564ac1b32340dd2f3158bf4c00bcb4dc"
                "f12c6d67af4b74ee"
    },
    // CRYPT_RAND_SHA384
    {
        .id = CRYPT_RAND_SHA384,
        .entropy = "f411e1feeccf01c0d4bde61ca2384a2640b41e383a055b374e0acfa8170c2f28",
        .nonce = "7cf75b960dcd0a0a9d2a4e7e8d5e47d3",
        .pers = "25d6dfee3e74d3b6a9f459094203fc76e0e589fa879cc445008c80e3736fc0a9",
        .entropySeed = "d222df563773906b875d55dc1aef90337ff59fc3ca5ed0af5e46d306d630c7e3",
        .adinSeed = "07a576624662253737789e543734d7c35ded8d74a3b53919b1c28c21a2b5ebc5",
        .adin1 = "2561c8591281f0682d3811387d0cdc16c137edfcc9527134212701f73550c572",
        .adin2 = "870441d9435f2cbf16f1168f50e32d9b8811be7adc10a5070c5eb993372c5732",
        .retBits = "9107af002a8bc3e0f0394eb0db3a801ca73844db0600873d1d576ccfbdd88dfc3eaa101e52e4c4ad"
                "9958d9d0e5f1eb555cd0d93ad2745a1302dfead60c42ef28e7211740b1dc694fdf72dd066d1d66a5"
                "8aceeb9a8c6a9c67a75326f97b742b85e7abdc853b01bd799bb9f3e8e6b5f2a41919543b17c0da4e"
                "4e25f04e1c2859a56466689ab85c46cb9f593abff0f058f7d26f2c09e379e5e0b6e123f24fb9bcfb"
                "a9a468dcb38a9577d63251d20f09b8d2b4dad74fb52e1e8dbdde6e0436563d66"
    },
    // CRYPT_RAND_SHA512
    {
        .id = CRYPT_RAND_SHA512,
        .entropy = "4b23595b0a3640cfabb0ec34df6a613308b0448488a5d9ff99da4278e072eb34",
        .nonce = "8e696bffd9ca3a71d2e2f05e600c8364",
        .pers = "010ba93ea68a3d4a200e5145859e299c5b5349b7645fb5bbcad687aba7d67313",
        .entropySeed = "04de4babdbe143bde99aa4452f9aa43b0a164eb927555c0496aa0fc9328a521c",
        .adinSeed = "2b0c7c3efb36b71b917a44086d168313675b426b17c5ab3d0eb6af753f6040e0",
        .adin1 = "d0b7d1d12ab15d3bba8f4eba07fee0974838962b247be480683b8e3d4a91033a",
        .adin2 = "66c78ca12e45bdca003b49cb6440b977dd85b167e7c803890ed1a73666eaa869",
        .retBits = "4008cbd8281dc82fd6c368f650ef2609bb771e80c63d478a77fa938248dcbb8b79e54ead0265f6ff"
                "1ebfafe4e387c6e27df9f03e4a5225e86a4436e56ebf03b3be2cfbcb49c89c92ec1dfa5ee445dd4f"
                "6f64e02a2423a0b18ebd02eec52f5cc21bc3565e796b3ded6552f1b5a574a201c3b11018222806f9"
                "618d23d77fd02db879cf87fe24ed7ba11b3b108b559633db1f95c5121b28011aa4dd20399bd4978e"
                "1f8b8880c333a47ff1750679bf28d329347b26d347aae90ee562ae8029579cbe0336e066d6b8ba5e"
                "0169fec804c30189a4434c1bf8a5b0a249951d3d89554da38ff0751b8b1fef9ae18a0aa2bc477736"
                "d199a06f61d400039a4cc03869bb10ca"
    },
    // CRYPT_RAND_SM3
    {
        .id = CRYPT_RAND_SM3,
        .entropy = "8c6368232f5cc9da92e5877fd368c5769ecf1f4eaf011a89e11686af8e379895",
        .nonce = "8dd1cfbcbd615a47e1298a94ca12f248",
        .pers = "c325c1db2ddaa54616b2b804cca6f1a8",
        .entropySeed = "5c638a5bc1ffd99fa58b0e2482347f9d5c638a5bc1ffd99fa58b0e2482347f9d",
        .adinSeed = "b05a4b1751cd5fb3e583966cf888d44d",
        .adin1 = "81b5bbc2ec9e7ae9c2f999ff58d28f2b",
        .adin2 = "7af5ca6867e0211baad5b24c6229d6a5",
        .retBits = "05a2637f235e86be101ec21b1e75ae26"
    },
    // CRYPT_RAND_HMAC_SHA1
    {
        .id = CRYPT_RAND_HMAC_SHA1,
        .entropy = "03e7b41c95818eb0b667bfa8a175a824",
        .nonce = "66a1e417a9b6b92f",
        .pers = "126dded5eb0bc81be37c10bcd9d5f793",
        .entropySeed = "d17e98c2e50ee0db00d25c3364451e95",
        .adinSeed = "dc596d188e2343802240bc7f5cc60516",
        .adin1 = "14c8ec10f5bdde6b9e75898d7f9f03d0",
        .adin2 = "31aa842afcc1daa94098241a87d6ddfc",
        .retBits = "4739b1bcf87404a2290829bd7a61f0b391a794c71c055c7cc513b28dcb5fdc88645bc9cb490f41fa"
                "b134c6b33ce9336571762754343961de671b02a47960b4b4e23c5bfb87dcc19b260b3bcb921ae325"
    },
    // CRYPT_RAND_HMAC_SHA224
    {
        .id = CRYPT_RAND_HMAC_SHA224,
        .entropy = "96ae702af50c50c7c38818a5133938bd7ce51197fc78e218",
        .nonce = "15b6c5a7ff9c0395d764159f",
        .pers = "e96554644097e9932585b7f4bb14d101f24c8b0376f38c05",
        .entropySeed = "707d5813e5bf47c1b8232b44a007bf7decfef499d758ed53",
        .adinSeed = "3f698a5f6f4fe67ef2ddf23bd5a67c1a2df4f3b19425fb85",
        .adin1 = "fe1f6a90fc0ed396bca21c0d40a1bb583eb63df78c98adac",
        .adin2 = "5942b56148f27dd5388f00caa47ffd4925e854237fe14454",
        .retBits = "150b9260ce9aa419fe1860332ae7c9f42d9ada1649679b53f46bc9d20de3431186a54afb5df7b626"
                "9cdc05540a93fdd50a2cd3a862372d862841768df02846b057993dd6aa32f874b7220a5a1fd9cb57"
                "3d720a54af5715cedfc16f0d9a467735e253b2b1a6e97421fcee1f2d670dec1a"
    },
    // CRYPT_RAND_HMAC_SHA256
    {
        .id = CRYPT_RAND_HMAC_SHA256,
        .entropy = "cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416",
        .nonce = "d0c0d01d156016d0eb6b7e9c7c3c8da8",
        .pers = "6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa",
        .entropySeed = "8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82",
        .adinSeed = "1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3",
        .adin1 = "16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff",
        .adin2 = "53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2",
        .retBits = "dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d"
                "95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8d"
                "c5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc45244565"
                "6fce22664827b88f"
    },
    // CRYPT_RAND_HMAC_SHA384
    {
        .id = CRYPT_RAND_HMAC_SHA384,
        .entropy = "c4868db5c46fde0a10008838b5be62c349209fded42fab461b01e11723c8242a",
        .nonce = "618faba54acba1e0afd4b27cbd731ed9",
        .pers = "135132cf2b8a57554bdc13c68e90dc434353e4f65a4d5ca07c3e0a13c62e7265",
        .entropySeed = "d30016b5827dc2bfe4034c6654d69775fe98432b19e3da373213d939d391f54a",
        .adinSeed = "a0bbd02f6aa71a06d1642ca2cc7cdc5e8857e431b176bcf1ecd20f041467bd2d",
        .adin1 = "93ee30a9e7a0e244aa91da62f2215c7233bdfc415740d2770780cbbad61b9ba2",
        .adin2 = "36d922cacca00ae89db8f0c1cae5a47d2de8e61ae09357ca431c28a07907fce1",
        .retBits = "2aac4cebed080c68ef0dcff348506eca568180f7370c020deda1a4c9050ce94d4db90fd827165846"
                "d6dd6cb2031eec1634b0e7f3e0e89504e34d248e23a8fb31cd32ff39a486946b2940f54c968f96cf"
                "c508cd871c84e68458ca7dccabc6dcfb1e9fbef9a47caae14c5239c28686e0fc0942b0c847c9d8d9"
                "87970c1c5f5f06eaa8385575dacb1e925c0ed85e13edbb9922083f9bbbb79405411ff5dfe7061568"
                "5df1f1e49867d0b6ed69afe8ac5e76ffab6ff3d71b4dae998faf8c7d5bc6ae4d"
    },
    // CRYPT_RAND_HMAC_SHA512
    {
        .id = CRYPT_RAND_HMAC_SHA512,
        .entropy = "da740cbc36057a8e282ae717fe7dfbb245e9e5d49908a0119c5dbcf0a1f2d5ab",
        .nonce = "46561ff612217ba3ff91baa06d4b5440",
        .pers = "fc227293523ecb5b1e28c87863626627d958acc558a672b148ce19e2abd2dde4",
        .entropySeed = "1d61d4d8a41c3254b92104fd555adae0569d1835bb52657ec7fbba0fe03579c5",
        .adinSeed = "b9ed8e35ad018a375b61189c8d365b00507cb1b4510d21cac212356b5bbaa8b2",
        .adin1 = "b7998998eaf9e5d34e64ff7f03de765b31f407899d20535573e670c1b402c26a",
        .adin2 = "2089d49d63e0c4df58879d0cb1ba998e5b3d1a7786b785e7cf13ca5ea5e33cfd",
        .retBits = "5b70f3e4da95264233efbab155b828d4e231b67cc92757feca407cc9615a660871cb07ad1a2e9a99"
                "412feda8ee34dc9c57fa08d3f8225b30d29887d20907d12330fffd14d1697ba0756d37491b0a8814"
                "106e46c8677d49d9157109c402ad0c247a2f50cd5d99e538c850b906937a05dbb8888d984bc77f6c"
                "a00b0e3bc97b16d6d25814a54aa12143afddd8b2263690565d545f4137e593bb3ca88a37b0aadf79"
                "726b95c61906257e6dc47acd5b6b7e4b534243b13c16ad5a0a1163c0099fce43f428cd27c3e6463c"
                "f5e9a9621f4b3d0b3d4654316f4707675df39278d5783823049477dcce8c57fdbd576711c91301e9"
                "bd6bb0d3e72dc46d480ed8f61fd63811"
    },
    // CRYPT_RAND_AES128_CTR
    {
        .id = CRYPT_RAND_AES128_CTR,
        .entropy = "289e5c8283cbd7dbe707255cb3cf2907d8a5ce5b347314966f9b2bebb1a1e200",
        .nonce = NULL,
        .pers = "7f7b59f23510b976fe155d047525c94e2dacb30d77ac8b09281544dd815d5293",
        .entropySeed = "98c522028f36fc6b85a8f3c003efd4b130dd90180ec81cf7c67d4c53d10f0022",
        .adinSeed = "f7a0378328d939f0f8521e39409d7175d87319c7597a9050414f7adc392a328d",
        .adin1 = "19c286f5b36194d1cc62c0188140bc9d61d2a9c5d88bb5aebc224bfb04dfca83",
        .adin2 = "820650c3201d347f5b20d3d25d1c8c7bef4d9f66a5a04c7dd9d669e95182a0c4",
        .retBits = "79a79d44edada58e3fc12a4e36ae900eeace290265f01262f40f2958a70dcbd4d4185f708c088ede"
                "7ff8c8375f44f4012f2512d38328a5df171a17029d90f185"
    },
    // CRYPT_RAND_AES192_CTR
    {
        .id = CRYPT_RAND_AES192_CTR,
        .entropy = "4b58271b116237eedd4e9ff9360382a59f3e2a173d860f2bbd8b2bace142b2395c67cf5a513f06f3",
        .nonce = NULL,
        .pers = "cf76c16cd5d270707ea9acc39744db69bfac63e566256fd6917bf9819679840f3fea2aa535d8df01",
        .entropySeed = "1867f371a345eef98b2d70fc1960397892645b7b29a4ead252e8835e0b600618a9bd6ff99785d890",
        .adinSeed = "6d44839aff8b7165deebd489ad088ecb7dcec11c32b1e747dba8f0e8a0b89f74a84ea8a05586fe9e",
        .adin1 = "42248fce0994e0e63504209d629a6943eb3e2ad512f03f79cbd5102928392bce1cacbba056ac6ca9",
        .adin2 = "bd529b600273329423a58d6f8a12be0f17989a02e73e347bc7d49d9169337a6cff7c07e8a807a80a",
        .retBits = "02486d32cd55954f406ba55705f1460d384439592dede81a84fda221fd45c0d651d67ec4a81a8b40"
                "4151a643f331ad051cb004352289de37bca71e8cc0a6aeab"
    },
    // CRYPT_RAND_AES256_CTR
    {
        .id = CRYPT_RAND_AES256_CTR,
        .entropy = "ae7ebe062971f5eb32e5b21444750785de816595ad2cbe80a209c8f8ab04b5468166de8c6ae522d8"
                "f10b56386a3b424f",
        .nonce = NULL,
        .pers = "55860dae57fcac297087c137efb796878a75868f6e7681114e9b73ed0c67e3c62bfc9f5d77e8caa5"
                "9bcdb223f4ffd247",
        .entropySeed = "a42407931bfeca70e6ee5dd197021a129525051c07468e8b25587c5ad50abe9204e882fe847b8fd4"
                "7cf7b4360e5aa034",
        .adinSeed = "ee4c88d1eb05f4853663eada501d2fc4b4984b283a88db579af2113031e03d9bc570de943dd16891"
                "8f3ba8065581fea7",
        .adin1 = "4b4b03ef19b0f259dca2b3ee3ae4cd86c3895a784b3d8eee043a2003c08289f8fffdad141e6b1ab2"
                "174d8d5d79c1e581",
        .adin2 = "3062b33f116b46e20fe3c354726ae9b2a3a4c51922c8107863cb86f1f0bdad7554075659d91c371e"
                "2b11b1e8106a1ed5",
        .retBits = "0d270518baeafac160ff1cb28c11ef68712c764c0c01674e6c9ca2cc9c7e0e8accfd3c753635ee07"
                "0081eee7628af6187fbc2854b3c204461a796cf3f3fcb092"
    },
    // CRYPT_RAND_AES128_CTR_DF
    {
        .id = CRYPT_RAND_AES128_CTR_DF,
        .entropy = "e14ed7064a97814dd326b9a05bc44543",
        .nonce = "876240c1f7de3dba",
        .pers = "26ccf56848a048721d0aad87d6fc65f0",
        .entropySeed = "7ec4ac660fa0bbfa66ac3802e511901f",
        .adinSeed = "8835d28e7f85a4e95087bdd1bb7ad57e",
        .adin1 = "2a9bd50bbb20fefe24649f5f80eede66",
        .adin2 = "f7ce3d5c6c381e56b25410c6909c1074",
        .retBits = "d2f3130d309bed1da65545b9d793e035fd2564303d1fdcfb6c7fee019500d9f5d434fab2d3c8d15e"
                "39a25f965aaa804c7141407e90c4a86a6c8d303ce83bfb34"
    },
    // CRYPT_RAND_AES192_CTR_DF
    {
        .id = CRYPT_RAND_AES192_CTR_DF,
        .entropy = "c4b1e6a99587eacd7ec8517f40f9433ca432cea8686433f0",
        .nonce = "d03a29e548e58ca7cbf0ac707b1464e3",
        .pers = "0daaead21779b2a428d2b7fb12d9ab8316899edbe26b5460de1549c99e4781c9",
        .entropySeed = "2229144c1b4efb79ab5fe079cda26bc33acbb2a0a87f642c",
        .adinSeed = "f116a683ca485fda846a598b8d9b079e78c2828286ad530bf01f693cc8af9f84",
        .adin1 = "7c89de353298935bd26aa18517355313df0630da5f45ea0240e809179363080b",
        .adin2 = "e978b8fe56afc908bed129a46d57a8698d66034d4dbcc7aba3a33d5796fb7559",
        .retBits = "8ce7e9589c2975fd6989a450aa65da9114e515777c97351da037ccb72d4987eb69c680411724ed60"
                "2e6ac76cd2d085725616c92777a4664d43a59c3ae9946134"
    },
    // CRYPT_RAND_AES256_CTR_DF
    {
        .id = CRYPT_RAND_AES256_CTR_DF,
        .entropy = "174b46250051a9e3d80c56ae7163dafe7e54481a56cafd3b8625f99bbb29c442",
        .nonce = "98ffd99c466e0e94a45da7e0e82dbc6b",
        .pers = "7095268e99938b3e042734b9176c9aa051f00a5f8d2a89ada214b89beef18ebf",
        .entropySeed = "e88be1967c5503f65d23867bbc891bd679db03b4878663f6c877592df25f0d9a",
        .adinSeed = "cdf6ad549e45b6aa5cd67d024931c33cd133d52d5ae500c3015020beb30da063",
        .adin1 = "c7228e90c62f896a09e11684530102f926ec90a3255f6c21b857883c75800143",
        .adin2 = "76a94f224178fe4cbf9e2b8acc53c9dc3e50bb613aac8936601453cda3293b17",
        .retBits = "1a6d8dbd642076d13916e5e23038b60b26061f13dd4e006277e0268698ffb2c87e453bae1251631a"
                "c90c701a9849d933995e8b0221fe9aca1985c546c2079027"
    },
    // CRYPT_RAND_SM4_CTR_DF
    {
        .id = CRYPT_RAND_SM4_CTR_DF,
        .entropy = "8c6368232f5cc9da92e5877fd368c5769ecf1f4eaf011a89e11686af8e379895",
        .nonce = "8dd1cfbcbd615a47e1298a94ca12f248",
        .pers = "c325c1db2ddaa54616b2b804cca6f1a8",
        .entropySeed = "5c638a5bc1ffd99fa58b0e2482347f9d5c638a5bc1ffd99fa58b0e2482347f9d",
        .adinSeed = "b05a4b1751cd5fb3e583966cf888d44d",
        .adin1 = "81b5bbc2ec9e7ae9c2f999ff58d28f2b",
        .adin2 = "7af5ca6867e0211baad5b24c6229d6a5",
        .retBits = "5e9a44ce51ee802f2fc49335d8b4588b"
    },
};

static int32_t CMVP_DrbgGetEntropy(void *ctx, CRYPT_Data *entropy, uint32_t strength, CRYPT_Range *lenRange)
{
    CMVP_DRBG_SEEDCTX *seedCtx = (CMVP_DRBG_SEEDCTX *)ctx;
    const CMVP_DRBG_VECTOR *vector = g_currentTestVector;
    GOTO_EXIT_IF(vector == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(vector->entropy == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    if (seedCtx->state == CMVP_DRBG_INSTANTIATE) {
        entropy->data = CMVP_StringsToBins(vector->entropy, &(entropy->len));
        GOTO_EXIT_IF(entropy->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
        seedCtx->state = CMVP_DRBG_SEED;
    } else if (seedCtx->state == CMVP_DRBG_SEED) {
        entropy->data = CMVP_StringsToBins(vector->entropySeed, &(entropy->len));
        GOTO_EXIT_IF(entropy->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
        seedCtx->state = CMVP_DRBG_MAX;
    }

    (void)strength;
    (void)lenRange;
    return CRYPT_SUCCESS;
EXIT:
    return CRYPT_CMVP_ERR_ALGO_SELFTEST;
}

static void CMVP_DrbgCleanData(void *ctx, CRYPT_Data *data)
{
    BSL_SAL_Free(data->data);
    data->data = NULL;
    data->len = 0;
    (void)ctx;
}

static int32_t CMVP_DrbgGetNonce(void *ctx, CRYPT_Data *nonce, uint32_t strength, CRYPT_Range *lenRange)
{
    (void)ctx;
    uint8_t *data = NULL;
    uint32_t dataLen;
    const CMVP_DRBG_VECTOR *vector = g_currentTestVector;
    GOTO_EXIT_IF(vector == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(vector->nonce == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    data = CMVP_StringsToBins(vector->nonce, &dataLen);
    GOTO_EXIT_IF(data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    nonce->data = data;
    nonce->len = dataLen;
    (void)strength;
    (void)lenRange;
    return CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(data);
    return CRYPT_CMVP_ERR_ALGO_SELFTEST;
}

static CRYPT_EAL_RndCtx *CMVP_DrbgInit(void *libCtx, const char *attrName, const CMVP_DRBG_VECTOR *drbgVec,
    CMVP_DRBG_SEEDCTX *seedCtx)
{
    CRYPT_EAL_RndCtx *ctx = NULL;
    uint8_t *pers = NULL;
    uint32_t persLen;
    CRYPT_RandSeedMethod method;
    const CMVP_DRBG_VECTOR *vector = drbgVec;
    GOTO_EXIT_IF(vector->pers == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    pers = CMVP_StringsToBins(vector->pers, &persLen);
    GOTO_EXIT_IF(pers == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    method.getEntropy = CMVP_DrbgGetEntropy;
    method.cleanEntropy = CMVP_DrbgCleanData;
    method.getNonce = CMVP_DrbgGetNonce;
    method.cleanNonce = CMVP_DrbgCleanData;

    int32_t index = 0;
    BSL_Param param[DRBG_PARAM_COUNT] = {0};
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEEDCTX, BSL_PARAM_TYPE_CTX_PTR,
        seedCtx, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        method.getEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANENTROPY, BSL_PARAM_TYPE_FUNC_PTR,
        method.cleanEntropy, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_GETNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        method.getNonce, 0);
    (void)BSL_PARAM_InitValue(&param[index++], CRYPT_PARAM_RAND_SEED_CLEANNONCE, BSL_PARAM_TYPE_FUNC_PTR,
        method.cleanNonce, 0);
    ctx = CRYPT_EAL_ProviderDrbgNewCtx(libCtx, drbgVec->id, attrName, param);

    GOTO_EXIT_IF(ctx == NULL,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_DrbgInstantiate(ctx, pers, persLen) != CRYPT_SUCCESS,  CRYPT_CMVP_ERR_ALGO_SELFTEST);

    BSL_SAL_Free(pers);
    return ctx;
EXIT:
    CRYPT_EAL_DrbgDeinit(ctx);
    BSL_SAL_Free(pers);
    return NULL;
}

static void FreeData(uint8_t *rand, uint8_t *expectRand, uint8_t *adinSeed, uint8_t *adin1, uint8_t *adin2)
{
    BSL_SAL_Free(rand);
    BSL_SAL_Free(expectRand);
    BSL_SAL_Free(adinSeed);
    BSL_SAL_Free(adin1);
    BSL_SAL_Free(adin2);
}

static uint8_t *ExecDrbg(CRYPT_EAL_RndCtx *ctx, uint32_t randLen, uint8_t *adin1, uint32_t adin1Len,
    uint8_t *adin2, uint32_t adin2Len)
{
    uint8_t *rand = NULL;
    rand = BSL_SAL_Malloc(randLen);
    GOTO_EXIT_IF(rand == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_DrbgbytesWithAdin(ctx, rand, randLen, adin1, adin1Len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_DrbgbytesWithAdin(ctx, rand, randLen, adin2, adin2Len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return rand;
EXIT:
    BSL_SAL_Free(rand);
    return NULL;
}

static bool GetData(const CMVP_DRBG_VECTOR *drbgVec, CRYPT_Data *expectRand, CRYPT_Data *adinSeed, CRYPT_Data *adin1,
    CRYPT_Data *adin2)
{
    expectRand->data = CMVP_StringsToBins(drbgVec->retBits, &(expectRand->len));
    GOTO_EXIT_IF(expectRand->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    adin1->data = CMVP_StringsToBins(drbgVec->adin1, &(adin1->len));
    GOTO_EXIT_IF(adin1->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    adin2->data = CMVP_StringsToBins(drbgVec->adin2, &(adin2->len));
    GOTO_EXIT_IF(adin2->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    adinSeed->data = CMVP_StringsToBins(drbgVec->adinSeed, &(adinSeed->len));
    GOTO_EXIT_IF(adinSeed->data == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return true;
EXIT:
    return false;
}

const CMVP_DRBG_VECTOR *FindDrbgVectorById(CRYPT_RAND_AlgId id)
{
    uint32_t num = sizeof(DRBG_VECTOR) / sizeof(DRBG_VECTOR[0]);
    const CMVP_DRBG_VECTOR *drbgVec = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (DRBG_VECTOR[i].id == id) {
            drbgVec = &DRBG_VECTOR[i];
            return drbgVec;
        }
    }

    return NULL;
}

static bool CRYPT_CMVP_SelftestDrbgInternal(void *libCtx, const char *attrName, CRYPT_RAND_AlgId id)
{
    bool ret = false;
    CRYPT_EAL_RndCtx *ctx = NULL;
    uint8_t *rand = NULL;
    CRYPT_Data expectRand = { NULL, 0 };
    CRYPT_Data adinSeed = { NULL, 0 };
    CRYPT_Data adin1 = { NULL, 0 };
    CRYPT_Data adin2 = { NULL, 0 };
    CMVP_DRBG_SEEDCTX seedCtx = { CMVP_DRBG_INSTANTIATE, id };

    const CMVP_DRBG_VECTOR *drbgVec = FindDrbgVectorById(id);
    if (drbgVec == NULL || drbgVec->entropy == NULL) {
        return false;
    }
    g_currentTestVector = drbgVec;

    GOTO_EXIT_IF(!GetData(drbgVec, &expectRand, &adinSeed, &adin1, &adin2), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ctx = CMVP_DrbgInit(libCtx, attrName, drbgVec, &seedCtx);
    GOTO_EXIT_IF(ctx == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_DrbgSeedWithAdin(ctx, adinSeed.data, adinSeed.len) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // 2: One byte and two characters
    rand = ExecDrbg(ctx, (uint32_t)strlen(drbgVec->retBits) / 2, adin1.data, adin1.len, adin2.data, adin2.len);
    GOTO_EXIT_IF(rand == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(memcmp(rand, expectRand.data, expectRand.len) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
EXIT:
    CRYPT_EAL_DrbgDeinit(ctx);
    FreeData(rand, expectRand.data, adinSeed.data, adin1.data, adin2.data);
    return ret;
}

bool CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AlgId id)
{
    return CRYPT_CMVP_SelftestDrbgInternal(NULL, NULL, id);
}

bool CRYPT_CMVP_SelftestProviderDrbg(void *libCtx, const char *attrName, CRYPT_RAND_AlgId id)
{
    return CRYPT_CMVP_SelftestDrbgInternal(libCtx, attrName, id);
}

#endif
