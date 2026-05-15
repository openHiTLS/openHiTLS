# ASN.1 基础类型编解码对照表

## 1. 目标与范围

本文主要目标：

- 基于源码，对 openhitls/bsl/asn1 目录下的核心 ASN.1 接口做语义化梳理，明确各接口的输入、输出、适用场景和边界条件。
- 按 ASN.1 基础类型与接口能力建立对照关系，帮助快速定位 INTEGER、OCTET STRING、SEQUENCE、OID 等类型应使用的编码/解码路径。
- 补充模板编码、列表编码、TLV 视图解码以及 primitive 转换路径下的内存归属和使用约束，便于开发和调试时直接查阅。

源码依据：
- `openhitls/bsl/asn1/include/bsl_asn1_internal.h`
- `openhitls/bsl/asn1/src/bsl_asn1.c`

说明：以下“核心API目录”和“详细拆解”仅覆盖 `bsl/asn1` 目录中的核心接口。

---

## 2. 基础数据结构

### 2.1 `BSL_ASN1_Buffer`
- 语义：统一承载一个 ASN.1 项（常用于 TLV 中的 V 视图/编码结果）。
- 字段：
  - `tag`：ASN.1 tag
  - `len`：value 长度
  - `buff`：指向 value 字节

### 2.2 `BSL_ASN1_BitString`
- 语义：BIT STRING 的 C 表示。
- 字段：`buff`、`len`、`unusedBits`。

### 2.3 `BSL_ASN1_TemplateItem / BSL_ASN1_Template`
- 语义：模板驱动编码/解码复杂结构（SEQUENCE、SET、嵌套对象）。
- 关键字段：`tag`、`flags`、`depth`。

---

## 3. 核心API语义化拆解

核心API目录（接口分类与ASN.1类型映射）

| 核心API | 接口分类 | 对应 ASN.1 基础类型 | 一句话功能概括 |
| --- | --- | --- | --- |
| `BSL_ASN1_DecodeTagLen` | TLV 头解析 | 通用（由 `tag` 入参决定，可用于 INTEGER/OCTET STRING/SEQUENCE/OID 等） | 仅解析 TLV 的 T+L 并把游标推进到 V 起点。 |
| `BSL_ASN1_DecodeItem` | TLV 项视图解码 | 通用（任意 tag 的 TLV 视图） | 解析一个完整 TLV 项并返回 `tag/len/buff` 视图。 |
| `BSL_ASN1_DecodePrimitiveItem` | Primitive 值转换 | BOOLEAN、INTEGER、ENUMERATED、BIT STRING、UTCTime、GeneralizedTime、BMPString | 将已知 tag 的 primitive value 转换为受支持的 C 基础结构。 |
| `BSL_ASN1_DecodeTemplate` | 模板化结构解码 | SEQUENCE、SET、SEQUENCE OF、SET OF、CHOICE、ANY（字段可含 INTEGER/OCTET STRING/OID 等） | 按模板批量解码复杂 ASN.1 结构（如 SEQUENCE/SET/嵌套）。 |
| `BSL_ASN1_DecodeListItem` | 列表结构解码 | SEQUENCE OF、SET OF | 解码 `SEQUENCE OF/SET OF` 类型且同层同tag的列表项。 |
| `BSL_ASN1_EncodeTemplate` | 模板化结构编码 | SEQUENCE、SET、SEQUENCE OF、SET OF、CHOICE、ANY（字段可含 INTEGER/OCTET STRING/OID 等） | 按模板将多个字段编码为 DER 输出缓冲。 |
| `BSL_ASN1_EncodeListItem` | 列表结构编码 | SEQUENCE OF、SET OF | 编码 `SEQUENCE OF/SET OF` 列表结构。 |
| `BSL_ASN1_EncodeLimb` | 整数原语编码 | INTEGER、ENUMERATED | 将 `uint64_t` 小正整数编码为 `INTEGER/ENUMERATED` 的 TLV结构体。 |
| `BSL_ASN1_GetEncodeLen` | DER 长度计算 | 通用（适用于任意 ASN.1 类型的长度计算） | 根据 value 长度计算 DER 总长度（`T+L+V`）。 |

按 ASN.1 基础类型反查接口

| ASN.1 基础类型 | 直接支持接口 | 说明 |
| --- | --- | --- |
| INTEGER / ENUMERATED | `BSL_ASN1_DecodePrimitiveItem`、`BSL_ASN1_EncodeLimb`、`BSL_ASN1_DecodeItem`、`BSL_ASN1_DecodeTemplate`、`BSL_ASN1_EncodeTemplate` | 既可走 primitive 直接转化，也可走 TLV/模板路径。 |
| OCTET STRING | `BSL_ASN1_DecodeTagLen`、`BSL_ASN1_DecodeItem`、`BSL_ASN1_DecodeTemplate`、`BSL_ASN1_EncodeTemplate` | `DecodePrimitiveItem` 不直接转 OCTET STRING 到专用 C 结构。 |
| SEQUENCE / SET | `BSL_ASN1_DecodeTemplate`、`BSL_ASN1_EncodeTemplate`、`BSL_ASN1_DecodeItem` | 复杂结构主要走模板接口。 |
| SEQUENCE OF / SET OF | `BSL_ASN1_DecodeListItem`、`BSL_ASN1_EncodeListItem`、`BSL_ASN1_DecodeTemplate`、`BSL_ASN1_EncodeTemplate` | 列表结构可走专用 list 接口或模板接口。 |
| OBJECT IDENTIFIER (OID) | `BSL_ASN1_DecodeTagLen`、`BSL_ASN1_DecodeItem`、`BSL_ASN1_DecodeTemplate`、`BSL_ASN1_EncodeTemplate` | 通过 TLV/模板获得或写入 OID 字段；不在 `DecodePrimitiveItem` 的直接转化分支中。 |
| BOOLEAN / BIT STRING / UTCTime / GeneralizedTime / BMPString | `BSL_ASN1_DecodePrimitiveItem`（解码） + `BSL_ASN1_DecodeItem`/模板接口 | Primitive 类型可直接解码为对应 C 结构。 |

> 下文按“函数目的 → 参数语义 → 限制 → 示例”对每个 API 做详细拆解。

### 3.1 `BSL_ASN1_DecodeTagLen`

**接口分类**
- TLV 头解析接口。

**对应 ASN.1 基础类型**
- 通用（由 `tag` 指定，可用于 INTEGER、OCTET STRING、SEQUENCE、OID 等）。

**作用**
- 只解码 `T+L`，并把输入游标推进到 `V` 起点。

**参数语义**
- `tag`：期望 tag。
- `encode`/`encLen`：输入游标与剩余长度（会被原地更新）。
- `valLen`：输出 value 长度。

**适用场景**
- 你想先验证外层 tag 与长度，再决定是否继续深层解析。

**示例**
```c
uint8_t *cursor = der;
uint32_t remain = derLen;
uint32_t vlen = 0;
ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &cursor, &remain, &vlen);
```

### 3.2 `BSL_ASN1_DecodeItem`

**接口分类**
- 通用 TLV 项视图解码接口。

**对应 ASN.1 基础类型**
- 通用（任意 ASN.1 tag 对应的 TLV 项）。

**作用**
- 解一个 TLV 项，得到 `tag/len/buff` 三元组。

**参数语义**
- 输入：`encode`/`encLen`（会推进）。
- 输出：`asnItem`（通常 `buff` 指向输入流中的 value 区）。

**限制**
- 返回的是“视图”，不是深拷贝；原始 DER 缓冲必须保持有效。

### 3.3 `BSL_ASN1_DecodePrimitiveItem`

**接口分类**
- Primitive 值到 C 结构的定向转换接口。

**对应 ASN.1 基础类型**
- BOOLEAN、INTEGER、ENUMERATED、BIT STRING、UTCTime、GeneralizedTime、BMPString。

**作用**
- 把 `BSL_ASN1_Buffer`（已知 tag+value）转换成 C 侧基础结构。

**完整转化能力（源码 switch 分支）**

1. `BSL_ASN1_TAG_BOOLEAN` → `bool *`
2. `BSL_ASN1_TAG_INTEGER` / `BSL_ASN1_TAG_ENUMERATED` → `int *`
3. `BSL_ASN1_TAG_BITSTRING` → `BSL_ASN1_BitString *`
4. `BSL_ASN1_TAG_UTCTIME` / `BSL_ASN1_TAG_GENERALIZEDTIME` → `BSL_TIME *`
5. `BSL_ASN1_TAG_BMPSTRING` → `BSL_ASN1_Buffer *`（函数内部分配输出缓冲）

**不能做的事（重点）**
- 不能直接转成 `char` / `char *`（除非你先按支持类型拿到缓冲后自行转换）。
- 不能直接转成 `float` / `double`。
- 对 `INTEGER/ENUMERATED`，该路径解析目标是 `int`，并且实现仅支持其定义范围内的正整数语义。
- 不在上述 switch 分支中的 tag（例如 OCTET STRING、UTF8String 等）会返回失败。

**示例（INTEGER）**
```c
BSL_ASN1_Buffer item = { .tag = BSL_ASN1_TAG_INTEGER, .len = 2, .buff = (uint8_t[]){0x03, 0xE8} };
int v = 0;
ret = BSL_ASN1_DecodePrimitiveItem(&item, &v); // v == 1000
```

### 3.4 `BSL_ASN1_DecodeTemplate`

**接口分类**
- 模板化复杂结构解码接口。

**对应 ASN.1 基础类型**
- SEQUENCE、SET、SEQUENCE OF、SET OF、CHOICE、ANY（以及这些结构中的 INTEGER、OCTET STRING、OID 等字段）。

**作用**
- 按模板批量解复杂 ASN.1 结构（SEQUENCE/SET/嵌套）。

**能力**
- 支持 `OPTIONAL/DEFAULT`。
- 支持 `ANY/CHOICE`（通过回调）。

### 3.5 `BSL_ASN1_DecodeListItem`

**接口分类**
- 列表结构解码接口。

**对应 ASN.1 基础类型**
- SEQUENCE OF、SET OF。

**作用**
- 解 `SEQUENCE OF / SET OF` 列表项（当前能力通常用于 1~2 层）。

### 3.6 `BSL_ASN1_EncodeTemplate`

**接口分类**
- 模板化复杂结构编码接口。

**对应 ASN.1 基础类型**
- SEQUENCE、SET、SEQUENCE OF、SET OF、CHOICE、ANY（以及这些结构中的 INTEGER、OCTET STRING、OID 等字段）。

**作用**
- 按模板把多个字段编码成 DER。

**输出语义**
- `encode` 为新分配内存，调用方负责释放。

### 3.7 `BSL_ASN1_EncodeListItem`

**接口分类**
- 列表结构编码接口。

**对应 ASN.1 基础类型**
- SEQUENCE OF、SET OF。

**作用**
- 编码 `SEQUENCE OF / SET OF`。

**注意**
- `SET OF` 的 DER 规范排序需调用方确认是否另行处理。

### 3.8 `BSL_ASN1_EncodeLimb`

**接口分类**
- 整数 primitive 编码接口。

**对应 ASN.1 基础类型**
- INTEGER、ENUMERATED。

**函数定位（你特别要求说明）**
- 该函数是“小正整数编码器”，输入是 `uint64_t limb`。

**函数原型语义**
- `int32_t BSL_ASN1_EncodeLimb(uint8_t tag, uint64_t limb, BSL_ASN1_Buffer *asn);`

**严格约束（来自实现）**
- `tag` 只能是：
  - `BSL_ASN1_TAG_INTEGER`
  - `BSL_ASN1_TAG_ENUMERATED`
- `limb` 是无符号整数输入（`uint64_t`）。
- 输出是该整数的 ASN.1 value 字节（`asn->buff` 内存由函数分配，调用方释放）。

**结论**
- `BSL_ASN1_EncodeLimb` 不是通用“任意类型编码器”，而是“`uint64_t` → INTEGER/ENUMERATED 内容缓冲”的专用工具。

**示例**
```c
BSL_ASN1_Buffer asn = {0};
ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)1000, &asn);
// asn.tag == INTEGER, asn.buff 指向 0x03 0xE8
free(asn.buff);
```

### 3.9 `BSL_ASN1_GetEncodeLen`

**接口分类**

- DER 长度计算辅助接口。

**对应 ASN.1 基础类型**
- 通用（任意 ASN.1 类型都需要 `T+L+V` 长度计算）。

**作用**
- 根据内容长度 `V` 计算 DER 的总长度 `T+L+V`。

---

## 4. 数据对实例映射（输入 C 数据 / 输出 Hex）

<!-- 说明：本节用于“直观对照”。其中模板与列表接口会受模板定义、tag、flags 影响，示例统一采用常见 DER 场景。 -->

### 4.1 `BSL_ASN1_DecodeTagLen`

| 项 | 数据 |
| --- | --- |
| 形参 | `tag, **encode, *encLen, *valLen` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `tag = BSL_ASN1_TAG_OCTETSTRING`<br>`*encode = 04 03 DE AD BE FF FF`（OCTET STRING + other）<br>`encLen = 7` |
| 输出 | `valLen=3`，`encLen = 5`，返回`BSL_SUCCESS` |
| 效果 | 本接口接收一串字节encode，这串字节的长度encLen和期望的标签tag，检验这串字节的标签跟tag相不相同，输出除了TL之外字节串剩余的长度encLen和V部分的长度valLen。 |

### 4.2 `BSL_ASN1_DecodeItem`

| 项 | 数据 |
| --- | --- |
| 形参 | `**encode, *encLen, *asnItem` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `*encode = 04 03 DE AD BE FF`<br>`*encLen = 6` |
| 输出 | `asnItem = {tag=0x04, len=3, buff->DE AD BE}`<br>`*encLen = 1`（剩余 `FF`） |
| 效果 | 从输入流中取出完整 TLV 项（T+L+V），并把游标推进到下一项起点。 |

### 4.3 `BSL_ASN1_DecodePrimitiveItem`

| 项 | 数据 |
| --- | --- |
| 形参 | `*asn, *decodeData` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `asn = {tag=BSL_ASN1_TAG_INTEGER, len=2, buff=03 E8}`<br>`decodeData = &out(int类型)` |
| 输出（C 数据） | `out = 1000` |
| 效果 | 根据 `asn.tag` 将 value 解析到目标 C 类型（如 `int/bool/BSL_TIME/BSL_ASN1_BitString`）。 |

### 4.4 `BSL_ASN1_DecodeTemplate`

| 项 | 数据 |
| --- | --- |
| 形参 | `*templ, decTemlCb, **encode, *encLen, *asnArr, arrNum` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `*encode = 30 07 02 01 05 04 02 DE AD`<br>`*encLen = 9`<br>`templ` 描述 `SEQUENCE{INTEGER,OCTET STRING}`<br>`decTemlCb = NULL`（本例没有 ANY/CHOICE，不需要回调函数来解析）<br>`arrNum = 2`（本例期望输出 2 个叶子字段） |
| 输出（C 数据） | `asnArr[0] = {tag=INTEGER, len=1, buff->05}`<br>`asnArr[1] = {tag=OCTETSTRING, len=2, buff->DE AD}`<br>`*encLen = 0`（本例正好消费完） |
| 关键参数解释 | `asnArr`：解码输出数组，每个元素是一个 `BSL_ASN1_Buffer` 视图。<br>`arrNum`：`asnArr` 可写入容量（即期望接收的项数），arrNum小于encode中的项数会报overflow。<br>`decTemlCb`：仅在模板里出现 `ANY/CHOICE` 时用于“取真实 tag / 校验 choice 分支”；普通模板可传 `NULL`。 |
| 效果 | 按模板层级批量解码嵌套结构，把每个模板字段映射到 `asnArr`，并同步推进 `encode/encLen`。 |

### 4.5 `BSL_ASN1_DecodeListItem`

| 项 | 数据 |
| --- | --- |
| 形参 | `*param, *asn, parseListItemCb, cbParam, *list` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `asn = {tag=SEQUENCE, len=13, buff=30 06 02 01 01 02 01 02 30 03 02 01 03}`<br>`param->layer=2`，`param->expTag[0]=SEQUENCE`，`param->expTag[1]=INTEGER` |
| 输出（C 数据） | `list` 是 `BSL_ASN1_List`（即 `BslList`）链表；每个节点是 `BslListNode{prev,next,data}`，其中 `data` 的具体结构由 `parseListItemCb` 决定。 |
| 关键参数解释 | `param` 用来定义“列表怎么拆”：<br>`param->layer` 表示列表嵌套层数（当前实现最多 2 层）。<br>`param->expTag[0]` 是第一层元素期望 tag（本例为 `SEQUENCE`）。<br>`param->expTag[1]` 是第二层元素期望 tag（本例为 `INTEGER`）。 |
| 效果 | 解析 `SEQUENCE OF/SET OF` 列表值区，逐元素做 tag/len 校验并回调转换。 |


先明确三点：
- `asn.tag` 是外层容器类型（`SEQUENCE OF` 或 `SET OF` 的外层 tag）。
- `asn.buff` 指向外层容器的 value 区，不含外层容器自己的 `T+L`。
- `expTag[i]` 校验的是“第 i+1 层元素”的 tag，不包括外层容器 tag。

以首表示例为例：
- `asn = {tag=SEQUENCE, len=13, buff=30 06 02 01 01 02 01 02 30 03 02 01 03}`
- `layer=2, expTag[0]=SEQUENCE, expTag[1]=INTEGER`

层级与字节对应关系：

| 字节片段 | 层级归属 | 使用的 `expTag` | 回调收到的 `layer` |
| --- | --- | --- | --- |
| `30 06 02 01 01 02 01 02` | 第 1 层元素（外层 value 区中的直接子项） | `expTag[0]` | `1` |
| `30 03 02 01 03` | 第 1 层元素（外层 value 区中的直接子项） | `expTag[0]` | `1` |
| `02 01 01` | 第 2 层元素（第 1 个 `SEQUENCE` 的子项） | `expTag[1]` | `2` |
| `02 01 02` | 第 2 层元素（第 1 个 `SEQUENCE` 的子项） | `expTag[1]` | `2` |
| `02 01 03` | 第 2 层元素（第 2 个 `SEQUENCE` 的子项） | `expTag[1]` | `2` |

能力边界（重点）：只能处理“同层单一 tag”

- 第一层所有元素必须是同一个 tag（都等于 `expTag[0]`）。
- 若 `layer=2`，第二层所有元素也必须是同一个 tag（都等于 `expTag[1]`）。
- 如果同一层出现多种 tag（例如第一层同时有 `SEQUENCE` 和 `SET`，或第二层同时有 `INTEGER` 和 `OCTET STRING`），会在 tag 校验处返回不匹配错误。
- 因此，异构同层场景应改用“外层逐项 `DecodeItem` + 按 tag 分支”或在回调中再用 `DecodeTemplate` 做二次解包。

### 4.6 `BSL_ASN1_EncodeTemplate`

| 项 | 数据 |
| --- | --- |
| 形参 | `*templ, *asnArr, arrNum, **encode, *encLen` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `asnArr = [{INTEGER,01,05},{OCTETSTRING,02,DE AD}]`<br>`templ = {{SEQUENCE,0,0},{INTEGER,0,1},{OCT STRING,0,1}} ` |
| 输出（C 数据） | `*encode = 30 07 02 01 05 04 02 DE AD`<br>`*encLen = 9` |
| 效果 | 按模板把多字段（含嵌套构造类型）编码为一段完整 DER。 |

### 4.7 `BSL_ASN1_EncodeListItem`

| 项 | 数据 |
| --- | --- |
| 形参 | `tag, listSize, *templ, *asnArr, arrNum, *out` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `tag=BSL_ASN1_TAG_SEQUENCE`<br>`listSize=3`<br>`asnArr = {INTEGER(1),INTEGER(2),INTEGER(3)}` |
| 输出（C 数据） | `out={tag=SEQUENCE\|CONSTRUCTED,len=11, buff=...}`<br>即`out = 30 09 02 01 01 02 01 02 02 01 03` |
| 效果 | 将多个同构元素编码成 `SEQUENCE OF/SET OF` 的 value，并返回外层构造项。 |

### 4.8 `BSL_ASN1_EncodeLimb`

| 项 | 数据 |
| --- | --- |
| 形参 | `tag, limb, *asn` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `tag=BSL_ASN1_TAG_INTEGER`，`limb=1000`，`asn->buff==NULL` |
| 输出（C 数据） | `asn={tag=INTEGER, len=2, buff->03 E8}` |
| 效果 | 将 `uint64_t` 小正整数（例子中为limb=1000）编码为 INTEGER/ENUMERATED 的BSL_ASN1_Buffer结构体。只能接收INTEGER 和 ENUMERATED的tag。 |

### 4.9 `BSL_ASN1_GetEncodeLen`

| 项 | 数据 |
| --- | --- |
| 形参 | `contentLen, *encodeLen` |
| 返回值类型 | `int32_t`（`BSL_SUCCESS` 或错误码） |
| 输入 | `contentLen=2` |
| 输出（C 数据） | `*encodeLen=4` |
| 对应 Hex 示例 | `02 02 03 E8`（`T+L+V` 总长度为 4） |
| 效果 | 根据内容长度计算 DER 总长度（1字节Tag + Len字段 + Value）。 |

---

## 5. 最小调用代码速查（每个核心接口一段）

### 5.1 `BSL_ASN1_DecodeTagLen`

```c
uint8_t der[] = {0x04, 0x03, 0xDE, 0xAD, 0xBE};
uint8_t *p = der;
uint32_t left = sizeof(der);
uint32_t vLen = 0;
int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &p, &left, &vLen);
// ret==0, vLen==3, p 指向 0xDE
```

### 5.2 `BSL_ASN1_DecodeItem`

```c
uint8_t der[] = {0x04, 0x03, 0xDE, 0xAD, 0xBE};
uint8_t *p = der;
uint32_t left = sizeof(der);
BSL_ASN1_Buffer item = {0};
int32_t ret = BSL_ASN1_DecodeItem(&p, &left, &item);
// ret==0, item.tag==BSL_ASN1_TAG_OCTETSTRING, item.len==3, item.buff[0]==0xDE
```

### 5.3 `BSL_ASN1_DecodePrimitiveItem`

```c
uint8_t v[] = {0x03, 0xE8}; // 1000
BSL_ASN1_Buffer item = { BSL_ASN1_TAG_INTEGER, 2, v };
int out = 0;
int32_t ret = BSL_ASN1_DecodePrimitiveItem(&item, &out);
// ret==0, out==1000
```

### 5.4 `BSL_ASN1_DecodeTemplate`

```c
// 示例语义: SEQUENCE { INTEGER a, OCTET STRING b }
// 注意：DecodeTemplate 输出为 BSL_ASN1_Buffer 数组（与模板项一一对应）。
uint8_t der[] = {0x30,0x07,0x02,0x01,0x05,0x04,0x02,0xDE,0xAD};
uint8_t *p = der;
uint32_t left = sizeof(der);
BSL_ASN1_Buffer outArr[3] = {0}; // 例如: [SEQUENCE, INTEGER, OCTET STRING]
int32_t ret = BSL_ASN1_DecodeTemplate(&g_mySeqTempl, NULL, &p, &left, outArr, 3);
// ret==0, outArr[1] 为 INTEGER, outArr[2] 为 OCTET STRING
```

### 5.5 `BSL_ASN1_DecodeListItem`

```c
// 示例语义: SEQUENCE OF SEQUENCE OF INTEGER {{1,2},{3}}
uint8_t listVal[] = {
  0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02,
  0x30,0x03,0x02,0x01,0x03
}; // 不含最外层 SEQUENCE 头
BSL_ASN1_Buffer asn = {
  .tag = BSL_ASN1_TAG_SEQUENCE,
  .len = sizeof(listVal),
  .buff = listVal,
};
uint8_t expTag[2] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_TAG_INTEGER};
BSL_ASN1_DecodeListParam param = {.layer = 2, .expTag = expTag};
BSL_ASN1_List outList = {0};
int32_t ret = BSL_ASN1_DecodeListItem(&param, &asn, ParseIntNodeCb, NULL, &outList);
// ret==0, 回调可收到 layer=1 的内层SEQUENCE节点和 layer=2 的INTEGER节点
```

```c
// 补充示例语义: SET OF SEQUENCE { INTEGER, OCTET STRING }
// 注意：二层DecodeListItem无法直接表达异构第二层（INTEGER + OCTET STRING）。
// 推荐：第一层按SEQUENCE拆分，再在回调里用DecodeTemplate解析每个元素。
uint8_t setVal[] = {
  0x30,0x06,0x02,0x01,0x01,0x04,0x01,0xAA,
  0x30,0x06,0x02,0x01,0x02,0x04,0x01,0xBB
}; // 不含最外层 SET 头
BSL_ASN1_Buffer setAsn = {
  .tag = BSL_ASN1_TAG_SET,
  .len = sizeof(setVal),
  .buff = setVal,
};
uint8_t setExpTag[1] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
BSL_ASN1_DecodeListParam setParam = {.layer = 1, .expTag = setExpTag};
BSL_ASN1_List outSetList = {0};
int32_t ret2 = BSL_ASN1_DecodeListItem(&setParam, &setAsn, ParseSeqNodeThenDecodeTemplateCb, NULL, &outSetList);
// ret2==0, 每个SEQUENCE元素由回调二次解析成 {INTEGER, OCTET STRING}
```

### 5.6 `BSL_ASN1_EncodeTemplate`

```c
// 示例语义: SEQUENCE { INTEGER a, OCTET STRING b }
BSL_ASN1_Buffer asnArr[2] = {
  {BSL_ASN1_TAG_INTEGER, 1, (uint8_t[]){0x05}},
  {BSL_ASN1_TAG_OCTETSTRING, 2, (uint8_t[]){0xDE, 0xAD}},
};

uint8_t *der = NULL;
uint32_t derLen = 0;
int32_t ret = BSL_ASN1_EncodeTemplate(&g_mySeqTempl, asnArr, 2, &der, &derLen);
// 期望 der: 30 07 02 01 05 04 02 DE AD
BSL_SAL_Free(der);
```

### 5.7 `BSL_ASN1_EncodeListItem`

```c
// 示例语义: SEQUENCE OF INTEGER {1,2,3}
BSL_ASN1_Buffer elems[3] = {
  {BSL_ASN1_TAG_INTEGER, 1, (uint8_t[]){0x01}},
  {BSL_ASN1_TAG_INTEGER, 1, (uint8_t[]){0x02}},
  {BSL_ASN1_TAG_INTEGER, 1, (uint8_t[]){0x03}},
};
BSL_ASN1_TemplateItem itemTemplItem[] = {
  {BSL_ASN1_TAG_INTEGER, 0, 0},
};
BSL_ASN1_Template itemTempl = {itemTemplItem, 1};
BSL_ASN1_Buffer out = {0};
int32_t ret = BSL_ASN1_EncodeListItem(BSL_ASN1_TAG_SEQUENCE, 3, &itemTempl, elems, 3, &out);
// out.buff 期望: 30 09 02 01 01 02 01 02 02 01 03
BSL_SAL_Free(out.buff);
```

### 5.8 `BSL_ASN1_EncodeLimb`

```c
BSL_ASN1_Buffer asn = {0};
int32_t ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, 1000, &asn);
// ret==0, asn.len==2, asn.buff: 03 E8
BSL_SAL_Free(asn.buff);
```

### 5.9 `BSL_ASN1_GetEncodeLen`

```c
uint32_t totalLen = 0;
int32_t ret = BSL_ASN1_GetEncodeLen(2, &totalLen);
// ret==0, totalLen==4，对应 TLV: 02 02 03 E8
```

---

## 6. 嵌套结构构建指南（通过 Sequence 复现证书复杂结构）

本节内容：演示如何把多个基础类型（INTEGER、OID、UTCTime/GeneralizedTime、BIT STRING 等）按层级嵌套成证书风格结构。

### 6.1 构建思路

可先抽象为如下结构：

```asn1
MiniTBSCertificate ::= SEQUENCE {
  version         [0] EXPLICIT INTEGER DEFAULT 0,
  serialNumber    INTEGER,
  signature       SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  NULL
  },
  validity        SEQUENCE {
    notBefore   UTCTime,
    notAfter    GeneralizedTime
  },
  subjectPKI      SEQUENCE {
    algorithm   SEQUENCE {
      algorithm OBJECT IDENTIFIER,
      parameters NULL
    },
    subjectPublicKey BIT STRING
  }
}
```

对应到 `BSL_ASN1_TemplateItem` 的关键点：
- 每进入一层 `SEQUENCE`，`depth` 增加 1。
- 容器节点用 `BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE`。
- 叶子节点放基础类型 tag（INTEGER/OID/UTCTIME/GENERALIZEDTIME/BITSTRING）。
- 可选或默认字段通过 `BSL_ASN1_FLAG_OPTIONAL`/`BSL_ASN1_FLAG_DEFAULT` 标注。
- 证书里常见 `[0] EXPLICIT` 可用 `BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0`。

### 6.2 证书风格 Sequence 嵌套模板示例

```c
enum {
  MINI_TBS_VER = 0,
  MINI_TBS_SERIAL,
  MINI_TBS_SIGALG_OID,
  MINI_TBS_SIGALG_NULL,
  MINI_TBS_NOT_BEFORE,
  MINI_TBS_NOT_AFTER,
  MINI_TBS_SPKI_ALG_OID,
  MINI_TBS_SPKI_ALG_NULL,
  MINI_TBS_SPK,
  MINI_TBS_ITEM_NUM
};

static BSL_ASN1_TemplateItem g_miniTbsTemplItems[] = {
  // depth 0: MiniTBSCertificate ::= SEQUENCE
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},

  // version [0] EXPLICIT INTEGER DEFAULT 0
  {BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0, BSL_ASN1_FLAG_DEFAULT, 1},
    {BSL_ASN1_TAG_INTEGER, BSL_ASN1_FLAG_DEFAULT, 2},

  // serialNumber INTEGER
  {BSL_ASN1_TAG_INTEGER, 0, 1},

  // signature AlgorithmIdentifier ::= SEQUENCE {OID, NULL}
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
    {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
    {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_OPTIONAL, 2},

  // validity ::= SEQUENCE {UTCTime, GeneralizedTime}
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
    {BSL_ASN1_TAG_UTCTIME, 0, 2},
    {BSL_ASN1_TAG_GENERALIZEDTIME, 0, 2},

  // subjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE{OID, NULL}, subjectPublicKey BIT STRING }
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2},
      {BSL_ASN1_TAG_OBJECT_ID, 0, 3},
      {BSL_ASN1_TAG_NULL, BSL_ASN1_FLAG_OPTIONAL, 3},
    {BSL_ASN1_TAG_BITSTRING, 0, 2},
};

static BSL_ASN1_Template g_miniTbsTempl = {
  g_miniTbsTemplItems,
  sizeof(g_miniTbsTemplItems) / sizeof(g_miniTbsTemplItems[0])
};
```

### 6.3 输入数据装配（基础类型拼成嵌套结构）

```c
uint8_t ver = 2;                // v3 cert 对应 INTEGER 2
uint8_t serial[] = {0x01, 0x23, 0x45};
uint8_t sigOid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B}; // 1.2.840.113549.1.1.11
uint8_t spkiOid[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01}; // rsaEncryption
BSL_TIME notBefore = {.year=2026,.month=3,.day=23,.hour=10,.minute=0,.second=0};
BSL_TIME notAfter  = {.year=2031,.month=3,.day=23,.hour=10,.minute=0,.second=0};
uint8_t pubBits[] = {0x30,0x82,0x01,0x0A};
BSL_ASN1_BitString spk = {.buff=pubBits,.len=sizeof(pubBits),.unusedBits=0};

BSL_ASN1_Buffer asnArr[MINI_TBS_ITEM_NUM] = {
  {BSL_ASN1_TAG_INTEGER, 1, &ver},                       // [0] EXPLICIT INTEGER
  {BSL_ASN1_TAG_INTEGER, sizeof(serial), serial},        // serialNumber
  {BSL_ASN1_TAG_OBJECT_ID, sizeof(sigOid), sigOid},      // signature.algorithm
  {BSL_ASN1_TAG_NULL, 0, NULL},                          // signature.parameters
  {BSL_ASN1_TAG_UTCTIME, sizeof(BSL_TIME), (uint8_t *)&notBefore},
  {BSL_ASN1_TAG_GENERALIZEDTIME, sizeof(BSL_TIME), (uint8_t *)&notAfter},
  {BSL_ASN1_TAG_OBJECT_ID, sizeof(spkiOid), spkiOid},    // spki.algorithm.algorithm
  {BSL_ASN1_TAG_NULL, 0, NULL},                          // spki.algorithm.parameters
  {BSL_ASN1_TAG_BITSTRING, sizeof(BSL_ASN1_BitString), (uint8_t *)&spk},
};
```

### 6.4 编码与结果（输出 Hex 字节流）

```c
uint8_t *der = NULL;
uint32_t derLen = 0;
int32_t ret = BSL_ASN1_EncodeTemplate(&g_miniTbsTempl, asnArr, MINI_TBS_ITEM_NUM, &der, &derLen);
// ret == 0 时，der 即为嵌套 SEQUENCE 的完整 DER。输出形态示意：
// 30 ..                                ; MiniTBSCertificate
//    A0 03 02 01 02                    ; [0] EXPLICIT version = 2
//    02 03 01 23 45                    ; serialNumber
//    30 0D 06 09 2A864886F70D01010B 05 00   ; signature AlgorithmIdentifier
//    30 .. 17 0D YYMMDDHHMMSSZ 18 0F YYYYMMDDHHMMSSZ ; validity
//    30 .. 30 .. 06 .. 05 00 03 .. 00 <pubkey-bytes> ; subjectPublicKeyInfo

BSL_SAL_Free(der);
```

### 6.5 与真实证书编码的映射关系

- 真实证书里 `TBSCertificate`、`Certificate` 本质都是“外层 SEQUENCE + 多层子 SEQUENCE”。
- 你可以先把每个子结构（如 AlgorithmIdentifier、Name、Validity、SPKI）单独编码成 `BSL_ASN1_Buffer`，再作为父级 `SEQUENCE` 的输入项拼接。
- 仓库中的 `x509_cert` 编码路径就是这种“子块先编码，再在上层模板组装”的策略，适合复杂结构渐进构建与调试。

---

## 7. 内存管理机制（编码分配原则 + 解码偏移逻辑）

本节基于 `openhitls/bsl/asn1/src/bsl_asn1.c` 的实现行为，给出“谁分配、谁释放、游标如何移动”的统一规则。

### 7.1 编码缓冲区分配原则：静态 vs 动态

| 场景 | 典型接口 | 内存归属 | 分配方式 | 释放责任 |
| --- | --- | --- | --- | --- |
| 输入参数（业务数据） | `BSL_ASN1_EncodeTemplate` / `BSL_ASN1_EncodeListItem` / `BSL_ASN1_EncodeLimb` | 调用方 | 可用栈上、静态区或业务堆内存 | 调用方按自身生命周期管理 |
| 编码输出 DER 缓冲 | `BSL_ASN1_EncodeTemplate` 的 `*encode` | 接口分配 | `BSL_SAL_Calloc` | 调用方释放（`BSL_SAL_Free`） |
| 列表编码输出 value 缓冲 | `BSL_ASN1_EncodeListItem` 的 `out->buff` | 接口分配 | `BSL_SAL_Calloc` | 调用方释放（`BSL_SAL_Free`） |
| 小整数编码输出 value 缓冲 | `BSL_ASN1_EncodeLimb` 的 `asn->buff` | 接口分配 | `BSL_SAL_Calloc` | 调用方释放（`BSL_SAL_Free`） |
| 编码内部中间态 | `eItems`（编码项状态数组） | 接口内部 | `BSL_SAL_Calloc` | 接口内部统一回收 |
| 解码普通项 | `BSL_ASN1_DecodeItem` / `BSL_ASN1_DecodeTemplate` 输出的 `buff` | 输入 DER 视图 | 不分配新内存（浅拷贝） | 不单独释放；依赖原始 DER 缓冲生命周期 |
| 解码特殊项（BMPString） | `BSL_ASN1_DecodePrimitiveItem` | 接口分配 | `BSL_SAL_Malloc`（`ParseBMPString`） | 调用方释放 |

结论：
- 编码路径是“输出动态分配、输入由调用方提供”。
- 解码路径多数是“零拷贝视图”，只有少数类型转换（如 BMPString）会新分配。

### 7.2 编码时的实操规则

1. `EncodeTemplate` 要求 `*encode == NULL`，接口成功后返回新分配缓冲；失败时不会把半成品交给调用方。
2. `EncodeListItem` 要求 `out != NULL` 且 `out->buff == NULL`，防止覆盖已有指针。
3. `EncodeLimb` 要求 `asn != NULL` 且 `asn->buff == NULL`，成功后只产出 value，不含外层 tag/len。
4. 编码内部会先计算总长度，再一次性申请目标缓冲，避免多次扩容。

### 7.3 解码时的指针偏移计算逻辑（核心）

可把解码游标抽象为：
- `p`：当前字节指针（对应 `*encode`）
- `n`：剩余长度（对应 `*encLen`）

#### 7.3.1 `BSL_ASN1_DecodeTagLen`

输入：`[Tag][Len...][Value...]`

若 `Len` 字段占 `k` 字节，则头部消费量为：
$$
H = 1 + k
$$

更新规则：
$$
p' = p + H,
\quad
n' = n - H,
\quad
\operatorname{valLen} = |Value|
$$

注意：该接口不跨过 value，仅把游标推到 value 起点。

#### 7.3.2 `BSL_ASN1_DecodeItem`

在 `DecodeTagLen` 基础上再跨过 value：

$$
p' = p + H + |Value|,
\quad
n' = n - (H + |Value|)
$$

同时输出：
- `asnItem.tag = Tag`
- `asnItem.len = |Value|`
- `asnItem.buff = p + H`（指向原始输入里的 value 视图）

#### 7.3.3 `BSL_ASN1_DecodeTemplate`

模板解码有两层偏移控制：

1. 全局游标：`temp` / `tempLen`，表示整体剩余输入。
2. 层级边界：`layerEnd[depth]`，限制当前模板深度可消费范围。

每处理一个模板项时，先记录 `beforeTemp = temp`，调用内部解析后，按实际消费字节回写：

$$
\Delta = temp - beforeTemp,
\quad
tempLen = tempLen - \Delta
$$

对构造类型（SEQUENCE/SET），若不是 `HEADERONLY`，会记录子层结束位置：

$$
layerEnd[depth+1] = temp + asn.len
$$

这保证了“子节点只能在父节点 value 范围内推进游标”，不会越界吃到兄弟节点。

详细例子（把公式落到具体字节）

示例输入 DER：

```text
30 07 02 01 05 04 02 DE AD
```

语义：`SEQUENCE { INTEGER(5), OCTET STRING(DE AD) }`

示例模板：

```c
// idx0: SEQUENCE(depth=0)
// idx1: INTEGER(depth=1)
// idx2: OCTET STRING(depth=1)
```

初始状态：
- `temp` 指向 `30`
- `tempLen = 9`
- `layerEnd[0] = temp + 9`

步骤 1：处理 idx0（SEQUENCE, depth=0）
- 解析到 `SEQUENCE` 的 value 长度 `asn.len = 7`
- 头部消费 2 字节（`30 07`），所以 `temp` 前移到 `02`
- `beforeTemp` 到新 `temp` 的增量：`Δ = 2`
- 全局回写：`tempLen = 9 - 2 = 7`
- 因为是构造类型且非 `HEADERONLY`：
  $$
  layerEnd[1] = temp + asn.len = (指向 02) + 7 = 输入末尾
  $$

步骤 2：处理 idx1（INTEGER, depth=1）
- 当前层可消费边界由 `layerEnd[1]` 限定
- 解析 `02 01 05`，消费 3 字节
- `Δ = 3`，回写后：`tempLen = 7 - 3 = 4`
- `temp` 指向 `04`

步骤 3：处理 idx2（OCTET STRING, depth=1）
- 仍受 `layerEnd[1]` 约束
- 解析 `04 02 DE AD`，消费 4 字节
- `Δ = 4`，回写后：`tempLen = 4 - 4 = 0`
- `temp` 到达输入末尾

结果：
- `asnArr` 得到两个叶子视图：`INTEGER(05)`、`OCTET STRING(DE AD)`
- `tempLen=0` 说明模板与输入严格对齐消费完

这个例子体现了 7.3.3 的两个核心点：
1. 全局游标按每个模板项实际消费量 `Δ` 回写；
2. 子层解析始终受 `layerEnd[depth]` 边界限制，避免跨父节点 value 越界。

#### 7.3.4 `BSL_ASN1_DecodeListItem`

列表解析在循环中重复执行：
1. 读并校验每个元素 tag。
2. 解析元素 length。
3. 构造 `item = {tag, len, buff}`。
4. 执行 `buff += len; n -= len` 进入下一个元素。

本质上是“在 list 的 value 区间内做多次 `DecodeItem` 风格偏移”。

### 7.4 生命周期与常见坑

1. 解码输出多数是浅拷贝视图，原始 DER 缓冲释放后，这些 `buff` 指针立即失效。
2. `DecodePrimitiveItem(BMPSTRING)` 会分配新内存，必须单独释放，不能按“视图”处理。
3. 编码接口返回的动态缓冲必须使用同一内存域释放（建议统一 `BSL_SAL_Free`）。
4. `EncodeLimb` 仅生成 value，不含 TL；若要完整 TLV，需要再拼接 tag/len 或交给模板编码。

