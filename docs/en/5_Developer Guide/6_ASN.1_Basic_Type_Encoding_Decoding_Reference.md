# ASN.1 Basic Type Encoding/Decoding Cross-Reference

## 1. Objective and Scope

Main objectives of this document:

- Based on source code, provide a semantic walkthrough of the core ASN.1 interfaces under `openhitls/bsl/asn1`, including each interface's inputs, outputs, applicable scenarios, and boundary conditions.
- Build a mapping between ASN.1 base types and interface capabilities, so developers can quickly locate the proper encode/decode path for INTEGER, OCTET STRING, SEQUENCE, OID, and similar types.
- Add memory ownership and usage constraints for template encoding, list encoding, TLV-view decoding, and primitive conversion paths, so this can be used directly during development and debugging.

Source references:
- `openhitls/bsl/asn1/include/bsl_asn1_internal.h`
- `openhitls/bsl/asn1/src/bsl_asn1.c`

Note: The following "Core API Catalog" and "Detailed Semantic Breakdown" only cover core interfaces in the `bsl/asn1` directory.

---

## 2. Basic Data Structures

### 2.1 `BSL_ASN1_Buffer`
- Semantics: Unified container for one ASN.1 item (commonly used as the V view in TLV or as an encoding result).
- Fields:
  - `tag`: ASN.1 tag
  - `len`: value length
  - `buff`: pointer to the value bytes

### 2.2 `BSL_ASN1_BitString`
- Semantics: C representation of BIT STRING.
- Fields: `buff`, `len`, `unusedBits`.

### 2.3 `BSL_ASN1_TemplateItem / BSL_ASN1_Template`
- Semantics: Template-driven encoding/decoding for complex structures (SEQUENCE, SET, nested objects).
- Key fields: `tag`, `flags`, `depth`.

---

## 3. Detailed Semantic Breakdown of Core APIs

Core API catalog (interface category and ASN.1 type mapping)

| Core API | Interface Category | Mapped ASN.1 Base Type | One-line Summary |
| --- | --- | --- | --- |
| `BSL_ASN1_DecodeTagLen` | TLV header parsing | Generic (determined by input `tag`, e.g., INTEGER/OCTET STRING/SEQUENCE/OID) | Parses only TLV T+L and advances the cursor to V start. |
| `BSL_ASN1_DecodeItem` | TLV item view decode | Generic (TLV view for any tag) | Parses one complete TLV item and returns a `tag/len/buff` view. |
| `BSL_ASN1_DecodePrimitiveItem` | Primitive value conversion | BOOLEAN, INTEGER, ENUMERATED, BIT STRING, UTCTime, GeneralizedTime, BMPString | Converts a known-tag primitive value into supported C base structures. |
| `BSL_ASN1_DecodeTemplate` | Template-based structure decode | SEQUENCE, SET, SEQUENCE OF, SET OF, CHOICE, ANY (fields can contain INTEGER/OCTET STRING/OID, etc.) | Batch-decodes complex ASN.1 structures (e.g., SEQUENCE/SET/nested) using a template. |
| `BSL_ASN1_DecodeListItem` | List structure decode | SEQUENCE OF, SET OF | Decodes list items for `SEQUENCE OF/SET OF` with same-tag items at each layer. |
| `BSL_ASN1_EncodeTemplate` | Template-based structure encode | SEQUENCE, SET, SEQUENCE OF, SET OF, CHOICE, ANY (fields can contain INTEGER/OCTET STRING/OID, etc.) | Encodes multiple fields into a DER output buffer using a template. |
| `BSL_ASN1_EncodeListItem` | List structure encode | SEQUENCE OF, SET OF | Encodes list structures for `SEQUENCE OF/SET OF`. |
| `BSL_ASN1_EncodeLimb` | Integer primitive encode | INTEGER, ENUMERATED | Encodes a small positive `uint64_t` integer into an `INTEGER/ENUMERATED` TLV structure. |
| `BSL_ASN1_GetEncodeLen` | DER length calculation | Generic (applies to any ASN.1 type length calculation) | Computes DER total length (`T+L+V`) from value length. |

Reverse lookup by ASN.1 base type

| ASN.1 Base Type | Directly Supported Interfaces | Notes |
| --- | --- | --- |
| INTEGER / ENUMERATED | `BSL_ASN1_DecodePrimitiveItem`, `BSL_ASN1_EncodeLimb`, `BSL_ASN1_DecodeItem`, `BSL_ASN1_DecodeTemplate`, `BSL_ASN1_EncodeTemplate` | Supports both direct primitive conversion and TLV/template paths. |
| OCTET STRING | `BSL_ASN1_DecodeTagLen`, `BSL_ASN1_DecodeItem`, `BSL_ASN1_DecodeTemplate`, `BSL_ASN1_EncodeTemplate` | `DecodePrimitiveItem` does not directly convert OCTET STRING to a dedicated C structure. |
| SEQUENCE / SET | `BSL_ASN1_DecodeTemplate`, `BSL_ASN1_EncodeTemplate`, `BSL_ASN1_DecodeItem` | Complex structures primarily use template interfaces. |
| SEQUENCE OF / SET OF | `BSL_ASN1_DecodeListItem`, `BSL_ASN1_EncodeListItem`, `BSL_ASN1_DecodeTemplate`, `BSL_ASN1_EncodeTemplate` | List structures can use either dedicated list interfaces or template interfaces. |
| OBJECT IDENTIFIER (OID) | `BSL_ASN1_DecodeTagLen`, `BSL_ASN1_DecodeItem`, `BSL_ASN1_DecodeTemplate`, `BSL_ASN1_EncodeTemplate` | OID fields are obtained/written via TLV/template paths; not in direct-conversion branches of `DecodePrimitiveItem`. |
| BOOLEAN / BIT STRING / UTCTime / GeneralizedTime / BMPString | `BSL_ASN1_DecodePrimitiveItem` (decode) + `BSL_ASN1_DecodeItem`/template interfaces | Primitive types can be directly decoded to corresponding C structures. |

> The following sections break down each API by "purpose -> parameter semantics -> constraints -> example".

### 3.1 `BSL_ASN1_DecodeTagLen`

**Interface category**
- TLV header parsing interface.

**Mapped ASN.1 base type**
- Generic (controlled by `tag`, can be used for INTEGER, OCTET STRING, SEQUENCE, OID, etc.).

**Purpose**
- Decodes only `T+L` and advances the input cursor to the `V` start.

**Parameter semantics**
- `tag`: expected tag.
- `encode`/`encLen`: input cursor and remaining length (updated in place).
- `valLen`: output value length.

**Applicable scenario**
- Use this when you need to validate outer tag and length first, then decide whether to continue deeper parsing.

**Example**
```c
uint8_t *cursor = der;
uint32_t remain = derLen;
uint32_t vlen = 0;
ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &cursor, &remain, &vlen);
```

### 3.2 `BSL_ASN1_DecodeItem`

**Interface category**
- Generic TLV item-view decoding interface.

**Mapped ASN.1 base type**
- Generic (TLV item for any ASN.1 tag).

**Purpose**
- Decodes one TLV item and returns the `tag/len/buff` tuple.

**Parameter semantics**
- Input: `encode`/`encLen` (cursor advances).
- Output: `asnItem` (`buff` usually points into the input stream's value region).

**Constraint**
- Returns a view, not a deep copy; the source DER buffer must remain valid.

### 3.3 `BSL_ASN1_DecodePrimitiveItem`

**Interface category**
- Targeted conversion from primitive value to C structure.

**Mapped ASN.1 base type**
- BOOLEAN, INTEGER, ENUMERATED, BIT STRING, UTCTime, GeneralizedTime, BMPString.

**Purpose**
- Converts `BSL_ASN1_Buffer` (known tag + value) into a C-side base structure.

**Complete conversion capability (switch branches in source code)**

1. `BSL_ASN1_TAG_BOOLEAN` -> `bool *`
2. `BSL_ASN1_TAG_INTEGER` / `BSL_ASN1_TAG_ENUMERATED` -> `int *`
3. `BSL_ASN1_TAG_BITSTRING` -> `BSL_ASN1_BitString *`
4. `BSL_ASN1_TAG_UTCTIME` / `BSL_ASN1_TAG_GENERALIZEDTIME` -> `BSL_TIME *`
5. `BSL_ASN1_TAG_BMPSTRING` -> `BSL_ASN1_Buffer *` (output buffer is allocated internally)

**What it cannot do (important)**
- Cannot directly convert to `char` / `char *` (unless you first obtain a supported buffer type and convert it yourself).
- Cannot directly convert to `float` / `double`.
- For `INTEGER/ENUMERATED`, the target parse type is `int`, and the implementation only supports positive-integer semantics within the defined range.
- Tags outside the switch branches above (e.g., OCTET STRING, UTF8String) return failure.

**Example (INTEGER)**
```c
BSL_ASN1_Buffer item = { .tag = BSL_ASN1_TAG_INTEGER, .len = 2, .buff = (uint8_t[]){0x03, 0xE8} };
int v = 0;
ret = BSL_ASN1_DecodePrimitiveItem(&item, &v); // v == 1000
```

### 3.4 `BSL_ASN1_DecodeTemplate`

**Interface category**
- Template-based complex-structure decoding interface.

**Mapped ASN.1 base type**
- SEQUENCE, SET, SEQUENCE OF, SET OF, CHOICE, ANY (including fields such as INTEGER, OCTET STRING, OID inside those structures).

**Purpose**
- Batch-decodes complex ASN.1 structures (SEQUENCE/SET/nested) according to a template.

**Capabilities**
- Supports `OPTIONAL/DEFAULT`.
- Supports `ANY/CHOICE` (via callback).

### 3.5 `BSL_ASN1_DecodeListItem`

**Interface category**
- List-structure decoding interface.

**Mapped ASN.1 base type**
- SEQUENCE OF, SET OF.

**Purpose**
- Decodes `SEQUENCE OF / SET OF` list items (current capability typically used for 1-2 layers).

### 3.6 `BSL_ASN1_EncodeTemplate`

**Interface category**
- Template-based complex-structure encoding interface.

**Mapped ASN.1 base type**
- SEQUENCE, SET, SEQUENCE OF, SET OF, CHOICE, ANY (including fields such as INTEGER, OCTET STRING, OID inside those structures).

**Purpose**
- Encodes multiple fields into DER according to a template.

**Output semantics**
- `encode` points to newly allocated memory; the caller must release it.

### 3.7 `BSL_ASN1_EncodeListItem`

**Interface category**
- List-structure encoding interface.

**Mapped ASN.1 base type**
- SEQUENCE OF, SET OF.

**Purpose**
- Encodes `SEQUENCE OF / SET OF`.

**Note**
- For `SET OF`, DER-required sorting should be verified and handled by the caller if needed.

### 3.8 `BSL_ASN1_EncodeLimb`

**Interface category**
- Integer primitive encoding interface.

**Mapped ASN.1 base type**
- INTEGER, ENUMERATED.

**Function role (explicitly highlighted)**
- This function is a "small positive integer encoder"; input is `uint64_t limb`.

**Function prototype semantics**
- `int32_t BSL_ASN1_EncodeLimb(uint8_t tag, uint64_t limb, BSL_ASN1_Buffer *asn);`

**Strict constraints (from implementation)**
- `tag` can only be:
  - `BSL_ASN1_TAG_INTEGER`
  - `BSL_ASN1_TAG_ENUMERATED`
- `limb` is unsigned integer input (`uint64_t`).
- Output is the ASN.1 value bytes for that integer (`asn->buff` is allocated by this function and must be freed by the caller).

**Conclusion**
- `BSL_ASN1_EncodeLimb` is not a generic "encode any type" function. It is a dedicated helper for `uint64_t -> INTEGER/ENUMERATED` value buffer encoding.

**Example**
```c
BSL_ASN1_Buffer asn = {0};
ret = BSL_ASN1_EncodeLimb(BSL_ASN1_TAG_INTEGER, (uint64_t)1000, &asn);
// asn.tag == INTEGER, asn.buff points to 0x03 0xE8
free(asn.buff);
```

### 3.9 `BSL_ASN1_GetEncodeLen`

**Interface category**

- DER length calculation helper interface.

**Mapped ASN.1 base type**
- Generic (every ASN.1 type may need `T+L+V` length calculation).

**Purpose**
- Computes DER total length `T+L+V` from content length `V`.

---

## 4. Data-to-Example Mapping (Input C Data / Output Hex)

<!-- Note: This section is for visual cross-reference. Template and list interfaces depend on template definitions, tags, and flags. Examples here use common DER scenarios. -->

### 4.1 `BSL_ASN1_DecodeTagLen`

| Item | Data |
| --- | --- |
| Parameters | `tag, **encode, *encLen, *valLen` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `tag = BSL_ASN1_TAG_OCTETSTRING`<br>`*encode = 04 03 DE AD BE FF FF` (OCTET STRING + other)<br>`encLen = 7` |
| Output | `valLen=3`, `encLen = 5`, returns `BSL_SUCCESS` |
| Effect | This API takes byte stream `encode`, its length `encLen`, and expected `tag`; verifies whether the incoming tag matches, and outputs remaining length after TL plus value length `valLen`. |

### 4.2 `BSL_ASN1_DecodeItem`

| Item | Data |
| --- | --- |
| Parameters | `**encode, *encLen, *asnItem` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `*encode = 04 03 DE AD BE FF`<br>`*encLen = 6` |
| Output | `asnItem = {tag=0x04, len=3, buff->DE AD BE}`<br>`*encLen = 1` (remaining `FF`) |
| Effect | Extracts one complete TLV item (T+L+V) from the input stream and advances the cursor to the next item start. |

### 4.3 `BSL_ASN1_DecodePrimitiveItem`

| Item | Data |
| --- | --- |
| Parameters | `*asn, *decodeData` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `asn = {tag=BSL_ASN1_TAG_INTEGER, len=2, buff=03 E8}`<br>`decodeData = &out (int type)` |
| Output (C data) | `out = 1000` |
| Effect | Parses value into target C type based on `asn.tag` (e.g., `int/bool/BSL_TIME/BSL_ASN1_BitString`). |

### 4.4 `BSL_ASN1_DecodeTemplate`

| Item | Data |
| --- | --- |
| Parameters | `*templ, decTemlCb, **encode, *encLen, *asnArr, arrNum` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `*encode = 30 07 02 01 05 04 02 DE AD`<br>`*encLen = 9`<br>`templ` describes `SEQUENCE{INTEGER,OCTET STRING}`<br>`decTemlCb = NULL` (no ANY/CHOICE in this example, so no callback is required)<br>`arrNum = 2` (this example expects 2 leaf fields) |
| Output (C data) | `asnArr[0] = {tag=INTEGER, len=1, buff->05}`<br>`asnArr[1] = {tag=OCTETSTRING, len=2, buff->DE AD}`<br>`*encLen = 0` (fully consumed in this example) |
| Key parameter explanation | `asnArr`: decode output array; each element is a `BSL_ASN1_Buffer` view.<br>`arrNum`: writable capacity of `asnArr` (expected item count). Overflow is reported if `arrNum` is smaller than decoded items.<br>`decTemlCb`: only used when `ANY/CHOICE` appears in template, for real tag resolution/choice-branch checking; can be `NULL` for normal templates. |
| Effect | Batch-decodes nested structure by template hierarchy, maps each template field to `asnArr`, and advances `encode/encLen` in sync. |

### 4.5 `BSL_ASN1_DecodeListItem`

| Item | Data |
| --- | --- |
| Parameters | `*param, *asn, parseListItemCb, cbParam, *list` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `asn = {tag=SEQUENCE, len=13, buff=30 06 02 01 01 02 01 02 30 03 02 01 03}`<br>`param->layer=2`, `param->expTag[0]=SEQUENCE`, `param->expTag[1]=INTEGER` |
| Output (C data) | `list` is a `BSL_ASN1_List` (i.e., `BslList`) linked list; each node is `BslListNode{prev,next,data}` and the concrete shape of `data` is defined by `parseListItemCb`. |
| Key parameter explanation | `param` defines "how to split the list":<br>`param->layer` indicates nesting levels (current implementation supports at most 2).<br>`param->expTag[0]` is expected tag for first-level elements (SEQUENCE in this example).<br>`param->expTag[1]` is expected tag for second-level elements (INTEGER in this example). |
| Effect | Parses `SEQUENCE OF/SET OF` value area, validates tag/len item by item, and converts via callback. |

First, clarify three points:
- `asn.tag` is the outer container type tag (`SEQUENCE OF` or `SET OF`).
- `asn.buff` points to the outer container's value area, excluding the outer container's own `T+L`.
- `expTag[i]` validates the tag of the element at layer `i+1`; it does not include the outer container tag.

Using the table example above:
- `asn = {tag=SEQUENCE, len=13, buff=30 06 02 01 01 02 01 02 30 03 02 01 03}`
- `layer=2, expTag[0]=SEQUENCE, expTag[1]=INTEGER`

Layer-to-byte mapping:

| Byte Segment | Layer Ownership | `expTag` Used | `layer` Received by Callback |
| --- | --- | --- | --- |
| `30 06 02 01 01 02 01 02` | Layer-1 element (direct child item in outer value area) | `expTag[0]` | `1` |
| `30 03 02 01 03` | Layer-1 element (direct child item in outer value area) | `expTag[0]` | `1` |
| `02 01 01` | Layer-2 element (child of the first `SEQUENCE`) | `expTag[1]` | `2` |
| `02 01 02` | Layer-2 element (child of the first `SEQUENCE`) | `expTag[1]` | `2` |
| `02 01 03` | Layer-2 element (child of the second `SEQUENCE`) | `expTag[1]` | `2` |

Capability boundary (important): only supports "single tag per layer"

- All first-layer elements must use the same tag (all equal to `expTag[0]`).
- If `layer=2`, all second-layer elements must also use the same tag (all equal to `expTag[1]`).
- If mixed tags appear in the same layer (e.g., first layer mixes `SEQUENCE` and `SET`, or second layer mixes `INTEGER` and `OCTET STRING`), tag check returns mismatch.
- For heterogeneous same-layer scenarios, use "outer-item-by-item `DecodeItem` + tag-based branching" or perform second-stage unpacking with `DecodeTemplate` inside callback.

### 4.6 `BSL_ASN1_EncodeTemplate`

| Item | Data |
| --- | --- |
| Parameters | `*templ, *asnArr, arrNum, **encode, *encLen` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `asnArr = [{INTEGER,01,05},{OCTETSTRING,02,DE AD}]`<br>`templ = {{SEQUENCE,0,0},{INTEGER,0,1},{OCT STRING,0,1}}` |
| Output (C data) | `*encode = 30 07 02 01 05 04 02 DE AD`<br>`*encLen = 9` |
| Effect | Encodes multiple fields (including nested constructed types) into one complete DER block by template. |

### 4.7 `BSL_ASN1_EncodeListItem`

| Item | Data |
| --- | --- |
| Parameters | `tag, listSize, *templ, *asnArr, arrNum, *out` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `tag=BSL_ASN1_TAG_SEQUENCE`<br>`listSize=3`<br>`asnArr = {INTEGER(1),INTEGER(2),INTEGER(3)}` |
| Output (C data) | `out={tag=SEQUENCE|CONSTRUCTED,len=11, buff=...}`<br>i.e. `out = 30 09 02 01 01 02 01 02 02 01 03` |
| Effect | Encodes multiple homogeneous elements into `SEQUENCE OF/SET OF` value and returns outer constructed item. |

### 4.8 `BSL_ASN1_EncodeLimb`

| Item | Data |
| --- | --- |
| Parameters | `tag, limb, *asn` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `tag=BSL_ASN1_TAG_INTEGER`, `limb=1000`, `asn->buff==NULL` |
| Output (C data) | `asn={tag=INTEGER, len=2, buff->03 E8}` |
| Effect | Encodes a small positive `uint64_t` integer (1000 in this example) into a `BSL_ASN1_Buffer` for INTEGER/ENUMERATED. Only INTEGER and ENUMERATED tags are accepted. |

### 4.9 `BSL_ASN1_GetEncodeLen`

| Item | Data |
| --- | --- |
| Parameters | `contentLen, *encodeLen` |
| Return type | `int32_t` (`BSL_SUCCESS` or error code) |
| Input | `contentLen=2` |
| Output (C data) | `*encodeLen=4` |
| Corresponding Hex Example | `02 02 03 E8` (total `T+L+V` length is 4) |
| Effect | Computes DER total length from content length (1-byte Tag + Len field + Value). |

---

## 5. Minimal Call Snippets (One Per Core Interface)

### 5.1 `BSL_ASN1_DecodeTagLen`

```c
uint8_t der[] = {0x04, 0x03, 0xDE, 0xAD, 0xBE};
uint8_t *p = der;
uint32_t left = sizeof(der);
uint32_t vLen = 0;
int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &p, &left, &vLen);
// ret==0, vLen==3, p points to 0xDE
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
// Example semantics: SEQUENCE { INTEGER a, OCTET STRING b }
// Note: DecodeTemplate outputs a BSL_ASN1_Buffer array (one-to-one with template items).
uint8_t der[] = {0x30,0x07,0x02,0x01,0x05,0x04,0x02,0xDE,0xAD};
uint8_t *p = der;
uint32_t left = sizeof(der);
BSL_ASN1_Buffer outArr[3] = {0}; // e.g., [SEQUENCE, INTEGER, OCTET STRING]
int32_t ret = BSL_ASN1_DecodeTemplate(&g_mySeqTempl, NULL, &p, &left, outArr, 3);
// ret==0, outArr[1] is INTEGER, outArr[2] is OCTET STRING
```

### 5.5 `BSL_ASN1_DecodeListItem`

```c
// Example semantics: SEQUENCE OF SEQUENCE OF INTEGER {{1,2},{3}}
uint8_t listVal[] = {
  0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02,
  0x30,0x03,0x02,0x01,0x03
}; // Excludes outermost SEQUENCE header
BSL_ASN1_Buffer asn = {
  .tag = BSL_ASN1_TAG_SEQUENCE,
  .len = sizeof(listVal),
  .buff = listVal,
};
uint8_t expTag[2] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, BSL_ASN1_TAG_INTEGER};
BSL_ASN1_DecodeListParam param = {.layer = 2, .expTag = expTag};
BSL_ASN1_List outList = {0};
int32_t ret = BSL_ASN1_DecodeListItem(&param, &asn, ParseIntNodeCb, NULL, &outList);
// ret==0, callback can receive layer=1 inner SEQUENCE nodes and layer=2 INTEGER nodes
```

```c
// Supplemental example semantics: SET OF SEQUENCE { INTEGER, OCTET STRING }
// Note: two-layer DecodeListItem cannot directly express heterogeneous second layer (INTEGER + OCTET STRING).
// Recommended: split first layer by SEQUENCE, then parse each element with DecodeTemplate in callback.
uint8_t setVal[] = {
  0x30,0x06,0x02,0x01,0x01,0x04,0x01,0xAA,
  0x30,0x06,0x02,0x01,0x02,0x04,0x01,0xBB
}; // Excludes outermost SET header
BSL_ASN1_Buffer setAsn = {
  .tag = BSL_ASN1_TAG_SET,
  .len = sizeof(setVal),
  .buff = setVal,
};
uint8_t setExpTag[1] = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE};
BSL_ASN1_DecodeListParam setParam = {.layer = 1, .expTag = setExpTag};
BSL_ASN1_List outSetList = {0};
int32_t ret2 = BSL_ASN1_DecodeListItem(&setParam, &setAsn, ParseSeqNodeThenDecodeTemplateCb, NULL, &outSetList);
// ret2==0, each SEQUENCE element is second-stage parsed in callback into {INTEGER, OCTET STRING}
```

### 5.6 `BSL_ASN1_EncodeTemplate`

```c
// Example semantics: SEQUENCE { INTEGER a, OCTET STRING b }
BSL_ASN1_Buffer asnArr[2] = {
  {BSL_ASN1_TAG_INTEGER, 1, (uint8_t[]){0x05}},
  {BSL_ASN1_TAG_OCTETSTRING, 2, (uint8_t[]){0xDE, 0xAD}},
};

uint8_t *der = NULL;
uint32_t derLen = 0;
int32_t ret = BSL_ASN1_EncodeTemplate(&g_mySeqTempl, asnArr, 2, &der, &derLen);
// Expected der: 30 07 02 01 05 04 02 DE AD
BSL_SAL_Free(der);
```

### 5.7 `BSL_ASN1_EncodeListItem`

```c
// Example semantics: SEQUENCE OF INTEGER {1,2,3}
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
// Expected out.buff: 30 09 02 01 01 02 01 02 02 01 03
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
// ret==0, totalLen==4, corresponding TLV: 02 02 03 E8
```

---

## 6. Nested Structure Construction Guide (Recreating Certificate-like Complex Structures with Sequence)

This section demonstrates how to compose multiple base types (INTEGER, OID, UTCTime/GeneralizedTime, BIT STRING, etc.) into layered, certificate-style structures.

### 6.1 Construction Approach

You can first abstract the structure as follows:

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

Key mapping points to `BSL_ASN1_TemplateItem`:
- Every time you enter one `SEQUENCE` layer, increase `depth` by 1.
- For container nodes, use `BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE`.
- For leaf nodes, use base type tags (INTEGER/OID/UTCTIME/GENERALIZEDTIME/BITSTRING).
- Mark optional/default fields using `BSL_ASN1_FLAG_OPTIONAL`/`BSL_ASN1_FLAG_DEFAULT`.
- Common certificate `[0] EXPLICIT` can use `BSL_ASN1_CLASS_CTX_SPECIFIC | BSL_ASN1_TAG_CONSTRUCTED | 0`.

### 6.2 Certificate-style Nested Sequence Template Example

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

### 6.3 Input Data Assembly (Composing Nested Structures from Base Types)

```c
uint8_t ver = 2;                // v3 certificate corresponds to INTEGER 2
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

### 6.4 Encoding and Result (Output Hex Byte Stream)

```c
uint8_t *der = NULL;
uint32_t derLen = 0;
int32_t ret = BSL_ASN1_EncodeTemplate(&g_miniTbsTempl, asnArr, MINI_TBS_ITEM_NUM, &der, &derLen);
// When ret == 0, der is the complete DER for the nested SEQUENCE. Output shape example:
// 30 ..                                ; MiniTBSCertificate
//    A0 03 02 01 02                    ; [0] EXPLICIT version = 2
//    02 03 01 23 45                    ; serialNumber
//    30 0D 06 09 2A864886F70D01010B 05 00   ; signature AlgorithmIdentifier
//    30 .. 17 0D YYMMDDHHMMSSZ 18 0F YYYYMMDDHHMMSSZ ; validity
//    30 .. 30 .. 06 .. 05 00 03 .. 00 <pubkey-bytes> ; subjectPublicKeyInfo

BSL_SAL_Free(der);
```

### 6.5 Mapping to Real Certificate Encoding

- In real certificates, `TBSCertificate` and `Certificate` are essentially "outer SEQUENCE + multiple nested child SEQUENCE blocks".
- You can first encode each sub-structure (e.g., AlgorithmIdentifier, Name, Validity, SPKI) into `BSL_ASN1_Buffer`, then assemble them as input items of the parent `SEQUENCE`.
- The `x509_cert` encoding path in this repository follows this strategy: "encode sub-blocks first, then assemble them at upper template level", which is suitable for progressive construction/debugging of complex structures.

---

## 7. Memory Management Mechanism (Encoding Allocation Rules + Decoding Offset Logic)

This section summarizes unified rules for "who allocates, who frees, and how cursor moves" based on implementation behavior in `openhitls/bsl/asn1/src/bsl_asn1.c`.

### 7.1 Encoding Buffer Allocation Rules: Static vs Dynamic

| Scenario | Typical Interface | Memory Ownership | Allocation Method | Freeing Responsibility |
| --- | --- | --- | --- | --- |
| Input parameters (business data) | `BSL_ASN1_EncodeTemplate` / `BSL_ASN1_EncodeListItem` / `BSL_ASN1_EncodeLimb` | Caller | Stack/static/business-heap allowed | Caller manages lifecycle |
| Encoded DER output buffer | `*encode` of `BSL_ASN1_EncodeTemplate` | Interface-allocated | `BSL_SAL_Calloc` | Caller frees (`BSL_SAL_Free`) |
| List-encoding output value buffer | `out->buff` of `BSL_ASN1_EncodeListItem` | Interface-allocated | `BSL_SAL_Calloc` | Caller frees (`BSL_SAL_Free`) |
| Small-integer encoding output value buffer | `asn->buff` of `BSL_ASN1_EncodeLimb` | Interface-allocated | `BSL_SAL_Calloc` | Caller frees (`BSL_SAL_Free`) |
| Internal encoding intermediate state | `eItems` (encoding-item state array) | Interface internal | `BSL_SAL_Calloc` | Interface cleans up internally |
| Normal decoding items | `buff` from `BSL_ASN1_DecodeItem` / `BSL_ASN1_DecodeTemplate` | Input DER view | No new allocation (shallow view) | Not separately freed; tied to source DER lifetime |
| Special decoding item (BMPString) | `BSL_ASN1_DecodePrimitiveItem` | Interface-allocated | `BSL_SAL_Malloc` (`ParseBMPString`) | Caller frees |

Conclusion:
- Encoding path: outputs are dynamically allocated, inputs are provided by caller.
- Decoding path: mostly zero-copy views; only a few type conversions (such as BMPString) allocate new memory.

### 7.2 Practical Rules During Encoding

1. `EncodeTemplate` requires `*encode == NULL`; on success returns a newly allocated buffer. On failure it does not hand over partial products.
2. `EncodeListItem` requires `out != NULL` and `out->buff == NULL`, preventing overwrite of existing pointers.
3. `EncodeLimb` requires `asn != NULL` and `asn->buff == NULL`; on success it outputs value bytes only, without outer tag/len.
4. Internal encoding computes total length first, then allocates target buffer once, avoiding repeated reallocation.

### 7.3 Pointer Offset Logic During Decoding (Core)

The decode cursor can be abstracted as:
- `p`: current byte pointer (maps to `*encode`)
- `n`: remaining length (maps to `*encLen`)

#### 7.3.1 `BSL_ASN1_DecodeTagLen`

Input: `[Tag][Len...][Value...]`

If `Len` occupies `k` bytes, header consumption is:
$$
H = 1 + k
$$

Update rules:
$$
p' = p + H,
\quad
n' = n - H,
\quad
\operatorname{valLen} = |Value|
$$

Note: this interface does not move past value; it only advances to the value start.

#### 7.3.2 `BSL_ASN1_DecodeItem`

On top of `DecodeTagLen`, it further moves across value:

$$
p' = p + H + |Value|,
\quad
n' = n - (H + |Value|)
$$

Outputs at the same time:
- `asnItem.tag = Tag`
- `asnItem.len = |Value|`
- `asnItem.buff = p + H` (value view within original input)

#### 7.3.3 `BSL_ASN1_DecodeTemplate`

Template decoding uses two-layer offset control:

1. Global cursor: `temp` / `tempLen`, representing overall remaining input.
2. Layer boundary: `layerEnd[depth]`, limiting consumable range at current template depth.

For each template item, it records `beforeTemp = temp` first, then after internal parsing writes back actual consumed bytes:

$$
\Delta = temp - beforeTemp,
\quad
tempLen = tempLen - \Delta
$$

For constructed types (SEQUENCE/SET), if not `HEADERONLY`, child-layer end is recorded:

$$
layerEnd[depth+1] = temp + asn.len
$$

This guarantees that child nodes can only advance inside parent value range and cannot overrun into sibling nodes.

Detailed example (formulas mapped to concrete bytes)

Example input DER:

```text
30 07 02 01 05 04 02 DE AD
```

Semantics: `SEQUENCE { INTEGER(5), OCTET STRING(DE AD) }`

Example template:

```c
// idx0: SEQUENCE(depth=0)
// idx1: INTEGER(depth=1)
// idx2: OCTET STRING(depth=1)
```

Initial state:
- `temp` points to `30`
- `tempLen = 9`
- `layerEnd[0] = temp + 9`

Step 1: process idx0 (SEQUENCE, depth=0)
- Parse `SEQUENCE` value length: `asn.len = 7`
- Header consumes 2 bytes (`30 07`), so `temp` moves to `02`
- Increment from `beforeTemp` to new `temp`: `Δ = 2`
- Global write-back: `tempLen = 9 - 2 = 7`
- Since this is a constructed type and not `HEADERONLY`:
  $$
  layerEnd[1] = temp + asn.len = (pointing to 02) + 7 = end of input
  $$

Step 2: process idx1 (INTEGER, depth=1)
- Current consumable boundary is constrained by `layerEnd[1]`
- Parse `02 01 05`, consuming 3 bytes
- `Δ = 3`, write-back gives `tempLen = 7 - 3 = 4`
- `temp` points to `04`

Step 3: process idx2 (OCTET STRING, depth=1)
- Still constrained by `layerEnd[1]`
- Parse `04 02 DE AD`, consuming 4 bytes
- `Δ = 4`, write-back gives `tempLen = 4 - 4 = 0`
- `temp` reaches end of input

Result:
- `asnArr` gets two leaf views: `INTEGER(05)`, `OCTET STRING(DE AD)`
- `tempLen=0` indicates strict alignment and full consumption by template

This example highlights two core points in 7.3.3:
1. Global cursor writes back according to each template item's actual consumed bytes `Δ`.
2. Child-layer parsing is always bounded by `layerEnd[depth]`, preventing overflow beyond parent value range.

#### 7.3.4 `BSL_ASN1_DecodeListItem`

List parsing repeats the following inside a loop:
1. Read and validate each element tag.
2. Parse element length.
3. Build `item = {tag, len, buff}`.
4. Execute `buff += len; n -= len` to move to next element.

In essence, this is repeated `DecodeItem`-style offset movement inside the list value range.

### 7.4 Lifecycle and Common Pitfalls

1. Most decode outputs are shallow-copy views; once original DER buffer is released, those `buff` pointers become invalid immediately.
2. `DecodePrimitiveItem(BMPSTRING)` allocates new memory and must be freed separately; do not treat it as a view.
3. Dynamically allocated buffers returned by encode interfaces must be released in the same memory domain (recommended unified `BSL_SAL_Free`).
4. `EncodeLimb` generates value bytes only, without TL; if full TLV is needed, prepend tag/len manually or use template encoding.
