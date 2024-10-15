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

#ifndef BSL_BYTES_H
#define BSL_BYTES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   convert uint8_t byte stream to uint16_t data
 *
 * @attention data cannot be empty
 *
 * @param   data [IN] uint8_t byte stream
 *
 * @return  uint16_t converted data
 */
static inline uint16_t BSL_ByteToUint16(const uint8_t *data)
{
    /** Byte 0 is shifted by 8 bits to the left, and byte 1 remains unchanged. uint16_t is obtained after OR */
    return ((uint16_t)data[0] << 8) | ((uint16_t)data[1]);
}

/**
 * @brief   convert uint16_t data to uint8_t byte stream
 *
 * @attention data cannot be empty
 *
 * @param   num [IN] data to be converted
 * @param   data [OUT] converted data
 */
static inline void BSL_Uint16ToByte(uint16_t num, uint8_t *data)
{
    /** convert to byte stream */
    data[0] = (uint8_t)(num >> 8);    // data is shifted rightwards by 8 bits and put in byte 0
    data[1] = (uint8_t)(num & 0xffu); // data AND 0xffu, put in byte 1
    return;
}

/**
 * @brief   convert uint8_t byte stream to uint24_t data
 *
 * @attention data cannot be empty
 *
 * @param   data [IN] uint8_t byte stream
 *
 * @return  uint24_t, converted data
 */
static inline uint32_t BSL_ByteToUint24(const uint8_t *data)
{
    /** Byte 0 is shifted left by 16 bits, byte 1 is shifted left by 8 bits, and byte 2 remains unchanged,
        uint24_t is obtained after the OR operation. */
    return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | ((uint32_t)data[2]);
}

/**
 * @brief   convert uint24_t data to uint8_t byte stream
 *
 * @attention data cannot be empty
 *
 * @param   num [IN] data to be converted
 * @param   data [OUT] converted data
 */
static inline void BSL_Uint24ToByte(uint32_t num, uint8_t *data)
{
    /** convert to byte stream */
    data[0] = (uint8_t)(num >> 16);   // data is shifted rightwards by 16 bits and put in byte 0
    data[1] = (uint8_t)(num >> 8);    // data is shifted rightwards by 8 bits and placed in byte 1
    data[2] = (uint8_t)(num & 0xffu); // data AND 0xffu, put in byte 2
    return;
}

/**
 * @brief   convert uint8_t byte stream to uint32_t data
 *
 * @attention data cannot be empty
 *
 * @param   data [IN]  uint8_t byte stream
 *
 * @return  uint32_t, converted data
 */
static inline uint32_t BSL_ByteToUint32(const uint8_t *data)
{
    /** Byte 0 is shifted leftward by 24 bits, byte 1 is shifted leftward by 16 bits,
        byte 2 is shifted leftward by 8 bits, and byte 3 remains unchanged, uint32_t is obtained after OR operation. */
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | ((uint32_t)data[3]);
}

/**
 * @brief   convert uint8_t byte stream to uint48_t data
 *
 * @attention data cannot be empty
 *
 * @param   data [IN]  uint8_t byte stream
 *
 * @return  uint48_t, converted data
 */
static inline uint64_t BSL_ByteToUint48(const uint8_t *data)
{
    /** Byte 0 is shifted leftward by 40 bits, byte 1 is shifted leftward by 32 bits,
        byte 2 is shifted leftward by 24 bits, byte 3 is shifted leftward by 16 bits,
        byte 4 is shifted leftward by 8 bits, and byte 5 remains unchanged, uint48_t is obtained after OR operation. */
    return ((uint64_t)data[0] << 40) | ((uint64_t)data[1] << 32) | ((uint64_t)data[2] << 24) |
        ((uint64_t)data[3] << 16) | ((uint64_t)data[4] << 8) | ((uint64_t)data[5]);
}

/**
 * @brief   convert uint48_t data to uint8_t byte stream
 *
 * @attention data cannot be empty
 *
 * @param   num [IN] data to be converted
 * @param   data [OUT] converted data
 */
static inline void BSL_Uint48ToByte(uint64_t num, uint8_t *data)
{
    /** convert to byte stream */
    data[0] = (uint8_t)(num >> 40);   // data is shifted rightwards by 40 bits and put in byte 0
    data[1] = (uint8_t)(num >> 32);   // data is shifted rightwards by 32 bits and put in byte 1
    data[2] = (uint8_t)(num >> 24);   // data is shifted rightwards by 24 bits and put in byte 2
    data[3] = (uint8_t)(num >> 16);   // data is shifted rightwards by 16 bits and put in byte 3
    data[4] = (uint8_t)(num >> 8);    // data is shifted rightwards by 8 bits and put in byte 4
    data[5] = (uint8_t)(num & 0xffu); // data AND 0xffu, put in byte 5
    return;
}

/**
 * @brief   convert uint8_t byte stream to uint64_t data
 *
 * @attention data cannot be empty
 *
 * @param   data [IN] uint8_t byte stream
 *
 * @return  uint32_t, converted data
 */
static inline uint64_t BSL_ByteToUint64(const uint8_t *data)
{
    /** Byte 0 is shifted leftward by 56 bits, byte 1 is shifted leftward by 48 bits,
        byte 2 is shifted leftward by 40 bits, byte 3 is shifted leftward by 32 bits,
        byte 4 is shifted leftward by 24 bits, byte 5 is shifted leftward by 16 bits,
        byte 6 is shifted leftward by 8 bits, and byte 7 remains unchanged, uint64_t is obtained after OR operation. */
    return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) | ((uint64_t)data[2] << 40) |
        ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
        ((uint64_t)data[6] << 8) | ((uint64_t)data[7]);
}

/**
 * @brief   convert uint32_t data to uint8_t byte stream
 *
 * @attention data cannot be empty
 *
 * @param   num [IN] data to be converted
 * @param   data [OUT] converted data
 */
static inline void BSL_Uint32ToByte(uint32_t num, uint8_t *data)
{
    /** convert to byte stream */
    data[0] = (uint8_t)(num >> 24);   // data is shifted rightwards by 24 bits and put in byte 0
    data[1] = (uint8_t)(num >> 16);   // data is shifted rightwards by 16 bits and put in byte 1
    data[2] = (uint8_t)(num >> 8);    // data is shifted rightwards by 8 bits and put in byte 2
    data[3] = (uint8_t)(num & 0xffu); // data AND 0xffu, put in byte 3
    return;
}

/**
 * @brief   convert uint64_t data to uint8_t byte stream
 *
 * @attention data cannot be empty
 *
 * @param   num [IN] data to be converted
 * @param   data [OUT] converted data
 */
static inline void BSL_Uint64ToByte(uint64_t num, uint8_t *data)
{
    /** convert to byte stream */
    data[0] = (uint8_t)(num >> 56);   // data is shifted rightwards by 56 bits and put in byte 0
    data[1] = (uint8_t)(num >> 48);   // data is shifted rightwards by 48 bits and put in byte 1
    data[2] = (uint8_t)(num >> 40);   // data is shifted rightwards by 40 bits and put in byte 2
    data[3] = (uint8_t)(num >> 32);   // data is shifted rightwards by 32 bits and put in byte 3
    data[4] = (uint8_t)(num >> 24);   // data is shifted rightwards by 24 bits and put in byte 4
    data[5] = (uint8_t)(num >> 16);   // data is shifted rightwards by 16 bits and put in byte 5
    data[6] = (uint8_t)(num >> 8);    // data is shifted rightwards by 8 bits and put in byte 6
    data[7] = (uint8_t)(num & 0xffu); // data AND 0xffu, put in byte 7
    return;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // BSL_BYTES_H
