// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace spdm
{

/** @brief Encode binary data as a Base64 string.
 *
 *  @param data  Input bytes to encode.
 *  @return      Base64-encoded string (no line breaks, no padding stripped).
 */
inline std::string base64Encode(const std::vector<uint8_t>& data)
{
    static constexpr std::string_view table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3)
    {
        uint32_t group = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size())
        {
            group |= static_cast<uint32_t>(data[i + 1]) << 8;
        }
        if (i + 2 < data.size())
        {
            group |= static_cast<uint32_t>(data[i + 2]);
        }

        result += table[(group >> 18) & 0x3F];
        result += table[(group >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? table[(group >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? table[group & 0x3F] : '=';
    }

    return result;
}

} // namespace spdm
