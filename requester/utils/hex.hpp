// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <charconv>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <vector>

namespace spdm
{

/** @brief Decode a hex string into bytes.
 *
 *  @param hex  Hex-encoded string, even length, no prefix or separators.
 *  @return     Decoded bytes, or an empty vector if the input is not
 *              valid hex.
 */
inline std::vector<uint8_t> hexDecode(std::string_view hex)
{
    if (hex.empty() || (hex.size() % 2) != 0)
    {
        return {};
    }

    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
    {
        const char* first = hex.data() + (2 * i);
        auto [ptr, ec] = std::from_chars(first, first + 2, out[i], 16);
        if (ec != std::errc() || ptr != first + 2)
        {
            return {};
        }
    }
    return out;
}

} // namespace spdm
