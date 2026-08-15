// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "dbus_path.hpp"

#include <algorithm>
#include <cctype>

namespace spdm::dbus_path
{

std::string sanitize(const std::string& host)
{
    std::string sanitized = host;
    std::ranges::replace_if(
        sanitized,
        [](unsigned char c) { return !(std::isalnum(c) || c == '_'); }, '_');
    return sanitized;
}

} // namespace spdm::dbus_path
