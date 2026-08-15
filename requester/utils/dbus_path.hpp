// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <string>

namespace spdm::dbus_path
{

/**
 * @brief Sanitize a hostname/IP into a valid D-Bus object path element.
 * @details D-Bus object path elements may only contain
 *          "[A-Z][a-z][0-9]_" (e.g. '.' in an IPv4 address or ':' in an
 *          IPv6 address are not allowed), so replace any other character
 *          with '_'.
 */
std::string sanitize(const std::string& host);

} // namespace spdm::dbus_path
