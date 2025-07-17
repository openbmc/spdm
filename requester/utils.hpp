// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>

#include <functional>
#include <map>
#include <string>
#include <variant>

namespace spdm
{

// Type aliases for complex D-Bus structures
using DbusPropertyValue =
    std::variant<std::string, uint8_t, std::vector<uint8_t>>;
using DbusInterface = std::map<std::string, DbusPropertyValue>;
using DbusInterfaces = std::map<std::string, DbusInterface>;
using ManagedObjects = std::map<std::string, DbusInterfaces>;

/**
 * @brief Get all managed objects for a service asynchronously
 * @param asyncCtx Async D-Bus context
 * @param service D-Bus service name
 * @param callback Callback function to handle the result
 */
void getManagedObjectsAsync(
    sdbusplus::async::context& asyncCtx, const std::string& service,
    std::function<void(bool success, ManagedObjects)> callback);

} // namespace spdm
