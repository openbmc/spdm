// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>
#include <sdbusplus/message.hpp>

#include <functional>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace spdm
{

// Type aliases for complex D-Bus structures
using DbusPropertyValue =
    std::variant<std::string, uint8_t, std::vector<uint8_t>, uint64_t>;
using DbusInterface = std::map<std::string, DbusPropertyValue>;
using DbusInterfaces = std::map<std::string, DbusInterface>;
using ManagedObjects =
    std::map<sdbusplus::message::object_path, DbusInterfaces>;

/**
 * @brief Get all managed objects for a service asynchronously
 * @param asyncCtx Async D-Bus context
 * @param service D-Bus service name
 * @param callback Callback function to handle the result
 */
void getManagedObjectsAsync(
    sdbusplus::async::context& asyncCtx, const std::string& service,
    std::function<void(bool success, ManagedObjects)> callback);

/**
 * @brief Get all managed objects from the entity manager asynchronously
 * @param asyncCtx Async D-Bus context
 * @param callback Callback function to handle the result
 */
void getManagedObjectsFromEMAsync(
    sdbusplus::async::context& asyncCtx,
    std::function<void(bool success, ManagedObjects)> callback);

/**
 * @brief Encode binary data to base64 string
 * @param data Binary data to encode
 * @return Base64 encoded string
 */
std::string base64Encode(const std::vector<uint8_t>& data);

} // namespace spdm
