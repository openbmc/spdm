// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>
#include <sdbusplus/message.hpp>

#include <functional>
#include <map>
#include <string>
#include <variant>

namespace spdm
{

// Type aliases for complex D-Bus structures
using DbusPropertyValue =
    std::variant<std::string, uint8_t, std::vector<uint8_t>, uint64_t>;
using DbusInterface = std::map<std::string, DbusPropertyValue>;
using DbusInterfaces = std::map<std::string, DbusInterface>;
using ManagedObjects =
    std::map<sdbusplus::message::object_path, DbusInterfaces>;
using SubTreeType =
    std::map<std::string, std::map<std::string, std::vector<std::string>>>;

/**
 * @brief Get objects from ObjectMapper that implement a specific interface
 * @param ctx Async context
 * @param interface Interface name to search for
 * @param serviceName Optional service name to filter results
 * @return SubTree of objects implementing the interface
 */
auto getObjectsFromMapper(sdbusplus::async::context& ctx,
                          const std::string& interface,
                          const std::string& serviceName = "")
    -> sdbusplus::async::task<SubTreeType>;

/**
 * @brief Get a D-Bus property value
 */
template <typename T>
inline auto getProperty(
    sdbusplus::async::context& ctx, const std::string& service,
    const std::string& objectPath, const std::string& interface,
    const std::string& property) -> sdbusplus::async::task<T>
{
    auto proxy = sdbusplus::async::proxy()
                     .service(service)
                     .path(objectPath)
                     .interface(interface);

    co_return co_await proxy.get_property<T>(ctx, property);
}

} // namespace spdm
