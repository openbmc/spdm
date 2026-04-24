// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>

#include <optional>
#include <string>

namespace spdm::utils
{
/**
 * @brief Fetch D-Bus properties for a given configuration interface
 *
 * @tparam Configuration The D-Bus configuration client type
 * @param ctx The async context
 * @param service The D-Bus service name
 * @param path The D-Bus object path
 * @return Task that resolves to optional properties, nullopt on error
 */
template <mapper::Interface Configuration>
auto fetchProperties(sdbusplus::async::context& ctx, const std::string& service,
                     const sdbusplus::object_path& path)
    -> sdbusplus::async::task<
        std::optional<typename Configuration::properties_t>>
{
    PHOSPHOR_LOG2_USING;

    try
    {
        auto properties = co_await Configuration(ctx)
                              .service(service)
                              .path(path.str)
                              .properties();

        co_return properties;
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        error(
            "Failed to fetch properties from D-Bus under path {PATH} : {ERROR}",
            "PATH", path.str, "ERROR", e);
        co_return std::nullopt;
    }
    catch (const sdbusplus::exception::UnpackPropertyError& e)
    {
        error("Failed to unpack properties under path {PATH} : {ERROR}", "PATH",
              path.str, "ERROR", e);
        co_return std::nullopt;
    }
}
} // namespace spdm::utils
