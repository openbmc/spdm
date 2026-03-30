// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>
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
template <typename Configuration>
auto fetchProperties(sdbusplus::async::context& ctx,
                     const std::string& service,
                     const sdbusplus::message::object_path& path)
    -> sdbusplus::async::task<
        std::optional<typename Configuration::PropertiesType>>;

} // namespace spdm::utils
