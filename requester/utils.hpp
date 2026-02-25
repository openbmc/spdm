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

/**
 * @brief Type alias for ObjectMapper GetSubTree result
 * @details Maps object paths to services and their interfaces.
 *          Format: map<object_path, map<service_name, vector<interface_names>>>
 */
using SubTreeType =
    std::map<std::string, std::map<std::string, std::vector<std::string>>>;

/**
 * @brief Get objects from ObjectMapper that implement a specific interface
 * @param ctx Async context
 * @param interface Interface name to search for
 * @return SubTree of objects implementing the interface
 */
auto getObjectsFromMapper(sdbusplus::async::context& ctx,
                          const std::string& interface)
    -> sdbusplus::async::task<SubTreeType>;

} // namespace spdm
