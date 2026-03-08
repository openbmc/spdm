// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>
#include <sdbusplus/message.hpp>

#include <concepts>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

namespace spdm::mapper
{

/** Concept to determine if a type is a dbus interface. */
template <typename T>
concept Interface = requires { std::string(T::interface); };

namespace instances
{

/** Instances by path and hosting service. */
using instances_t =
    std::vector<std::tuple<sdbusplus::object_path, std::string>>;

/** Get instances by interface-type.
 *
 * @param ctx Async context
 * @param interface Interface name to search for
 * @return Instances implementing the interface type.
 */
auto by_interface(sdbusplus::async::context& ctx, const std::string interface)
    -> sdbusplus::async::task<instances_t>;

/** Syntatic helper for by_interface. */
template <Interface T>
auto by_interface(sdbusplus::async::context& ctx)
    -> sdbusplus::async::task<instances_t>
{
    return by_interface(ctx, T::interface);
}
} // namespace instances
} // namespace spdm::mapper
