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

} // namespace spdm
