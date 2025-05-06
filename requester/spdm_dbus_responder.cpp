// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::bus::bus& /* bus */,
                                     const ResponderInfo& info,
                                     sdbusplus::async::context& /* ctx */) :
    deviceName(std::to_string(info.eid)), inventoryPath(info.objectPath)
{
    lg2::info("Created SPDM D-Bus responder for device {EID} at {PATH}", "EID",
              info.eid, "PATH", info.objectPath);
}

} // namespace spdm
