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
    inventoryPath(info.objectPath)
{
    std::visit(
        [this](const auto& responder) {
            using T = std::decay_t<decltype(responder)>;

            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                deviceName = std::to_string(responder.eid);
            }
            else
            {
                deviceName = responder.ipAddr;
            }
        },
        info.responderData);

    lg2::info("Created SPDM D-Bus responder for device {ID} at {PATH}", "ID",
              deviceName, "PATH", info.objectPath);
}

} // namespace spdm
