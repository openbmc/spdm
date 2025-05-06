// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::bus::bus& /* bus */,
                                     const ResponderInfo& responderInfo,
                                     sdbusplus::async::context& ctx) :
    deviceName(std::to_string(responderInfo.eid)),
    inventoryPath(responderInfo.objectPath)
{
    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + deviceName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(ctx, componentIntegrityPath);

    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + deviceName;
    trustedComponent = std::make_unique<TrustedComponent>(ctx,
                                                          trustedComponentPath);

    info("Created SPDM D-Bus responder for device {EID} at {PATH}", "EID",
         responderInfo.eid, "PATH", responderInfo.objectPath);
}

} // namespace spdm
