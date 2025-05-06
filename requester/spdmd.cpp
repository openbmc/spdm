// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

PHOSPHOR_LOG2_USING;

// Main function must be in global namespace
int main()
{
    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, "/xyz/openbmc_project/spdmd");

    // Request D-Bus name
    ctx.request_name("xyz.openbmc_project.spdmd.spdm");

    // Create discovery protocol - Concrete Strategy
    auto discoveryProtocol =
        std::make_unique<spdm::MCTPTransportDiscovery>(ctx);

    // Assign the discovery protocol to the discovery object - Context
    spdm::SPDMDiscovery discovery(std::move(discoveryProtocol));

    // Perform discovery
    if (discovery.discover())
    {
        // Log discovered devices
        for (const auto& device : discovery.respInfos)
        {
            info("Found SPDM device: PATH={PATH}, EID={EID}, UUID={UUID}",
                 "PATH", device.objectPath, "EID", device.eid, "UUID",
                 device.uuid);
        }
    }
    else
    {
        error("No SPDM devices found");
    }
    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
