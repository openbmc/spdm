// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

PHOSPHOR_LOG2_USING;

int main()
{
    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    // Request D-Bus name
    ctx.request_name(dbusServiceName);

    std::vector<std::unique_ptr<spdm::DiscoveryProtocol>> protocols;

    protocols.push_back(std::make_unique<spdm::MCTPTransportDiscovery>(ctx));

    // Assign the discovery protocol to the discovery object - Context
    spdm::SPDMDiscovery discovery(std::move(protocols));

    // Perform discovery
    if (discovery.discover())
    {
        // Log discovered devices
        for (const auto& device : discovery.responderInfos)
        {
            info("Found SPDM device: PATH={PATH}", "PATH", device.objectPath);
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
