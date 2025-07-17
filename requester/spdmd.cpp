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
    discovery.discover([](std::vector<spdm::ResponderInfo> devices) {
        if (devices.empty())
        {
            error("No SPDM devices found");
        }
        else
        {
            // Log discovered devices
            for (const auto& device : devices)
            {
                info("Found SPDM device: PATH={PATH}", "PATH",
                     device.objectPath);
            }
        }
    });
    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
