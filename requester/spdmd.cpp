// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
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
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;

    // Perform discovery
    discovery.discover([&responders,
                        &ctx](std::vector<spdm::ResponderInfo> devices) {
        if (devices.empty())
        {
            error("No SPDM devices found");
        }
        else
        {
            // Process discovered devices
            for (const auto& device : devices)
            {
                try
                {
                    info("Creating D-Bus responder for device {PATH}", "PATH",
                         device.objectPath);
                    // Create SPDMDBusResponder with ResponderInfo and async
                    // context for parallel execution
                    auto responder = std::make_unique<spdm::SPDMDBusResponder>(
                        ctx, device, ctx);
                    responders.push_back(std::move(responder));
                    info("Successfully created responder for device {PATH}",
                         "PATH", device.objectPath);
                }
                catch (...)
                {
                    error("Unknown error processing device {PATH}", "PATH",
                          device.objectPath);
                }
            }
        }
    });
    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
