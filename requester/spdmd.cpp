// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

PHOSPHOR_LOG2_USING;

/**
 * @brief Process discovered SPDM devices and create responders
 * @param devices Vector of discovered SPDM devices
 * @param responders Vector to store created responders
 * @param ctx Async context for D-Bus operations
 */
void processDiscoveredDevices(
    const std::vector<spdm::ResponderInfo>& devices,
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders,
    sdbusplus::async::context& ctx)
{
    if (devices.empty())
    {
        error("No SPDM devices found");
        return;
    }

    // Process discovered devices
    for (const auto& device : devices)
    {
        try
        {
            if (!device.transport)
            {
                error("Transport is null for device {PATH}", "PATH",
                      device.objectPath);
                continue;
            }

            info("Initializing transport for device {PATH}", "PATH",
                 device.objectPath);
            if (!device.transport->initialize())
            {
                error("Failed to initialize SPDM transport for device {PATH}",
                      "PATH", device.objectPath);
                continue;
            }
            info("Creating D-Bus responder for device {PATH}", "PATH",
                 device.objectPath);
            // Create SPDMDBusResponder with ResponderInfo and async
            // context for parallel execution
            auto responder =
                std::make_unique<spdm::SPDMDBusResponder>(device, ctx);

            responders.push_back(std::move(responder));
            info("Successfully created responder for device {PATH}", "PATH",
                 device.objectPath);
        }
        catch (const std::exception& e)
        {
            error("Error processing device {PATH}: {ERROR}", "PATH",
                  device.objectPath, "ERROR", e.what());
            continue;
        }
    }
}

// Main function must be in global namespace
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
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;

    // Perform discovery
    discovery.discover(
        [&responders, &ctx](std::vector<spdm::ResponderInfo> devices) {
            processDiscoveredDevices(devices, responders, ctx);
        });

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
