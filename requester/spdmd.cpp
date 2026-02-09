// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "tcp_event_handler.hpp"
#include "tcp_transport_discovery.hpp"

#include <CLI/CLI.hpp>
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

    info("Processing {COUNT} discovered SPDM devices", "COUNT", devices.size());

    // Process discovered devices
    for (const auto& device : devices)
    {
        try
        {
            // Check if device object path is valid
            if (static_cast<std::string>(device.deviceObjectPath).empty())
            {
                warning(
                    "DeviceObjectPath is empty for device {PATH}, using objectPath instead",
                    "PATH", device.objectPath);
            }

            if (device.transport)
            {
                info("Initializing transport for device {PATH}", "PATH",
                     device.objectPath);

                if (!device.transport->initialize())
                {
                    error(
                        "Failed to initialize SPDM transport for device {PATH}",
                        "PATH", device.objectPath);
                    continue;
                }
                info("Transport initialized successfully for device {PATH}",
                     "PATH", device.objectPath);
            }
            else
            {
                warning("Transport is null for device {PATH}", "PATH",
                        device.objectPath);
                // TODO: event based discovery for SPDM devices
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

    info("Created {COUNT} D-Bus responders", "COUNT", responders.size());
}

// Main function must be in global namespace
int main(int argc, char** argv)
{
    std::unique_ptr<spdm::DiscoveryProtocol> discoveryProtocol = nullptr;
    bool has_mctp = false;
    bool has_tcp = false;

    CLI::App app{"SPDM requester daemon"};
    app.add_flag("--mctp", has_mctp, "Enable MCTP discovery protocol support");
    app.add_flag("--tcp", has_tcp, "Enable TCP discovery protocol support");

    CLI11_PARSE(app, argc, argv);
    info("Starting SPDM daemon");

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    // Request D-Bus name
    ctx.request_name(dbusServiceName);
    info("Registered D-Bus service: {SERVICE}", "SERVICE", dbusServiceName);

    // Create discovery protocol - Concrete Strategy
    if (has_mctp)
    {
        discoveryProtocol = std::make_unique<spdm::MCTPTransportDiscovery>(ctx);
    }

    if (has_tcp)
    {
        discoveryProtocol = std::make_unique<spdm::TCPTransportDiscovery>(ctx);
    }

    if (discoveryProtocol == nullptr)
    {
        error("No discovery proctocol selected");
        return EXIT_FAILURE;
    }

    spdm::SPDMDiscovery discovery(std::move(discoveryProtocol));

    info("SPDM device discovery");

    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;

    // Perform discovery
    discovery.discover(
        [&responders, &ctx](std::vector<spdm::ResponderInfo> devices) {
            processDiscoveredDevices(devices, responders, ctx);
        });

    auto tcpEventHandler =
        std::make_unique<spdm::TCPEventHandler>(ctx, responders, discovery);

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    // Cleanup
    responders.clear();

    info("SPDM daemon shutting down");

    return EXIT_SUCCESS;
}
