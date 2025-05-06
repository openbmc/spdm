// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

#include <cstdlib>
#include <iostream>

PHOSPHOR_LOG2_USING;

int main()
{
    try
    {
        auto app = spdmd::SPDMDaemon();
        auto& bus = app.bus;

        // Create discovery protocol - Concrete Strategy
        auto discoveryProtocol =
            std::make_unique<spdm::MCTPTransportDiscovery>(bus);

        // Assign the discovery protocol to the discovery object - Context
        spdm::SPDMDiscovery discovery(std::move(discoveryProtocol));

        std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;
        // Perform discovery
        if (discovery.discover())
        {
            // Print discovered devices
            for (const auto& device : discovery.respInfos)
            {
                try
                {
                    lg2::info("Creating D-Bus responder for device {PATH}",
                              "PATH", device.objectPath);
                    // Create SPDMDBusResponder with ResponderInfo and async
                    // context for parallel execution
                    auto responder = std::make_unique<spdm::SPDMDBusResponder>(
                        bus, device, app.ctx);
                    responders.push_back(std::move(responder));
                    lg2::info(
                        "Successfully created responder for device {PATH}",
                        "PATH", device.objectPath);
                }
                catch (...)
                {
                    lg2::error("Unknown error processing device {PATH}", "PATH",
                               device.objectPath);
                    continue;
                }
            }
        }
        else
        {
            lg2::error("No SPDM devices found");
        }

        // Run the daemon (this will block until shutdown)
        app.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e)
    {
        lg2::error("Fatal error: {ERROR}", "ERROR", e);
        return EXIT_FAILURE;
    }
}
