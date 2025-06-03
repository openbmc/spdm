// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

#include <iostream>
#include <vector>

// Main function must be in global namespace
int main()
{
    try
    {
        auto app = spdmd::SPDMDaemon();

        //---- MCTP Discovery------//
        // Get D-Bus connection from app
        auto& bus = app.getBus();

        // Create MCTP transport
        auto mctpDiscovery = std::make_unique<spdm::MCTPDiscovery>(bus);

        // Create discovery instance
        spdm::SPDMDiscovery discovery(std::move(mctpDiscovery));

        // Vector to store responders
        std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;

        // Perform discovery
        if (discovery.discover())
        {
            // Print discovered devices
            for (const auto& device : discovery.getRespondersInfo())
            {
                std::cout << "Found SPDM device:\n"
                          << "  Path: " << device.objectPath << "\n"
                          << "  EID: " << device.eid << "\n"
                          << "  UUID: " << device.uuid << "\n";
                try
                {
                    // Safety check for transport
                    if (!device.transport)
                    {
                        lg2::error("Transport is null for device {PATH}",
                                   "PATH", device.objectPath);
                        continue;
                    }

                    lg2::info("Initializing transport for device {PATH}",
                              "PATH", device.objectPath);
                    if (!device.transport->initialize())
                    {
                        lg2::error(
                            "Failed to initialize SPDM transport for device {PATH}",
                            "PATH", device.objectPath);
                        continue;
                    }
                    lg2::info("Creating D-Bus responder for device {PATH}",
                              "PATH", device.objectPath);
                    // Create SPDMDBusResponder with ResponderInfo and async
                    // context for parallel execution
                    auto responder = std::make_unique<spdm::SPDMDBusResponder>(
                        bus, device, app.getAsyncContext());

                    responders.push_back(std::move(responder));
                    lg2::info(
                        "Successfully created responder for device {PATH}",
                        "PATH", device.objectPath);
                }
                catch (const std::exception& e)
                {
                    lg2::error("Error processing device {PATH}: {ERROR}",
                               "PATH", device.objectPath, "ERROR", e.what());
                    continue;
                }
            }
        }
        else
        {
            lg2::error("No SPDM devices found");
        }
        return app.run();
    }
    catch (const std::exception& e)
    {
        lg2::error("Fatal error: {ERROR}", "ERROR", e);
        return EXIT_FAILURE;
    }
}
