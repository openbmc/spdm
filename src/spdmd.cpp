// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_discovery.hpp"
#include "spdm_discovery.hpp"
#include "spdmd_app.hpp"

#include <phosphor-logging/lg2.hpp>

#include <iostream>

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
