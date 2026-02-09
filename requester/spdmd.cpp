// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"

#include <CLI/CLI.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

PHOSPHOR_LOG2_USING;

int main(int argc, char** argv)
{
    bool has_mctp = false;

    CLI::App app{"SPDM requester daemon"};
    app.add_flag("--mctp", has_mctp, "Enable MCTP discovery protocol support");

    CLI11_PARSE(app, argc, argv);
    info("Starting SPDM daemon");

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    // Request D-Bus name
    ctx.request_name(dbusServiceName);

    std::vector<std::unique_ptr<spdm::DiscoveryProtocol>> protocols;
    
    if (has_mctp)
    {
        protocols.push_back(std::make_unique<spdm::MCTPTransportDiscovery>(ctx));
    }

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
