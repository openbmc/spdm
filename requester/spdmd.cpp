// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "policy_manager.hpp"
#include "spdm_discovery.hpp"
#include "spdm_responder_manager.hpp"
#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdint>

int main()
{
    using namespace spdm;

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    PolicyManager policyManager(ctx, objManagerPath);
    if (const auto result = policyManager.load(); !result)
    {
        lg2::error("Failed to load policy manager: {ERROR}", "ERROR",
                   result.error());
        return EXIT_FAILURE;
    }

    SPDMDiscovery discovery{};

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    // Create responder manager
    SPDMResponderManager responderMgr(ctx);

    // Spawn main task
    ctx.spawn([&]() -> sdbusplus::async::task<> {
        // Wait for initial discovery to complete
        co_await discovery.run();

        // Request D-Bus name after discovery completes
        ctx.request_name(dbusServiceName);

        // Process discovered devices after claiming bus name
        co_await responderMgr.processDiscoveredDevices(discovery.getDevices());
    }());

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
