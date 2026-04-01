// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_discovery.hpp"
#include "spdm_responder_manager.hpp"
#include "tcp_transport_discovery.hpp"

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

    SPDMDiscovery discovery{};

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    // Create responder manager
    SPDMResponderManager responderManager{ctx};

    // Enable dynamic device notifications
    discovery.setResponderManager(&responderManager);

    // Spawn main task
    ctx.spawn([&]() -> sdbusplus::async::task<> {
        // Wait for initial discovery to complete
        co_await discovery.run();

        // Request D-Bus name after discovery completes
        ctx.request_name(dbusServiceName);

        // Process discovered devices after claiming bus name
        co_await responderManager.processDiscoveredDevices(
            discovery.responderInfos);
    }());

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
