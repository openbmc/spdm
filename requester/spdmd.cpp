// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

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

    std::vector<std::unique_ptr<SPDMDBusResponder>> responders;

    // Run the initial discovery, create D-Bus responders, then claim bus name.
    ctx.spawn([&]() -> sdbusplus::async::task<> {
        co_await discovery.run();

        for (const auto& device : discovery.devices())
        {
            responders.push_back(
                std::make_unique<SPDMDBusResponder>(ctx, device));
        }

        // Request D-Bus name after initial discovery.
        ctx.request_name(dbusServiceName);
    }());

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
