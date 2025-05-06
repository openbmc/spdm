// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "policy_manager.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "tcp_transport_discovery.hpp"
#include "utils/paths.hpp"

#include <CLI/CLI.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdint>
#include <filesystem>

int main(int argc, char* argv[])
{
    using namespace spdm;

    CLI::App app;
    std::filesystem::path stateDir;
    app.add_option("--state-dir", stateDir,
                   "Override the SPDM state directory");
    CLI11_PARSE(app, argc, argv);

    if (!stateDir.empty())
    {
        paths::set_state_dir(stateDir);
    }

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    PolicyManager policyManager(ctx, objManagerPath);

    SPDMDiscovery discovery{};

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    std::vector<std::unique_ptr<SPDMDBusResponder>> responders;

    // Run the initial discovery, create D-Bus responders, then claim bus name.
    ctx.spawn([](auto& ctx, auto& discovery,
                 auto& responders) -> sdbusplus::async::task<> {
        co_await discovery.run();

        for (const auto& device : discovery.devices())
        {
            responders.push_back(
                std::make_unique<SPDMDBusResponder>(ctx, device));
        }

        // Request D-Bus name after initial discovery.
        ctx.request_name(dbusServiceName);
    }(ctx, discovery, responders));

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
