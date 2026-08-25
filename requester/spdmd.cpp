// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "policy_manager.hpp"
#include "responder_manager.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "tcp_transport_discovery.hpp"
#include "utils/paths.hpp"

#include <CLI/CLI.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/async/timer.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdint>
#include <filesystem>

namespace spdm
{
namespace
{
auto retryAfter(sdbusplus::async::context& ctx, std::chrono::seconds delay,
                ResponderManager<SPDMDBusResponder>::Retry retry)
    -> sdbusplus::async::task<>
{
    co_await sdbusplus::async::sleep_for(ctx, delay);
    retry();
}
} // namespace
} // namespace spdm

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

    ResponderManager<SPDMDBusResponder> responders(
        [&ctx](std::chrono::seconds delay, auto retry) {
            ctx.spawn(retryAfter(ctx, delay, std::move(retry)));
        });

    // Create a D-Bus responder for every device as it is discovered.
    discovery.onDeviceAdded([&ctx, &responders](const ResponderInfo& device) {
        // Discovery may reallocate its device list while a retry is pending.
        responders.add(device.path.str, [&ctx, device] {
            auto responder = std::make_unique<SPDMDBusResponder>(device);
            if (!responder->initialize(ctx))
            {
                return std::unique_ptr<SPDMDBusResponder>{};
            }
            return responder;
        });
    });

    // Destroy the D-Bus responder when a device is removed at runtime.
    discovery.onDeviceRemoved(
        [&responders](const sdbusplus::object_path& path) {
            responders.remove(path.str);
        });

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    // Wait for initial discovery to complete, then claim bus name.
    ctx.spawn([](auto& ctx, auto& discovery) -> sdbusplus::async::task<> {
        co_await discovery.run();
        ctx.request_name(dbusServiceName);
    }(ctx, discovery));

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}
