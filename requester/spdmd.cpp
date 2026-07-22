// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "policy_manager.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "spdm_session_config.hpp"
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

    lg2::info("Starting SPDM daemon");

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

    lg2::info("Starting SPDM device discovery");

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    std::vector<std::unique_ptr<SPDMDBusResponder>> responders;

    // Common secure-session config
    SecureSessionConfig sessionCfg{};
    sessionCfg.peerRootCertBaseDir = "/usr/share/spdm-emu";

    // Register callback for runtime SecureSessionEnabled flips while
    // Enabled=true. KEY_EX caps were already advertised at responder creation,
    // so we can open / close sessions on the fly without a full re-init.
    policyManager.registerSecureSessionEnabledChangeCallback([&responders,
                                                              &policyManager,
                                                              &sessionCfg](
                                                                 bool oldValue,
                                                                 bool
                                                                     newValue) {
        if (oldValue == newValue)
        {
            return;
        }

        if (!policyManager.enabled())
        {
            lg2::info(
                "SecureSessionEnabled changed but Enabled is false; will take effect when Enabled is true");
            return;
        }

        if (!oldValue && newValue)
        {
            lg2::info(
                "SecureSessionEnabled changed from false to true, opening sessions");
            for (const auto& r : responders)
            {
                if (!r->secureSessionActive())
                {
                    if (LIBSPDM_STATUS_IS_ERROR(
                            r->openSecureSession(sessionCfg)))
                    {
                        lg2::warning(
                            "Runtime openSecureSession failed for {DEVICE}",
                            "DEVICE", r->deviceName);
                    }
                }
            }
        }
        else
        {
            lg2::info(
                "SecureSessionEnabled changed from true to false, closing sessions");
            for (const auto& r : responders)
            {
                if (r->secureSessionActive())
                {
                    if (LIBSPDM_STATUS_IS_ERROR(r->closeSecureSession()))
                    {
                        lg2::warning(
                            "Runtime closeSecureSession failed for {DEVICE}",
                            "DEVICE", r->deviceName);
                    }
                }
            }
        }
    });

    // Run the initial discovery, create D-Bus responders, then claim bus name.
    ctx.spawn([](auto& ctx, auto& discovery, auto& responders,
                 auto& policyManager,
                 auto& sessionCfg) -> sdbusplus::async::task<> {
        co_await discovery.run();

        lg2::info(
            "Processing {COUNT} discovered SPDM devices (secure-session={SECURE})",
            "COUNT", discovery.devices().size(), "SECURE",
            policyManager.secure_session_enabled());

        for (const auto& device : discovery.devices())
        {
            try
            {
                lg2::info("Creating D-Bus responder for device {PATH}", "PATH",
                          device.path);
                auto responder =
                    std::make_unique<SPDMDBusResponder>(ctx, device);

                // Always advertise KEY_EX caps so that runtime flips of
                // SecureSessionEnabled can open/close sessions without a
                // full re-init. Cert load and session establishment remain
                // gated on the policy.
                if (LIBSPDM_STATUS_IS_ERROR(
                        responder->applySessionConfig(sessionCfg)))
                {
                    lg2::error(
                        "Failed to apply secure-session config for device {PATH}",
                        "PATH", device.path);
                }
                else if (policyManager.secure_session_enabled())
                {
                    if (LIBSPDM_STATUS_IS_ERROR(
                            responder->openSecureSession(sessionCfg)))
                    {
                        lg2::error(
                            "Secure session not opened for device {PATH}",
                            "PATH", device.path);
                    }
                }

                lg2::info("Successfully created responder for device {PATH}",
                          "PATH", device.path);
                responders.push_back(std::move(responder));
            }
            catch (const std::exception& e)
            {
                lg2::error(
                    "Failed to create responder for device {PATH}: {ERROR}",
                    "PATH", device.path, "ERROR", e.what());
            }
        }

        lg2::info("Created {COUNT} D-Bus responders", "COUNT",
                  responders.size());

        // Request D-Bus name after initial discovery.
        ctx.request_name(dbusServiceName);
        lg2::info("Registered D-Bus service: {SERVICE}", "SERVICE",
                  dbusServiceName);
    }(ctx, discovery, responders, policyManager, sessionCfg));

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    // Cleanup: close any active secure sessions before destroying responders
    for (const auto& r : responders)
    {
        if (r->secureSessionActive())
        {
            if (LIBSPDM_STATUS_IS_ERROR(r->closeSecureSession()))
            {
                lg2::warning("closeSecureSession failed for {DEVICE}", "DEVICE",
                             r->deviceName);
            }
        }
    }
    responders.clear();

    lg2::info("SPDM daemon shutting down");

    return EXIT_SUCCESS;
}
