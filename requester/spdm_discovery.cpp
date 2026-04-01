// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"

#include "spdm_responder_manager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>

namespace spdm
{

SPDMDiscovery::SPDMDiscovery() {}

auto SPDMDiscovery::run() -> sdbusplus::async::task<>
{
    PHOSPHOR_LOG2_USING;

    co_await initialDiscovery.on_empty();
    debug("SPDMDiscovery: initial discovery complete.");

    // Check results.
    if (!responderInfos.empty())
    {
        // Log discovered devices
        for (const auto& device : responderInfos)
        {
            info("Found SPDM device: PATH={PATH}", "PATH", device.path);
        }
    }
    else
    {
        warning("No SPDM devices found");
    }
}

void SPDMDiscovery::add(ResponderInfo&& r, bool isRuntimeDiscovered)
{
    // Always add to the vector first to maintain the list of discovered devices
    responderInfos.emplace_back(std::move(r));

    if (isRuntimeDiscovered && responderManager)
    {
        // Capture the device data by value in the lambda to avoid dangling
        // references We need to extract the data before spawning since
        // responderInfos could be reallocated
        const auto& lastDevice = responderInfos.back();
        auto path = lastDevice.path;
        auto info = lastDevice.info;
        auto transport = lastDevice.transport;

        auto& ctx = responderManager->getContext();
        ctx.spawn(
            [](SPDMResponderManager* mgr, sdbusplus::message::object_path p,
               std::variant<MctpResponderInfo, TcpResponderInfo> i,
               TransportType t) -> sdbusplus::async::task<> {
                ResponderInfo device{std::move(p), std::move(i), t};
                co_await mgr->processDiscoveredDevices(
                    std::vector<ResponderInfo>{std::move(device)});
            }(responderManager, std::move(path), std::move(info), transport));
    }
}

void SPDMDiscovery::remove(const sdbusplus::message::object_path& path)
{
    std::erase_if(responderInfos,
                  [&path](const auto& r) { return r.path == path; });

    if (responderManager)
    {
        responderManager->notifyDeviceRemoved(path);
    }
}

} // namespace spdm
