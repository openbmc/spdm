// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_responder_manager.hpp"

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

SPDMResponderManager::SPDMResponderManager(sdbusplus::async::context& ctx) :
    asyncCtx(ctx)
{}

auto SPDMResponderManager::processDiscoveredDevices(
    const std::vector<ResponderInfo>& devices) -> sdbusplus::async::task<>
{
    info("Processing {COUNT} SPDM devices", "COUNT", devices.size());

    for (const auto& device : devices)
    {
        auto responder = std::make_shared<SPDMDBusResponder>(asyncCtx, device);
        responders.emplace(device.path.str, responder);

        manageResponders.spawn([responder]() -> sdbusplus::async::task<> {
            co_await responder->run();
            co_return;
        }());
    }

    info("Initial SPDM device processing complete");
    co_return;
}

void SPDMResponderManager::notifyDeviceAdded(const ResponderInfo& device)
{
    info("Adding SPDM device: {PATH}", "PATH", device.path.str);

    // Create responder synchronously to avoid race condition on map
    auto responder = std::make_shared<SPDMDBusResponder>(asyncCtx, device);
    responders.emplace(device.path.str, responder);

    manageResponders.spawn([responder]() -> sdbusplus::async::task<> {
        co_await responder->run();
    }());
}

void SPDMResponderManager::notifyDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    info("Removing SPDM device: {PATH}", "PATH", path.str);

    // The shared_ptr ensures the responder lives until all its
    // async tasks complete
    std::erase_if(responders, [&path](const auto& entry) {
        if (entry.first == path.str)
        {
            info("Erasing responder for device: {PATH}", "PATH", entry.first);
            return true;
        }
        return false;
    });
}

} // namespace spdm
