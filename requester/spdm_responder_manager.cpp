// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_responder_manager.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

SPDMResponderManager::SPDMResponderManager() {}

auto SPDMResponderManager::processDiscoveredDevices(
    const std::vector<ResponderInfo>& devices) -> sdbusplus::async::task<>
{
    info("Processing {COUNT} SPDM devices", "COUNT", devices.size());

    for (const auto& device : devices)
    {
        manageResponders.spawn([this, device]() -> sdbusplus::async::task<> {
            co_await handleDeviceAdded(device);
            co_return;
        }());
    }

    info("Initial SPDM device processing complete");
    co_return;
}

void SPDMResponderManager::notifyDeviceAdded(const ResponderInfo& device)
{
    manageResponders.spawn([this, device]() -> sdbusplus::async::task<> {
        co_await handleDeviceAdded(device);
        co_return;
    }());
}

void SPDMResponderManager::notifyDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    debug("Dynamic device removed notification: {PATH}", "PATH", path.str);
    handleDeviceRemoved(path);
}

auto SPDMResponderManager::connectSPDMDevice(const ResponderInfo& device)
    -> sdbusplus::async::task<>
{
    debug("Connecting to SPDM device: {PATH}", "PATH", device.path.str);
    co_return;
}

auto SPDMResponderManager::handleDeviceAdded(const ResponderInfo& device)
    -> sdbusplus::async::task<>
{
    co_await connectSPDMDevice(device);
    info("SPDM device ready: {PATH}", "PATH", device.path.str);
    co_return;
}

void SPDMResponderManager::handleDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    info("Removing SPDM device: {PATH}", "PATH", path.str);
}

} // namespace spdm
