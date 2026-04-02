// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_responder_manager.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

SPDMResponderManager::SPDMResponderManager(sdbusplus::async::context& ctx) :
    ctx(ctx)
{}

auto SPDMResponderManager::processDiscoveredDevices(
    const std::vector<ResponderInfo>& devices) -> sdbusplus::async::task<>
{
    info("Processing {COUNT} SPDM devices", "COUNT", devices.size());

    // Process each device sequentially
    for (const auto& device : devices)
    {
        const auto& devicePath = device.path.str;

        // Connect and perform attestation
        co_await connectSPDMDevice(device);

        debug("SPDM device ready: {PATH}", "PATH", devicePath);
    }
}

void SPDMResponderManager::notifyDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    debug("Dynamic device removed notification: {PATH}", "PATH", path.str);

    // Handle removal synchronously
    handleDeviceRemoved(path);
}

auto SPDMResponderManager::connectSPDMDevice(const ResponderInfo& device)
    -> sdbusplus::async::task<>
{
    info(
        "Connect to SPDM responder and perform SPDM protocol discovery: {PATH}",
        "PATH", device.path.str);

    co_return;
}

void SPDMResponderManager::handleDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    const auto& devicePath = path.str;

    info("Removing SPDM device: {PATH}", "PATH", devicePath);
}

} // namespace spdm
