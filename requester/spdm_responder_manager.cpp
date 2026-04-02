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
    info("Processing {COUNT} initially discovered SPDM devices", "COUNT",
         devices.size());

    // Process each device sequentially
    for (const auto& device : devices)
    {
        co_await handleDeviceAdded(device);
    }

    info("Initial SPDM device processing complete");
}

auto SPDMResponderManager::connectSPDMDevice(const ResponderInfo& device)
    -> sdbusplus::async::task<>
{
    // TODO: Implement actual SPDM connection
    debug("Connecting to SPDM device: {PATH}", "PATH", device.path.str);

    // TODO: Perform protocol discovery
    debug("Performing SPDM protocol discovery: {PATH}", "PATH",
          device.path.str);

    co_return;
}

auto SPDMResponderManager::handleDeviceAdded(const ResponderInfo& device)
    -> sdbusplus::async::task<>
{
    const auto& devicePath = device.path.str;

    info("Processing SPDM device: {PATH}", "PATH", devicePath);

    try
    {
        // Connect and perform attestation
        co_await connectSPDMDevice(device);

        info("SPDM device ready: {PATH}", "PATH", devicePath);
    }
    catch (const std::exception& e)
    {
        error("Failed to process SPDM device {PATH}: {ERROR}", "PATH",
              devicePath, "ERROR", e);
    }
}

} // namespace spdm
