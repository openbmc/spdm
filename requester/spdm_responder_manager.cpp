// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_responder_manager.hpp"

#include "policy_manager.hpp"
#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{
PHOSPHOR_LOG2_USING;

SPDMResponderManager::SPDMResponderManager(sdbusplus::async::context& ctx,
                                           ::PolicyManager& policyMgr) :
    asyncCtx(ctx), policyManager(policyMgr)
{
    // Register callback for SPDMEnabled property changes
    policyManager.on_enabled([this](bool enabled) {
        info("SPDMEnabled property changed to: {ENABLED}", "ENABLED", enabled);
        if (enabled)
        {
            info("SPDMEnabled is now true, starting attestation for all "
                 "responders");
            attestAllDiscoveredDevices();
        }
        else
        {
            info("SPDMEnabled is now false, stopping all attestations");
            stopAllAttestations();
        }
    });
}

auto SPDMResponderManager::processDiscoveredDevices(
    const std::vector<ResponderInfo>& devices) -> sdbusplus::async::task<>
{
    info("Processing {COUNT} SPDM devices", "COUNT", devices.size());

    for (const auto& device : devices)
    {
        auto responder = std::make_shared<SPDMDBusResponder>(asyncCtx, device);
        responders.emplace(device.path.str, responder);
    }

    if (policyManager.enabled())
    {
        info("SPDMEnabled is true, starting attestation for all devices");
        attestAllDiscoveredDevices();
    }
    else
    {
        info("SPDMEnabled is false, attestation not started");
    }

    co_return;
}

void SPDMResponderManager::notifyDeviceAdded(const ResponderInfo& device)
{
    info("Adding SPDM device: {PATH}", "PATH", device.path.str);

    auto responder = std::make_shared<SPDMDBusResponder>(asyncCtx, device);
    responders.emplace(device.path.str, responder);

    if (policyManager.enabled())
    {
        info("SPDMEnabled is true, starting attestation for device: {PATH}",
             "PATH", device.path.str);
        manageResponders.spawn([responder]() -> sdbusplus::async::task<> {
            co_await responder->run();
        }());
    }
    else
    {
        info("SPDMEnabled is false, attestation not started for device: {PATH}",
             "PATH", device.path.str);
    }
}

void SPDMResponderManager::notifyDeviceRemoved(
    const sdbusplus::message::object_path& path)
{
    info("Removing SPDM device: {PATH}", "PATH", path.str);

    std::erase_if(responders, [&path](const auto& entry) {
        return entry.first == path.str;
    });
}

void SPDMResponderManager::attestAllDiscoveredDevices()
{
    info("Starting attestation for {COUNT} responders", "COUNT",
         responders.size());

    for (const auto& [path, responder] : responders)
    {
        manageResponders.spawn([responder]() -> sdbusplus::async::task<> {
            co_await responder->run();
        }());
    }
}

void SPDMResponderManager::stopAllAttestations()
{
    info("Stopping all attestations for {COUNT} responders", "COUNT",
         responders.size());

    manageResponders.request_stop();
}

} // namespace spdm

