// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_responder_manager.hpp"

#include "spdm_responder.hpp"

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
        auto responder = std::make_shared<SPDMResponder>(asyncCtx, device);
        responders.emplace(device.path.str, responder);

        manageResponders.spawn([responder]() -> sdbusplus::async::task<> {
            co_await responder->run();
        }());
    }

    info("Initial SPDM device processing complete");
    co_return;
}

} // namespace spdm
