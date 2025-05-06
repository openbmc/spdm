// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{

SPDMDiscovery::SPDMDiscovery() {}

auto SPDMDiscovery::run() -> sdbusplus::async::task<>
{
    PHOSPHOR_LOG2_USING;

    co_await initialDiscovery.on_empty();
    debug("SPDMDiscovery: initial discovery complete.");

    // Check results.
    if (responderInfos.empty())
    {
        // Log discovered devices
        for (const auto& device : responderInfos)
        {
            info("Found SPDM device: PATH={PATH}", "PATH", device.objectPath);
        }
    }
    else
    {
        warning("No SPDM devices found");
    }
}

} // namespace spdm
