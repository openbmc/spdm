// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

/**
 * @brief Constructs the SPDM discovery object
 * @details Initializes discovery with provided transport implementation
 *
 * @param transportIn Unique pointer to transport implementation
 */
SPDMDiscovery::SPDMDiscovery(
    std::vector<std::unique_ptr<DiscoveryProtocol>> discoveryProtocolIn) :
    discoveryProtocol(std::move(discoveryProtocolIn))
{}

/**
 * @brief Performs device discovery
 * @details Initiates discovery process using configured transport
 *
 * @param callback Callback function to handle the discovery result
 */
void SPDMDiscovery::discover(
    std::function<void(std::vector<ResponderInfo> devices)> callback)
{
    for (auto& protocol : discoveryProtocol)
    {
        protocol->discoverDevices([callback = std::move(callback)](
                                      std::vector<ResponderInfo> devices) {
            if (devices.empty())
            {
                info("No SPDM devices discovered");
            }
            else
            {
                info("Discovered {COUNT} SPDM devices", "COUNT",
                     devices.size());
            }
            callback(std::move(devices));
        });
    }
}

} // namespace spdm
