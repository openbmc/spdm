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
 * @return true if devices were found, false otherwise
 * @throws std::runtime_error on discovery failure
 */
bool SPDMDiscovery::discover()
{
    try
    {
        for (auto& protocol : discoveryProtocol)
        {
            auto discoveredDevices = protocol->discoverDevices();
            responderInfos.insert(responderInfos.end(),
                                  discoveredDevices.begin(),
                                  discoveredDevices.end());
        }
        return !responderInfos.empty();
    }
    catch (const std::exception& e)
    {
        error("Discovery failed: {ERROR}", "ERROR", e);
        return false;
    }
}

} // namespace spdm
