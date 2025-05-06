// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/bus.hpp>



#include <vector>

namespace spdm
{

/**
 * @brief MCTP-specific transport implementation
 * @details Handles discovery of SPDM devices over MCTP transport using D-Bus
 */
class MCTPTransportDiscovery : public DiscoveryProtocol
{
  public:
    /**
     * @brief Construct a new MCTP Transport object
     * @param busRef Reference to D-Bus connection
     */
    explicit MCTPTransportDiscovery(sdbusplus::bus::bus& busRef);

    /**
     * @brief Discover SPDM devices over MCTP
     * @return Vector of discovered device information
     * @throws sdbusplus::exception::SdBusError on D-Bus errors
     */
    std::vector<ResponderInfo> discoverDevices() override;

    /**
     * @brief Get the transport type
     * @return TransportType::MCTP
     */
    TransportType getType() const override
    {
        return TransportType::MCTP;
    }

  private:

    sdbusplus::bus::bus& bus; ///< D-Bus connection
};

} // namespace spdm
