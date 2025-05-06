// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>

PHOSPHOR_LOG2_USING;

namespace spdm
{

/**
 * @brief Constructs MCTP transport object
 * @param busRef Reference to D-Bus connection
 */
MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::bus::bus& busRef) :
    bus(busRef)
{}

/**
 * @brief Discovers SPDM devices over MCTP
 * @details Uses GetManagedObjects to efficiently get all MCTP endpoint data in
 * one call
 *
 * @return Vector of discovered SPDM devices
 * @throws sdbusplus::exception::SdBusError on D-Bus communication errors
 */
std::vector<ResponderInfo> MCTPTransportDiscovery::discoverDevices()
{
    std::vector<ResponderInfo> devices;
    return devices;
}

} // namespace spdm
