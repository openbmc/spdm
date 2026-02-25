// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"
#include "utils.hpp"

#include <sdbusplus/async.hpp>

namespace spdm
{

/**
 * @brief TCP-specific transport implementation
 * @details Handles discovery of SPDM devices over TCP transport using D-Bus
 */
class TCPTransportDiscovery
{
  public:
    explicit TCPTransportDiscovery(sdbusplus::async::context& ctx) :
        ctx(ctx) {};

    auto discovery() -> sdbusplus::async::task<std::vector<ResponderInfo>>;

    static auto type() -> TransportType
    {
        return TransportType::TCP;
    }

  private:
    /**
     * @brief Process managed objects to extract SPDM device information
     * @param managedObjects Map of managed objects from D-Bus
     * @return Vector of discovered SPDM devices
     */
    std::vector<ResponderInfo> processManagedObjects(
        const ManagedObjects& managedObjects);

    /**
     * @brief Create a device from D-Bus interfaces
     * @param interfaces D-Bus interfaces for the object
     * @param objectPath Object path for logging
     * @return Optional ResponderInfo if device is valid, nullopt otherwise
     */
    std::optional<ResponderInfo> createDeviceFromInterfaces(
        const DbusInterfaces& interfaces, const std::string& objectPath);

    sdbusplus::async::context& ctx;
};

} // namespace spdm
