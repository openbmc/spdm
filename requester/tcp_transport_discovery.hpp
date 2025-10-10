// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"
#include "utils.hpp"

#include <sdbusplus/async.hpp>

#include <vector>

namespace spdm
{

/**
 * @brief TCP-specific transport implementation
 * @details Handles discovery of SPDM devices over TCP transport using D-Bus
 */
class TCPTransportDiscovery : public DiscoveryProtocol
{
  public:
    /**
     * @brief Construct a new TCP Transport object
     * @param ctx Reference to async D-Bus context
     */
    explicit TCPTransportDiscovery(sdbusplus::async::context& ctx);

    /**
     * @brief Discover SPDM devices over TCP
     * @param callback Callback function to handle the discovered devices
     */
    void discoverDevices(
        std::function<void(std::vector<ResponderInfo>)> callback) override;

    /**
     * @brief Get the transport type
     * @return TransportType::TCP
     */
    TransportType getType() const override
    {
        return TransportType::TCP;
    }

  public:
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

    /** parse SPDM EM configs
     * @param devices Devices to get configs for
     * @param emManagedObjects Managed objects for the EM service
     */
    void parseSpdmEMConfig(std::vector<ResponderInfo>& devices,
                           const ManagedObjects& emManagedObjects);

    /** process SPDM EM configs
     * @param devices Devices to get configs for
     * @param emManagedObjects Managed objects for the EM service
     * @param callback Callback function to handle the result
     */
    void getSpdmEMConfigs(
        std::vector<ResponderInfo> devices,
        std::function<void(std::vector<ResponderInfo>)> callback);

  private:
    /// TCP message type for SPDM (already defined in libspdm headers)
    static constexpr uint8_t TCP_MESSAGE_TYPE_SPDM_VALUE = 0x05;

    sdbusplus::async::context* asyncCtx = nullptr; ///< Async D-Bus context
};

} // namespace spdm
