// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "mctp_helper.hpp"
#include "spdm_discovery.hpp"
#include "utils.hpp"

#include <sdbusplus/async.hpp>

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
     * @param ctx Reference to async D-Bus context
     */
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx);

    /**
     * @brief Discover SPDM devices over MCTP
     * @param callback Callback function to handle the discovered devices
     */
    void discoverDevices(
        std::function<void(std::vector<ResponderInfo>)> callback) override;

    /**
     * @brief Get the transport type
     * @return TransportType::MCTP
     */
    TransportType getType() const override
    {
        return TransportType::MCTP;
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
     * @param socketCreated Whether MCTP socket was successfully created
     * @return Optional ResponderInfo if device is valid, nullopt otherwise
     */
    std::optional<ResponderInfo> createDeviceFromInterfaces(
        const DbusInterfaces& interfaces, const std::string& objectPath,
        bool socketCreated);

  private:
    MctpIoClass mctpIo;
    /**
     * @brief Check if endpoint supports SPDM message type
     * @param mctpInterface MCTP interface properties
     * @param objectPath Object path for logging
     * @return true if endpoint supports SPDM, false otherwise
     */
    bool supportsSpdm(const DbusInterface& mctpInterface,
                      const std::string& objectPath);

    /**
     * @brief Extract EID from MCTP interface
     * @param mctpInterface MCTP interface properties
     * @param objectPath Object path for logging
     * @return EID value if valid, invalid_eid otherwise
     */
    size_t extractEid(const DbusInterface& mctpInterface,
                      const std::string& objectPath);

    /**
     * @brief Extract UUID from interfaces
     * @param interfaces All interfaces for the object
     * @param objectPath Object path for logging
     * @return UUID string if valid, empty string otherwise
     */
    std::string extractUuid(const DbusInterfaces& interfaces,
                            const std::string& objectPath);

    /// MCTP endpoint interface name
    static constexpr auto mctpEndpointIntfName =
        "xyz.openbmc_project.MCTP.Endpoint";

    /// UUID interface name
    static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

    /// MCTP service name
    static constexpr auto mctpService = "au.com.codeconstruct.MCTP1";

    /// MCTP message type for SPDM (already defined in libspdm headers)
    static constexpr uint8_t MCTP_MESSAGE_TYPE_SPDM_VALUE = 0x05;

    /// Invalid EID marker
    static constexpr size_t invalid_eid = 255;

    sdbusplus::async::context* asyncCtx = nullptr; ///< Async D-Bus context
};

} // namespace spdm
