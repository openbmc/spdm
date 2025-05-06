// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "mctp_helper.hpp"
#include "spdm_discovery.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>

#include <map>
#include <string>
#include <variant>
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
    MctpIoClass mctpIo;
    /**
     * @brief Get all managed objects for a service
     * @param service D-Bus service name
     * @return Map of object paths to their interfaces and properties
     */
    std::map<
        std::string,
        std::map<std::string,
                 std::map<std::string, std::variant<std::string, uint8_t,
                                                    std::vector<uint8_t>>>>>
        getManagedObjects(const std::string& service);

    /**
     * @brief Check if endpoint supports SPDM message type
     * @param mctpInterface MCTP interface properties
     * @param objectPath Object path for logging
     * @return true if endpoint supports SPDM, false otherwise
     */
    bool supportsSpdm(
        const std::map<std::string, std::variant<std::string, uint8_t,
                                                 std::vector<uint8_t>>>&
            mctpInterface,
        const std::string& objectPath);

    /**
     * @brief Extract EID from MCTP interface
     * @param mctpInterface MCTP interface properties
     * @param objectPath Object path for logging
     * @return EID value if valid, invalid_eid otherwise
     */
    size_t extractEid(
        const std::map<std::string, std::variant<std::string, uint8_t,
                                                 std::vector<uint8_t>>>&
            mctpInterface,
        const std::string& objectPath);

    /**
     * @brief Extract UUID from interfaces
     * @param interfaces All interfaces for the object
     * @param objectPath Object path for logging
     * @return UUID string if valid, empty string otherwise
     */
    std::string extractUuid(
        const std::map<
            std::string,
            std::map<std::string,
                     std::variant<std::string, uint8_t, std::vector<uint8_t>>>>&
            interfaces,
        const std::string& objectPath);

    /// MCTP endpoint interface name
    static constexpr auto mctpEndpointIntfName =
        "xyz.openbmc_project.MCTP.Endpoint";

    /// UUID interface name
    static constexpr auto uuidIntfName = "xyz.openbmc_project.Common.UUID";

    /// MCTP service name
    static constexpr auto mctpService = "au.com.codeconstruct.MCTP1";

    /// Invalid EID marker
    static constexpr size_t invalid_eid = 255;

    sdbusplus::bus::bus& bus; ///< D-Bus connection
};

} // namespace spdm
