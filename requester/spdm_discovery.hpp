// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace spdm
{

/**
 * @brief Supported transport types for SPDM
 * @details Enumerates the different transport protocols that can be used
 *          for SPDM communication
 */
enum class TransportType
{
    MCTP,     ///< Management Component Transport Protocol
    PCIE_DOE, ///< PCIe Data Object Exchange
    TCP       ///< TCP/IP Protocol
};

struct MctpResponderInfo
{
    size_t eid;       ///< Endpoint ID
    std::string uuid; ///< Device UUID
};

struct tcpResponderInfo
{
    std::string ipAddr;
    uint64_t port;
};

/**
 * @brief Information about a discovered SPDM responder
 * @details Contains identification and connection information for an SPDM
 * device
 */
struct ResponderInfo
{
    std::string objectPath; ///< D-Bus object path
    sdbusplus::message::object_path deviceObjectPath;
    std::shared_ptr<spdm::SpdmTransport> transport;
    std::variant<MctpResponderInfo, tcpResponderInfo> responderData;
    TransportType transportType;
};

/**
 * @brief Interface for SPDM transport protocols
 * @details Abstract base class defining the interface that all transport
 *          implementations must provide
 */
class DiscoveryProtocol
{
  public:
    virtual ~DiscoveryProtocol() = default;

    /**
     * @brief Discover SPDM-capable devices on this transport
     * @param callback Callback function to handle the discovered devices
     */
    virtual void discoverDevices(
        std::function<void(std::vector<ResponderInfo>)> callback) = 0;

    /**
     * @brief Get the transport type
     * @return Transport type identifier
     */
    virtual TransportType getType() const = 0;
};

/**
 * @brief Main SPDM device discovery class
 * @details Manages the discovery of SPDM devices using a configured transport
 */
class SPDMDiscovery
{
  public:
    /**
     * @brief Construct a new SPDM Discovery object
     * @param transport Unique pointer to transport implementation
     */
    explicit SPDMDiscovery(
        std::unique_ptr<DiscoveryProtocol> discoveryProtocolIn);

    /**
     * @brief Start device discovery
     * @param callback Callback function to handle the discovered devices
     */
    void discover(
        std::function<void(std::vector<ResponderInfo> devices)> callback);

    inline DiscoveryProtocol* getDiscoveryProtocol()
    {
        return discoveryProtocol.get();
    }

  private:
    std::unique_ptr<DiscoveryProtocol>
        discoveryProtocol; ///< Transport implementation
};

} // namespace spdm
