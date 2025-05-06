// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

// #include "libspdm_transport.hpp"

#include <sdbusplus/async.hpp>

#include <cstdint>
#include <string>
#include <variant>
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
    TCP,      ///< TCP/IP Protocol
};

struct MctpResponderInfo
{
    uint8_t eid;      ///< Endpoint ID
    std::string uuid; ///< Device UUID
};

struct TcpResponderInfo
{
    std::string ipAddr;
    uint64_t port;
};

/**
 * @brief Information about a discovered SPDM responder
 * @details Contains identification and connection information for an SPDM
 *          device
 */
struct ResponderInfo
{
    std::string objectPath; ///< D-Bus object path
    sdbusplus::message::object_path deviceObjectPath;
    std::variant<MctpResponderInfo, TcpResponderInfo> responderData;
    TransportType transportType;
};

namespace details
{
/** Concept for transport discovery types.
 *
 * Discoveries are required to have two things:
 *      - A co-routine named 'discovery'.
 *      - A static function to get the TransportType.
 **/
template <typename T>
concept DiscoveryType = requires(T t) {
                            {
                                t.discovery()
                            } -> std::same_as<sdbusplus::async::task<>>;
                            { T::type() } -> std::same_as<TransportType>;
                        };
} // namespace details

/**
 * @brief Main SPDM device discovery class
 * @details Manages the discovery of SPDM devices using a configured transport
 */
class SPDMDiscovery
{
  public:
    /**
     * Construct a new SPDM Discovery object
     */
    SPDMDiscovery();

    /**
     * Ensure initial device discovery is complete.
     */
    auto run() -> sdbusplus::async::task<>;

    /**
     * Start discovery for a specific transport type.
     * @param d Transport to start discovery for.
     */
    template <details::DiscoveryType D>
    void discover(D& d)
    {
        initialDiscovery.spawn([](D& d) -> sdbusplus::async::task<> {
            co_await d.discovery();
        }(d));
    }

    /**
     * Add a discovered device's ResponderInfo.
     * @param r The ResponderInfo.
     */
    void add(ResponderInfo&& r)
    {
        responderInfos.emplace_back(std::move(r));
    }

    /** @brief Discovered devices */
    std::vector<ResponderInfo> responderInfos;

  private:
    sdbusplus::async::async_scope initialDiscovery;
};

} // namespace spdm
