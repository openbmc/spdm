// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <sdbusplus/async.hpp>

#include <algorithm>
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
    sdbusplus::object_path path;
    std::variant<MctpResponderInfo, TcpResponderInfo> info;
    TransportType transport;
};

// Forward declaration
class SPDMDiscovery;

namespace details
{
/** Concept for transport discovery types.
 *
 * Discoveries are required to have two things:
 *      - A co-routine named 'discovery'.
 *      - A static function to get the TransportType.
 **/
template <typename T>
concept DiscoveryType = requires(T t, SPDMDiscovery& discovery) {
                            {
                                t.discovery(discovery)
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
        initialDiscovery.spawn([this](D& d) -> sdbusplus::async::task<> {
            co_await d.discovery(*this);
        }(d));
    }

    /**
     * Add a discovered device's ResponderInfo.
     * @param r The ResponderInfo.  When the same path arrives again
     *          (e.g. the initial mapper sweep + a runtime
     *          InterfacesAdded signal both seeing the same endpoint,
     *          or a matcher that re-fires), the existing entry is
     *          replaced rather than ignored.  A re-add may represent
     *          a fresh device state — firmware update, reset, or a
     *          compromise scenario — that should not inherit cached
     *          attestation state.  Forcing fresh state every time is
     *          the correct posture for an attestation-bearing
     *          discovery surface, even at the cost of re-attesting
     *          an unchanged device.
     */
    void add(ResponderInfo&& r)
    {
        auto path = r.path;
        std::erase_if(responderInfos,
                      [&path](const auto& e) { return e.path == path; });
        responderInfos.emplace_back(std::move(r));
    }

    /**
     * Remove a discovered device by object path.
     * @param The D-Bus object path of the device to remove.
     */
    void remove(const sdbusplus::object_path&);

    /**
     * Return all discovered devices.
     */
    const std::vector<ResponderInfo>& devices() const
    {
        return responderInfos;
    }

  private:
    sdbusplus::async::async_scope initialDiscovery;

    /** @brief Discovered devices */
    std::vector<ResponderInfo> responderInfos;
};

} // namespace spdm
