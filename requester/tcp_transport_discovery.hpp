// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"
#include "utils.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/match.hpp>

namespace spdm
{

/**
 * @brief TCP-specific transport implementation
 * @details Handles discovery of SPDM devices over TCP transport using D-Bus
 */
class TCPTransportDiscovery
{
  public:
    explicit TCPTransportDiscovery(sdbusplus::async::context& ctx);

    auto discovery(SPDMDiscovery& spdmDiscovery) -> sdbusplus::async::task<>;

    /**
     * @brief Monitor for newly added TCP SPDM responders
     * @param spdmDiscovery Reference to the main discovery object
     * @return Coroutine task that runs indefinitely
     * @details Listens for InterfacesAdded signals and automatically adds
     *          new TCP responders to the discovery list
     */
    auto monitorSpdmTcpResponderAdded(SPDMDiscovery& spdmDiscovery)
        -> sdbusplus::async::task<>;

    /**
     * @brief Monitor for removed TCP SPDM responders
     * @param spdmDiscovery Reference to the main discovery object
     * @return Coroutine task that runs indefinitely
     * @details Listens for InterfacesRemoved signals and automatically removes
     *          TCP responders from the discovery list
     */
    auto monitorSpdmTcpResponderRemoved(SPDMDiscovery& spdmDiscovery)
        -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::TCP;
    }

  private:
    /**
     * @brief Extract SPDM TCP responder info from D-Bus object
     * @param objectPath The D-Bus object path of the TCP responder
     * @return ResponderInfo object with TCP responder details
     */
    auto createResponderInfo(const std::string& objectPath)
        -> sdbusplus::async::task<ResponderInfo>;

    sdbusplus::async::context& ctx;
    /// D-Bus matcher for InterfacesAdded signals
    std::unique_ptr<sdbusplus::async::match> tcpResponderAddedMatcher;
    /// D-Bus matcher for InterfacesRemoved signals
    std::unique_ptr<sdbusplus::async::match> tcpResponderRemovedMatcher;
};

} // namespace spdm
