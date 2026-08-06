// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/barrier.hpp>
#include <sdbusplus/async/match.hpp>

namespace spdm
{

class SpdmTcpTransport;

/**
 * @brief TCP-specific transport implementation
 * @details Handles discovery of SPDM devices over TCP transport using D-Bus
 */
class TCPTransportDiscovery
{
  public:
    explicit TCPTransportDiscovery(sdbusplus::async::context& ctx);

    auto discovery(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::TCP;
    }

    /**
     * @brief Synchronization barrier for coordinating monitor tasks
     * @details Used to ensure both monitoring coroutines are ready before
     *          starting initial device discovery to prevent race conditions
     */
    sdbusplus::async::barrier startup_barrier;

  private:
    sdbusplus::async::context& ctx;

    /**
     * @brief Monitor for newly added TCP SPDM responders
     * @param spdmDiscovery Reference to the main discovery object
     * @return Coroutine task that runs indefinitely
     * @details Listens for InterfacesAdded signals and automatically adds
     *          new TCP responders to the discovery list
     */
    auto monitor_added(SPDMDiscovery&) -> sdbusplus::async::task<>;

    /**
     * @brief Monitor for removed TCP SPDM responders
     * @param spdmDiscovery Reference to the main discovery object
     * @return Coroutine task that runs indefinitely
     * @details Listens for InterfacesRemoved signals and automatically removes
     *          TCP responders from the discovery list
     */
    auto monitor_removed(SPDMDiscovery&) -> sdbusplus::async::task<>;
};

} // namespace spdm
