// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/barrier.hpp>
#include <sdbusplus/async/match.hpp>

namespace spdm
{

/**
 * @brief MCTP-specific transport implementation
 * @details Handles discovery of SPDM devices over MCTP transport using D-Bus.
 *          Performs an initial mapper sweep on startup and subscribes to
 *          InterfacesAdded/Removed signals so endpoints registered by mctpd
 *          after spdmd starts are also attested.
 */
class MCTPTransportDiscovery
{
  public:
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx);

    auto discovery(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }

    sdbusplus::async::barrier startup_barrier;

  private:
    sdbusplus::async::context& ctx;

    auto monitor_added(SPDMDiscovery&) -> sdbusplus::async::task<>;
    auto monitor_removed(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static constexpr uint8_t spdm_message_type = 0x5;
    // mctpd is upstream maintained by Code Construct (au.com.codeconstruct)
    // and publishes endpoint objects under its own native path tree.
    // The standard xyz.openbmc_project.MCTP.Endpoint interface is exposed
    // on these same paths rather than republished under
    // /xyz/openbmc_project, so the InterfacesAdded match must scope to
    // mctpd's tree to catch runtime endpoint additions.
    static constexpr auto mctp_namespace_path = "/au/com/codeconstruct/mctp1";
};

} // namespace spdm
