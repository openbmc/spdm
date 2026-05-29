// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/barrier.hpp>
#include <sdbusplus/async/match.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string>

namespace spdm
{

/**
 * @brief MCTP transport discovery for SPDM devices.
 *
 * Runs an initial mapper sweep and subscribes to InterfacesAdded/Removed so
 * endpoints registered by mctpd after spdmd starts are also attested.
 */
class MCTPTransportDiscovery
{
  public:
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx);

    /**
     * @brief Arm the runtime monitors, then run the initial mapper sweep.
     *
     * The monitors are spawned before the mapper snapshot is read so an
     * endpoint that appears during enumeration is caught exactly once
     * (deduped against SPDMDiscovery::add()'s same-path skip).
     */
    auto discovery(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }

  private:
    sdbusplus::async::context& ctx;

    /// Register SPDM-capable endpoints as mctpd adds them at runtime.
    auto monitorAdded(SPDMDiscovery&) -> sdbusplus::async::task<>;

    /// Drop the matching ResponderInfo as mctpd removes endpoints.
    auto monitorRemoved(SPDMDiscovery&) -> sdbusplus::async::task<>;

    /**
     * @brief Register an endpoint only if it advertises SPDM support.
     * @return true if added; false if skipped (logs the skip).
     */
    auto addResponder(SPDMDiscovery& discovery,
                      const sdbusplus::object_path& path, uint8_t eid,
                      const std::string& uuid,
                      std::span<const uint8_t> supportedTypes) -> bool;

    /// Joins discovery() with the monitors so the matchers are armed before
    /// the initial mapper read.
    sdbusplus::async::barrier startup_barrier;

    using MonitorFunc =
        sdbusplus::async::task<> (MCTPTransportDiscovery::*)(SPDMDiscovery&);

    static constexpr std::array monitors{
        &MCTPTransportDiscovery::monitorAdded,
        &MCTPTransportDiscovery::monitorRemoved,
    };

    // discovery() plus each monitor rendezvous at the barrier.
    static constexpr std::size_t num_startup_tasks = 1 + monitors.size();

    static constexpr uint8_t spdm_message_type = 0x5;

    // mctpd publishes endpoints under its own tree (Code Construct,
    // au.com.codeconstruct), so scope the match there rather than under
    // /xyz/openbmc_project.
    static constexpr auto mctp_namespace_path = "/au/com/codeconstruct/mctp1";
};

} // namespace spdm
