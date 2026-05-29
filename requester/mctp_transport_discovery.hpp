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
    /**
     * @brief Construct the discovery helper.
     * @param ctx D-Bus async context used for the initial mapper sweep
     *            and the InterfacesAdded/Removed matchers.
     *
     * Initializes a 3-arity startup_barrier: discovery() and both
     * monitor coroutines participate so the matchers are armed
     * before the initial mapper read.
     */
    explicit MCTPTransportDiscovery(sdbusplus::async::context& ctx);

    /**
     * @brief Run an initial mapper sweep for SPDM-capable MCTP endpoints
     *        and arm runtime monitors before returning.
     * @param discovery Sink that receives each discovered endpoint.
     *
     * Spawns monitor_added and monitor_removed coroutines before the
     * mapper snapshot is read, so endpoints that appear during
     * enumeration are caught exactly once -- deduped against
     * SPDMDiscovery::add()'s same-path skip (added in 90799).
     */
    auto discovery(SPDMDiscovery&) -> sdbusplus::async::task<>;

    static auto type() -> TransportType
    {
        return TransportType::MCTP;
    }

  private:
    sdbusplus::async::context& ctx;

    /**
     * @brief Watch for new MCTP endpoints added by mctpd at runtime.
     * @param discovery Sink that receives the new endpoint.
     *
     * Subscribes to InterfacesAdded under mctpd's namespace and reads
     * EID / UUID / SupportedMessageTypes from the signal payload
     * directly (no separate Get/GetAll round-trip).  Endpoints whose
     * payload omits the UUID interface are skipped -- see Code
     * Construct mctp src/mctpd.c publish_peer() which adds the UUID
     * vtable only when peer->uuid is set.
     */
    auto monitor_added(SPDMDiscovery&) -> sdbusplus::async::task<>;

    /**
     * @brief Watch for MCTP endpoints removed by mctpd at runtime.
     * @param discovery Sink that owns the removed entry.
     *
     * Subscribes to InterfacesRemoved under mctpd's namespace and
     * forwards the path so SPDMDiscovery can drop the matching
     * ResponderInfo.
     */
    auto monitor_removed(SPDMDiscovery&) -> sdbusplus::async::task<>;

    /**
     * @brief Barrier joining discovery() with both monitor coroutines.
     *
     * 3-arity.  discovery() arrives after spawning the monitors; each
     * monitor arrives after its match is constructed.  All three
     * rendezvous before the initial mapper sweep runs so no
     * InterfacesAdded signal emitted during enumeration is lost.
     */
    sdbusplus::async::barrier startup_barrier;

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
