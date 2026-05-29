// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/async/barrier.hpp>
#include <sdbusplus/async/match.hpp>

#include <cstddef>
#include <span>
#include <string>

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
     * SPDMDiscovery::add()'s same-path skip.
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
     * EID / UUID / SupportedMessageTypes from the signal payload directly
     * (no separate Get/GetAll round-trip).  EID is the identifier; the UUID
     * is best-effort and recorded only when present -- mctpd's publish_peer()
     * (Code Construct mctp src/mctpd.c) adds the UUID vtable only when
     * peer->uuid is set, so EID-only endpoints are accepted rather than
     * dropped.
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
     * @brief Register an endpoint with the discovery sink only when it
     *        advertises SPDM support.
     * @return true if SPDM-capable and added; false if skipped.
     *
     * Shared by the initial mapper sweep and the runtime InterfacesAdded
     * monitor: they extract EID / UUID / message-types differently (typed
     * client proxy vs raw signal payload, by design) but converge on the
     * same SPDM-support check and ResponderInfo registration.
     */
    auto addIfSpdmCapable(SPDMDiscovery& discovery,
                          const sdbusplus::object_path& path, uint8_t eid,
                          const std::string& uuid,
                          std::span<const uint8_t> supportedTypes) -> bool;

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

    // Startup-barrier rendezvous count: the two monitor_* matcher
    // coroutines plus discovery()'s own initial-snapshot read. All three
    // must reach the barrier before the mapper sweep so an endpoint added
    // during enumeration can't slip past both discovery paths.
    static constexpr std::size_t num_startup_tasks = 3;

    // mctpd publishes endpoints under its own object tree, not under
    // /xyz/openbmc_project. It is upstream-maintained by Code Construct
    // (au.com.codeconstruct); the standard xyz.openbmc_project.MCTP.Endpoint
    // interface is exposed on those native paths rather than republished,
    // so the InterfacesAdded match must scope to mctpd's tree to catch
    // runtime endpoint additions.
    static constexpr auto mctp_namespace_path = "/au/com/codeconstruct/mctp1";
};

} // namespace spdm
