// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <algorithm>
#include <ranges>
#include <span>

namespace spdm
{
PHOSPHOR_LOG2_USING;
using MctpEndpoint = sdbusplus::client::xyz::openbmc_project::mctp::Endpoint<>;
using CommonUUID = sdbusplus::client::xyz::openbmc_project::common::UUID<>;

using InterfaceMap = std::unordered_map<
    std::string,
    std::unordered_map<std::string, std::variant<std::string, uint64_t, uint8_t,
                                                 std::vector<uint8_t>>>>;

namespace rules = sdbusplus::bus::match::rules;

MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
    ctx(ctx), startup_barrier(num_startup_tasks)
{}

auto MCTPTransportDiscovery::addIfSpdmCapable(
    SPDMDiscovery& discovery, const sdbusplus::object_path& path, uint8_t eid,
    const std::string& uuid, std::span<const uint8_t> supportedTypes) -> bool
{
    if (!std::ranges::contains(supportedTypes, spdm_message_type))
    {
        return false;
    }

    discovery.add(
        ResponderInfo{path, MctpResponderInfo{eid, uuid}, TransportType::MCTP});
    return true;
}

auto MCTPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    // Spawn monitoring tasks so endpoints added by mctpd at runtime are
    // picked up. The 3-arity barrier ensures the InterfacesAdded matchers
    // are armed before we read the initial mapper snapshot, eliminating
    // the lost-signal race on endpoints that appear during enumeration.
    ctx.spawn(monitor_added(discovery));
    ctx.spawn(monitor_removed(discovery));

    co_await startup_barrier.wait();

    auto instances =
        co_await mapper::instances::by_interface<MctpEndpoint>(ctx);

    for (const auto& [path, service] : instances)
    {
        auto endpointProps = co_await MctpEndpoint(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();

        // UUID is best-effort (see monitor_added): identify on EID and record
        // the UUID when present. mctpd exposes the UUID interface only for
        // endpoints that have one, so don't drop an SPDM-capable device that
        // lacks it.
        std::string uuid;
        try
        {
            auto uuidProps = co_await CommonUUID(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();
            uuid = uuidProps.uuid;
        }
        catch (const std::exception& e)
        {
            debug("UUID unavailable for {PATH}; proceeding EID-only: {ERR}",
                  "PATH", path, "ERR", e);
        }

        if (!addIfSpdmCapable(discovery, path, endpointProps.eid, uuid,
                              endpointProps.supported_message_types))
        {
            debug("Endpoint {PATH} does not support SPDM", "PATH", path);
            continue;
        }

        debug("Found SPDM MCTP device at {PATH}, EID={EID}, UUID={UUID}",
              "PATH", path, "EID", endpointProps.eid, "UUID", uuid);
    }

    debug("MCTP transport discovery completed");
}

auto MCTPTransportDiscovery::monitor_added(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesAdded(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        sdbusplus::object_path path;
        InterfaceMap interfaces;
        try
        {
            path = msg.unpack<sdbusplus::object_path>();
            interfaces = msg.unpack<InterfaceMap>();
        }
        catch (const std::exception& e)
        {
            // Unexpected property type in the signal payload — skip rather
            // than letting the exception unwind through the loop and end
            // the matcher coroutine.
            debug("Skipping unparseable InterfacesAdded signal: {ERR}", "ERR",
                  e);
            continue;
        }

        // mctpd emits a single InterfacesAdded signal per endpoint path via
        // sd_bus_emit_object_added(); the payload carries every interface
        // currently registered at that path (see Code Construct mctp
        // src/mctpd.c publish_peer() and emit_endpoint_added()). Extract
        // EID / SupportedMessageTypes / UUID directly from the payload so
        // we avoid the extra Get/GetAll round-trips for data we already
        // have, and so the read is atomic with the signal rather than
        // racing against a later mctpd state change.
        auto endpointIfaceIt = interfaces.find(MctpEndpoint::interface);
        if (endpointIfaceIt == interfaces.end())
        {
            continue;
        }
        const auto& endpointProps = endpointIfaceIt->second;

        auto smtIt = endpointProps.find("SupportedMessageTypes");
        if (smtIt == endpointProps.end() ||
            !std::holds_alternative<std::vector<uint8_t>>(smtIt->second))
        {
            debug(
                "InterfacesAdded for {PATH} missing SupportedMessageTypes; skipping",
                "PATH", path);
            continue;
        }
        const auto& smt = std::get<std::vector<uint8_t>>(smtIt->second);

        auto eidIt = endpointProps.find("EID");
        if (eidIt == endpointProps.end() ||
            !std::holds_alternative<uint8_t>(eidIt->second))
        {
            debug("InterfacesAdded for {PATH} missing EID; skipping", "PATH",
                  path);
            continue;
        }
        const auto eid = std::get<uint8_t>(eidIt->second);

        // UUID is best-effort. mctpd publishes the UUID interface only when
        // the endpoint actually has one at publish_peer() time (Code Construct
        // mctp src/mctpd.c). EID is the identifier — assigned by the bus owner,
        // stable per platform topology, and the field entity-manager keys on —
        // so accept EID-only endpoints rather than dropping SPDM-capable
        // devices that lack a UUID; record the UUID when it is present.
        std::string uuid;
        if (auto uuidIfaceIt = interfaces.find(CommonUUID::interface);
            uuidIfaceIt != interfaces.end())
        {
            if (auto uuidPropIt = uuidIfaceIt->second.find("UUID");
                uuidPropIt != uuidIfaceIt->second.end() &&
                std::holds_alternative<std::string>(uuidPropIt->second))
            {
                uuid = std::get<std::string>(uuidPropIt->second);
            }
        }

        if (!addIfSpdmCapable(discovery, path, eid, uuid, smt))
        {
            debug("Runtime endpoint {PATH} does not support SPDM", "PATH",
                  path);
            continue;
        }

        info(
            "Runtime-discovered SPDM MCTP device at {PATH}, EID={EID}, UUID={UUID}",
            "PATH", path, "EID", eid, "UUID", uuid);
    }
}

auto MCTPTransportDiscovery::monitor_removed(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesRemoved(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        sdbusplus::object_path path;
        std::vector<std::string> interfaces;
        try
        {
            std::tie(path, interfaces) =
                msg.unpack<sdbusplus::object_path, std::vector<std::string>>();
        }
        catch (const std::exception& e)
        {
            debug("Skipping unparseable InterfacesRemoved signal: {ERR}", "ERR",
                  e);
            continue;
        }

        if (!std::ranges::contains(interfaces, MctpEndpoint::interface))
        {
            continue;
        }

        info("MCTP SPDM Responder removed from path: {PATH}", "PATH", path.str);
        discovery.remove(path.str);
    }
}

} // namespace spdm
