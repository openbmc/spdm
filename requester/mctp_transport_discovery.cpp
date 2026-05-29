// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <algorithm>
#include <ranges>

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

        if (!std::ranges::contains(endpointProps.supported_message_types,
                                   spdm_message_type))
        {
            debug("Endpoint {PATH} does not support SPDM", "PATH", path);
            continue;
        }

        auto uuidProps = co_await CommonUUID(ctx)
                             .service(service)
                             .path(path.str)
                             .properties();

        debug("Found SPDM MCTP device at {PATH}, EID={EID}", "PATH", path,
              "EID", endpointProps.eid);

        discovery.add(ResponderInfo{
            path, MctpResponderInfo{endpointProps.eid, uuidProps.uuid},
            TransportType::MCTP});
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
                  e.what());
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
        if (!std::ranges::contains(smt, spdm_message_type))
        {
            debug("Runtime endpoint {PATH} does not support SPDM", "PATH",
                  path);
            continue;
        }

        auto eidIt = endpointProps.find("EID");
        if (eidIt == endpointProps.end() ||
            !std::holds_alternative<uint8_t>(eidIt->second))
        {
            debug("InterfacesAdded for {PATH} missing EID; skipping", "PATH",
                  path);
            continue;
        }
        const auto eid = std::get<uint8_t>(eidIt->second);

        // mctpd publishes the UUID interface conditionally — only when the
        // endpoint actually has a UUID at publish_peer() time. Skip
        // endpoints whose payload omits it; whether spdmd should accept
        // EID-only identification is an open question on the Gerrit review.
        auto uuidIfaceIt = interfaces.find(CommonUUID::interface);
        if (uuidIfaceIt == interfaces.end())
        {
            debug(
                "InterfacesAdded for {PATH} omits UUID interface; skipping (mctpd publishes UUID conditionally)",
                "PATH", path);
            continue;
        }
        auto uuidPropIt = uuidIfaceIt->second.find("UUID");
        if (uuidPropIt == uuidIfaceIt->second.end() ||
            !std::holds_alternative<std::string>(uuidPropIt->second))
        {
            debug(
                "InterfacesAdded for {PATH} UUID interface present but UUID property malformed; skipping",
                "PATH", path);
            continue;
        }
        const auto& uuid = std::get<std::string>(uuidPropIt->second);

        info(
            "Runtime-discovered SPDM MCTP device at {PATH}, EID={EID}, UUID={UUID}",
            "PATH", path, "EID", eid, "UUID", uuid);

        discovery.add(ResponderInfo{path, MctpResponderInfo{eid, uuid},
                                    TransportType::MCTP});
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
                  e.what());
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
