// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/unpack_properties.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <algorithm>
#include <ranges>
#include <span>
#include <utility>

namespace spdm
{
PHOSPHOR_LOG2_USING;
using MctpEndpoint = sdbusplus::client::xyz::openbmc_project::mctp::Endpoint<>;
using CommonUUID = sdbusplus::client::xyz::openbmc_project::common::UUID<>;

using PropertyMap = std::vector<std::pair<
    std::string,
    std::variant<std::string, uint64_t, uint8_t, std::vector<uint8_t>>>>;
using InterfaceMap = std::unordered_map<std::string, PropertyMap>;

namespace rules = sdbusplus::bus::match::rules;

MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
    ctx(ctx), startup_barrier(num_startup_tasks)
{}

auto MCTPTransportDiscovery::addResponder(
    SPDMDiscovery& discovery, const sdbusplus::object_path& path, uint8_t eid,
    const std::string& uuid, std::span<const uint8_t> supportedTypes) -> bool
{
    if (!std::ranges::contains(supportedTypes, spdm_message_type))
    {
        debug("Endpoint {PATH} does not advertise SPDM", "PATH", path);
        return false;
    }

    discovery.add(
        ResponderInfo{path, MctpResponderInfo{eid, uuid}, TransportType::MCTP});
    return true;
}

auto MCTPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    // Arm the runtime monitors before the mapper snapshot so an endpoint that
    // appears during enumeration is not lost.
    for (const auto& monitor : monitors)
    {
        ctx.spawn((this->*monitor)(discovery));
    }

    co_await startup_barrier.wait();

    auto instances =
        co_await mapper::instances::by_interface<MctpEndpoint>(ctx);

    for (const auto& [path, service] : instances)
    {
        auto endpointProps = co_await MctpEndpoint(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();

        // UUID is best-effort: mctpd exposes the interface only for endpoints
        // that have one, so identify on EID and record the UUID when present.
        std::string uuid;
        try
        {
            auto uuidProps = co_await CommonUUID(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();
            uuid = uuidProps.uuid;
        }
        catch (const sdbusplus::exception::exception& e)
        {
            debug("UUID unavailable for {PATH}; proceeding EID-only: {ERR}",
                  "PATH", path, "ERR", e);
        }

        if (!addResponder(discovery, path, endpointProps.eid, uuid,
                          endpointProps.supported_message_types))
        {
            continue;
        }

        debug("Found SPDM MCTP device at {PATH}, EID={EID}, UUID={UUID}",
              "PATH", path, "EID", endpointProps.eid, "UUID", uuid);
    }

    debug("MCTP transport discovery completed");
}

auto MCTPTransportDiscovery::monitorAdded(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesAdded(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        auto [path,
              interfaces] = msg.unpack<sdbusplus::object_path, InterfaceMap>();

        // Read EID / SupportedMessageTypes / UUID from the signal payload to
        // avoid an extra Get/GetAll round-trip.
        auto endpointIfaceIt = interfaces.find(MctpEndpoint::interface);
        if (endpointIfaceIt == interfaces.end())
        {
            continue;
        }
        const auto& endpointProps = endpointIfaceIt->second;

        uint8_t eid = 0;
        std::vector<uint8_t> smt;
        if (!sdbusplus::unpackPropertiesNoThrow(
                [&path](const sdbusplus::UnpackErrorReason /*reason*/,
                        const std::string& property) {
                    debug(
                        "InterfacesAdded for {PATH} missing/invalid {PROP}; skipping",
                        "PATH", path, "PROP", property);
                },
                endpointProps, "EID", eid, "SupportedMessageTypes", smt))
        {
            continue;
        }

        // UUID is best-effort (see discovery()); record it when present.
        std::string uuid;
        if (auto uuidIfaceIt = interfaces.find(CommonUUID::interface);
            uuidIfaceIt != interfaces.end())
        {
            sdbusplus::unpackPropertiesNoThrow(
                [](const sdbusplus::UnpackErrorReason, const std::string&) {},
                uuidIfaceIt->second, "UUID", uuid);
        }

        if (!addResponder(discovery, path, eid, uuid, smt))
        {
            continue;
        }

        info(
            "Runtime-discovered SPDM MCTP device at {PATH}, EID={EID}, UUID={UUID}",
            "PATH", path, "EID", eid, "UUID", uuid);
    }
}

auto MCTPTransportDiscovery::monitorRemoved(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesRemoved(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        auto [path, interfaces] =
            msg.unpack<sdbusplus::object_path, std::vector<std::string>>();

        if (!std::ranges::contains(interfaces, MctpEndpoint::interface))
        {
            continue;
        }

        info("MCTP SPDM Responder removed from path: {PATH}", "PATH", path.str);
        discovery.remove(path.str);
    }
}

} // namespace spdm
