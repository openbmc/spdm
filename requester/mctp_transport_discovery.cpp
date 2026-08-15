// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/utility/merge_variants.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <algorithm>
#include <ranges>
#include <utility>

namespace spdm
{
PHOSPHOR_LOG2_USING;
using MctpEndpoint = sdbusplus::client::xyz::openbmc_project::mctp::Endpoint<>;
using CommonUUID = sdbusplus::client::xyz::openbmc_project::common::UUID<>;

MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
    ctx(ctx), startup_barrier(num_startup_tasks)
{}

auto MCTPTransportDiscovery::addResponder(
    SPDMDiscovery& discovery, const sdbusplus::object_path& path,
    uint32_t networkId, uint8_t eid, std::string&& uuid,
    const std::vector<uint8_t>& supportedTypes) -> bool
{
    if (!std::ranges::contains(supportedTypes, spdm_message_type))
    {
        debug("Endpoint {PATH} does not advertise SPDM", "PATH", path);
        return false;
    }

    discovery.add(
        ResponderInfo{path, MctpResponderInfo{networkId, eid, std::move(uuid)},
                      TransportType::MCTP});
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

        std::string uuid;
        try
        {
            auto uuidProps = co_await CommonUUID(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();
            uuid = uuidProps.uuid;
        }
        catch (const sdbusplus::exception_t& e)
        {
            debug("UUID unavailable for {PATH}; proceeding EID-only: {ERR}",
                  "PATH", path, "ERR", e);
        }

        if (!addResponder(discovery, path, endpointProps.network_id,
                          endpointProps.eid, std::string(uuid),
                          endpointProps.supported_message_types))
        {
            continue;
        }

        debug(
            "Found SPDM MCTP device at {PATH}, NET={NET}, EID={EID}, UUID={UUID}",
            "PATH", path, "NET", endpointProps.network_id, "EID",
            endpointProps.eid, "UUID", uuid);
    }

    debug("MCTP transport discovery completed");
}

auto MCTPTransportDiscovery::monitorAdded(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, sdbusplus::match_rules::interfacesAdded(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        using InterfaceMap = std::unordered_map<
            std::string, std::unordered_map<
                             std::string, sdbusplus::utility::merge_variants_t<
                                              MctpEndpoint::PropertiesVariant,
                                              CommonUUID::PropertiesVariant>>>;

        auto [path,
              interfaces] = msg.unpack<sdbusplus::object_path, InterfaceMap>();

        // Read EID / SupportedMessageTypes / UUID from the signal payload to
        // avoid an extra Get/GetAll round-trip.
        auto endpointIfaceIt = interfaces.find(MctpEndpoint::interface);
        if (endpointIfaceIt == interfaces.end())
        {
            continue;
        }
        // Decode EID / SupportedMessageTypes straight from the
        // InterfacesAdded payload we already hold (no GetAll round-trip) via
        // the generated client binding's unpack.
        MctpEndpoint::properties_t endpointProps;
        std::string uuid;
        try
        {
            endpointProps =
                MctpEndpoint::properties_t::unpack(endpointIfaceIt->second);

            // UUID is best-effort (see discovery()); record when present.
            if (auto uuidIfaceIt = interfaces.find(CommonUUID::interface);
                uuidIfaceIt != interfaces.end())
            {
                uuid =
                    CommonUUID::properties_t::unpack(uuidIfaceIt->second).uuid;
            }
        }
        catch (const sdbusplus::internal_exception_t& e)
        {
            debug(
                "InterfacesAdded for {PATH} has malformed properties; skipping: {ERR}",
                "PATH", path, "ERR", e);
            continue;
        }

        if (!addResponder(discovery, path, endpointProps.network_id,
                          endpointProps.eid, std::string(uuid),
                          endpointProps.supported_message_types))
        {
            continue;
        }

        info(
            "Runtime-discovered SPDM MCTP device at {PATH}, NET={NET}, EID={EID}, UUID={UUID}",
            "PATH", path, "NET", endpointProps.network_id, "EID",
            endpointProps.eid, "UUID", uuid);
    }
}

auto MCTPTransportDiscovery::monitorRemoved(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, sdbusplus::match_rules::interfacesRemoved(mctp_namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        auto [path, interfaces] =
            msg.unpack<sdbusplus::object_path, std::vector<std::string>>();

        processInterfaceRemoved(discovery, path, interfaces);
    }
}

void MCTPTransportDiscovery::processInterfaceRemoved(
    SPDMDiscovery& discovery, const sdbusplus::object_path& path,
    const std::vector<std::string>& interfaces)
{
    if (!std::ranges::contains(interfaces, MctpEndpoint::interface))
    {
        return;
    }

    info("MCTP SPDM Responder removed from path: {PATH}", "PATH", path.str);
    discovery.remove(path.str);
}

} // namespace spdm
