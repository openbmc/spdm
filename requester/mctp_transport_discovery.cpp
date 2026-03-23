// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/proxy.hpp>

#include <algorithm>
#include <ranges>
#include <variant>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto MCTPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    static constexpr auto mctpEndpointIntf =
        "xyz.openbmc_project.MCTP.Endpoint";
    static constexpr auto uuidIntf = "xyz.openbmc_project.Common.UUID";
    static constexpr uint8_t spdmMessageType = 0x05;

    using EndpointVariant = std::variant<uint8_t, std::vector<uint8_t>>;

    auto instances =
        co_await mapper::instances::by_interface(ctx, mctpEndpointIntf);

    for (const auto& [path, service] : instances)
    {
        auto endpointProxy =
            sdbusplus::async::proxy().service(service).path(path.str).interface(
                mctpEndpointIntf);

        auto props =
            co_await endpointProxy.get_all_properties<EndpointVariant>(ctx);

        auto& messageTypes =
            std::get<std::vector<uint8_t>>(props.at("SupportedMessageTypes"));

        if (!std::ranges::contains(messageTypes, spdmMessageType))
        {
            debug("Endpoint {PATH} does not support SPDM", "PATH", path);
            continue;
        }

        auto eid = std::get<uint8_t>(props.at("EID"));

        auto uuid =
            co_await sdbusplus::async::proxy()
                .service(service)
                .path(path.str)
                .interface(uuidIntf)
                .get_property<std::string>(ctx, "UUID");

        debug("Found SPDM MCTP device at {PATH}, EID={EID}", "PATH", path,
              "EID", eid);

        discovery.add(ResponderInfo{path, MctpResponderInfo{eid, uuid},
                                    TransportType::MCTP});
    }

    debug("MCTP transport discovery completed");
}

} // namespace spdm
