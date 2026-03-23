// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/proxy.hpp>

#include <algorithm>

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

    auto instances =
        co_await mapper::instances::by_interface(ctx, mctpEndpointIntf);

    for (const auto& [path, service] : instances)
    {
        auto endpointProxy =
            sdbusplus::async::proxy().service(service).path(path.str).interface(
                mctpEndpointIntf);

        auto messageTypes =
            co_await endpointProxy.get_property<std::vector<uint8_t>>(
                ctx, "SupportedMessageTypes");

        if (std::find(messageTypes.begin(), messageTypes.end(),
                      spdmMessageType) == messageTypes.end())
        {
            debug("Endpoint {PATH} does not support SPDM", "PATH", path);
            continue;
        }

        auto eid = co_await endpointProxy.get_property<uint8_t>(ctx, "EID");

        auto uuidProxy =
            sdbusplus::async::proxy().service(service).path(path.str).interface(
                uuidIntf);

        auto uuid = co_await uuidProxy.get_property<std::string>(ctx, "UUID");

        debug("Found SPDM MCTP device at {PATH}, EID={EID}", "PATH", path,
              "EID", eid);

        discovery.add(ResponderInfo{path, MctpResponderInfo{eid, uuid},
                                    TransportType::MCTP});
    }

    debug("MCTP transport discovery completed");
}

} // namespace spdm
