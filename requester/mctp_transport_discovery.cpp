// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/client.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <ranges>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto MCTPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    using MctpEndpoint =
        sdbusplus::client::xyz::openbmc_project::mctp::Endpoint<>;
    using CommonUUID = sdbusplus::client::xyz::openbmc_project::common::UUID<>;

    static constexpr uint8_t spdmMessageType = 0x05;

    auto instances =
        co_await mapper::instances::by_interface<MctpEndpoint>(ctx);

    for (const auto& [path, service] : instances)
    {
        auto endpointProps = co_await MctpEndpoint(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();

        if (!std::ranges::contains(endpointProps.supported_message_types,
                                   spdmMessageType))
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

} // namespace spdm
