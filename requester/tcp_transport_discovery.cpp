// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include "utils/mapper.hpp"
#include "utils/utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/client.hpp>
#include <xyz/openbmc_project/Configuration/SpdmTcpResponder/client.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto TCPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    using Configuration = sdbusplus::client::xyz::openbmc_project::
        configuration::SpdmTcpResponder<>;

    spdm::mapper::instances::instances_t instances{};
    try
    {
        instances =
            co_await mapper::instances::by_interface<Configuration>(ctx);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        info("No TCP SPDM responders found during initial discovery: {ERROR}",
             "ERROR", e);
        co_return;
    }

    for (const auto& [path, service] : instances)
    {
        auto propertiesOpt =
            co_await utils::fetchProperties<Configuration>(ctx, service, path);

        if (!propertiesOpt)
        {
            warning("Couldn't get properties for responder {PATH}", "PATH",
                    path);
            continue;
        }

        const auto& properties = *propertiesOpt;

        debug("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
              properties.hostname, "PORT", properties.port, "PATH", path);

        discovery.add(ResponderInfo{
            path, TcpResponderInfo{properties.hostname, properties.port},
            TransportType::TCP});
    }

    debug("TCP transport discovery completed");
}

} // namespace spdm
