// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include "utils/mapper.hpp"

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
        // No TCP responders found during initial discovery
        info(
            "TCPTransportDiscovery::discovery: No TCP SPDM responders found during initial discovery: {ERROR}",
            "ERROR", e);
        co_return;
    }

    for (const auto& [path, service] : instances)
    {
        auto properties = co_await Configuration(ctx)
                              .service(service)
                              .path(path.str)
                              .properties();

        debug("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
              properties.hostname, "PORT", properties.port, "PATH", path);

        discovery.add(ResponderInfo{
            path, TcpResponderInfo{properties.hostname, properties.port},
            TransportType::TCP});
    }

    debug("TCP transport discovery completed");
}

} // namespace spdm
