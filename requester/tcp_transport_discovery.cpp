// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/client.hpp>
#include <xyz/openbmc_project/Configuration/SpdmTcpResponder/client.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto TCPTransportDiscovery::discovery(SPDMDiscovery&)
    -> sdbusplus::async::task<>
{
    using SpdmTcpResponder = sdbusplus::client::xyz::openbmc_project::
        configuration::SpdmTcpResponder<>;

    auto subtree =
        co_await getObjectsFromMapper(ctx, SpdmTcpResponder::interface);

    for (const auto& [objectPath, services] : subtree)
    {
        for (const auto& [serviceName, interfaces] : services)
        {
            auto responder =
                SpdmTcpResponder(ctx).service(serviceName).path(objectPath);

            auto properties = co_await responder.properties();

            debug("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
                  properties.hostname, "PORT", properties.port, "PATH",
                  objectPath);

            spdmDiscovery.add(ResponderInfo{
                objectPath, sdbusplus::message::object_path{objectPath},
                TcpResponderInfo{properties.hostname, properties.port},
                TransportType::TCP});
        }
    }

    debug("TCP transport discovery completed");
}

} // namespace spdm
