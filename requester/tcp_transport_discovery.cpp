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

constexpr auto entityManagerService = "xyz.openbmc_project.EntityManager";

auto TCPTransportDiscovery::discovery(SPDMDiscovery& spdmDiscovery)
    -> sdbusplus::async::task<>
{
    using SpdmTcpResponder = sdbusplus::client::xyz::openbmc_project::
        configuration::SpdmTcpResponder<>;

    try
    {
        auto subtree = co_await getObjectsFromMapper(
            ctx, SpdmTcpResponder::interface, entityManagerService);

        for (const auto& [objectPath, services] : subtree)
        {
            auto responder = SpdmTcpResponder(ctx)
                                 .service(entityManagerService)
                                 .path(objectPath);

            auto hostname = co_await responder.hostname();
            auto port = co_await responder.port();

            TcpResponderInfo tcpInfo{hostname, port};

            debug("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
                 hostname, "PORT", port, "PATH", objectPath);

            ResponderInfo device{objectPath, sdbusplus::message::object_path{},
                                 tcpInfo, TransportType::TCP};

            spdmDiscovery.add(std::move(device));
        }

        debug("TCPTransportDiscovery: discovery complete");
    }
    catch (const std::exception& e)
    {
        error("TCP Discovery failed {ERROR}", "ERROR", e);
    }
    co_return;
}

} // namespace spdm
