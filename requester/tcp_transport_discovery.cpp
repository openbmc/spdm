// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto TCPTransportDiscovery::discovery(SPDMDiscovery* spdmDiscovery)
    -> sdbusplus::async::task<>
{
    constexpr auto entityManager = "xyz.openbmc_project.EntityManager";
    constexpr auto spdmTcpInterface =
        "xyz.openbmc_project.Configuration.SpdmTcpResponder";

    try
    {
        auto subtree = co_await getSubTree(ctx, spdmTcpInterface);

        for (const auto& [objectPath, services] : subtree)
        {
            // Only process objects from EntityManager
            if (services.find(entityManager) == services.end())
            {
                continue;
            }

            auto hostname = co_await getProperty<std::string>(
                ctx, entityManager, objectPath, spdmTcpInterface, "Hostname");

            auto port = co_await getProperty<uint64_t>(
                ctx, entityManager, objectPath, spdmTcpInterface, "Port");

            TcpResponderInfo tcpInfo{hostname, port};

            debug("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
                 hostname, "PORT", port, "PATH", objectPath);

            ResponderInfo device{objectPath, sdbusplus::message::object_path{},
                                 tcpInfo, TransportType::TCP};

            spdmDiscovery->add(std::move(device));
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
