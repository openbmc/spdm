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
using SpdmTcpResponder =
    sdbusplus::client::xyz::openbmc_project::configuration::SpdmTcpResponder<>;

TCPTransportDiscovery::TCPTransportDiscovery(sdbusplus::async::context& ctx) :
    ctx(ctx)
{
    tcpResponderAddedMatcher = std::make_unique<sdbusplus::async::match>(
        ctx, sdbusplus::bus::match::rules::interfacesAdded() +
                 sdbusplus::bus::match::rules::argNpath(0, "/") +
                 sdbusplus::bus::match::rules::sender(entityManagerService));

    tcpResponderRemovedMatcher = std::make_unique<sdbusplus::async::match>(
        ctx, sdbusplus::bus::match::rules::interfacesRemoved() +
                 sdbusplus::bus::match::rules::argNpath(0, "/") +
                 sdbusplus::bus::match::rules::sender(entityManagerService));
}

auto TCPTransportDiscovery::createResponderInfo(const std::string& objectPath)
    -> sdbusplus::async::task<ResponderInfo>
{
    auto responder =
        SpdmTcpResponder(ctx).service(entityManagerService).path(objectPath);

    auto hostname = co_await responder.hostname();
    auto port = co_await responder.port();

    TcpResponderInfo tcpInfo{hostname, port};

    debug("SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP", hostname, "PORT",
         port, "PATH", objectPath);

    co_return ResponderInfo{objectPath, sdbusplus::message::object_path{},
                            tcpInfo, TransportType::TCP};
}

auto TCPTransportDiscovery::discovery(SPDMDiscovery& spdmDiscovery)
    -> sdbusplus::async::task<>
{
    try
    {
        auto subtree = co_await getObjectsFromMapper(
            ctx, SpdmTcpResponder::interface, entityManagerService);

        for (const auto& [objectPath, services] : subtree)
        {
            auto device = co_await createResponderInfo(objectPath);
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

auto TCPTransportDiscovery::monitorSpdmTcpResponderAdded(
    SPDMDiscovery& spdmDiscovery) -> sdbusplus::async::task<>
{
    info("Starting InterfacesAdded monitoring for SpdmTcpResponder");

    while (true)
    {
        auto msg = co_await tcpResponderAddedMatcher->next();

        sdbusplus::message::object_path path;
        DbusInterfaces interfaces;

        try
        {
            msg.read(path, interfaces);

            // Check if the SpdmTcpResponder interface is in the added interfaces
            if (!interfaces.contains(SpdmTcpResponder::interface))
            {
                continue;
            }

            info("TCP SPDM Responder added at path: {PATH}", "PATH", path.str);

            auto device = co_await createResponderInfo(path.str);
            spdmDiscovery.add(std::move(device));
        }
        catch (const std::exception& e)
        {
            error("Error processing SpdmTCPResponder InterfacesAdded: {ERROR}",
                  "ERROR", e);
        }
    }
}

auto TCPTransportDiscovery::monitorSpdmTcpResponderRemoved(
    SPDMDiscovery& spdmDiscovery) -> sdbusplus::async::task<>
{
    info("Starting InterfacesRemoved monitoring for SpdmTcpResponder");

    while (true)
    {
        auto msg = co_await tcpResponderRemovedMatcher->next();

        sdbusplus::message::object_path path;
        std::vector<std::string> interfaces;

        try
        {
            msg.read(path, interfaces);

            // Check if the SpdmTcpResponder interface is in the removed interfaces
            if (!std::ranges::contains(interfaces, SpdmTcpResponder::interface))
            {
                continue;
            }

            info("TCP SPDM Responder removed from path: {PATH}", "PATH",
                 path.str);

            // Remove the responder from spdmDiscovery.responderInfos
            auto& responders = spdmDiscovery.responderInfos;
            auto it = std::ranges::find_if(
                responders, [&path](const ResponderInfo& r) {
                    return r.objectPath == path.str;
                });

            if (it != responders.end())
            {
                debug("Removed SpdmTCPResponder responder at {PATH}", "PATH",
                      path.str);
                responders.erase(it);
            }
        }
        catch (const std::exception& e)
        {
            error("Error processing SpdmTCPResponder InterfacesRemoved: {ERROR}",
                  "ERROR", e);
        }
    }
}

} // namespace spdm
