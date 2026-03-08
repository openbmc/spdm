// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async/barrier.hpp>
#include <sdbusplus/async/client.hpp>
#include <xyz/openbmc_project/Configuration/SpdmTcpResponder/client.hpp>
#include <xyz/openbmc_project/ObjectMapper/client.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

using Configuration =
    sdbusplus::client::xyz::openbmc_project::configuration::SpdmTcpResponder<>;

TCPTransportDiscovery::TCPTransportDiscovery(sdbusplus::async::context& ctx) :
    barrier(std::make_shared<sdbusplus::async::barrier>(2)), ctx(ctx)
{}

auto TCPTransportDiscovery::monitorSpdmTcpResponderAdded(
    SPDMDiscovery& discovery) -> sdbusplus::async::task<>
{
    auto matcher = std::make_shared<sdbusplus::async::match>(
        ctx, sdbusplus::bus::match::rules::interfacesAdded() +
                 sdbusplus::bus::match::rules::path(
                     "/xyz/openbmc_project/inventory"));

    co_await barrier->wait();

    while (true)
    {
        auto msg = co_await matcher->next();

        sdbusplus::message::object_path path{};
        std::map<std::string,
                 std::map<std::string, std::variant<std::string, uint64_t>>>
            interfaces{};
        std::tie(path, interfaces) = msg.unpack<
            sdbusplus::message::object_path,
            std::map<
                std::string,
                std::map<std::string, std::variant<std::string, uint64_t>>>>();

        // Check if the SpdmTcpResponder interface is in the added interfaces
        if (!interfaces.contains(Configuration::interface))
        {
            continue;
        }

        info("TCP SPDM Responder added at path: {PATH}", "PATH", path.str);
        auto service = msg.get_sender();

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
}

auto TCPTransportDiscovery::monitorSpdmTcpResponderRemoved(
    SPDMDiscovery& discovery) -> sdbusplus::async::task<>
{
    auto matcher = std::make_shared<sdbusplus::async::match>(
        ctx, sdbusplus::bus::match::rules::interfacesRemoved() +
                 sdbusplus::bus::match::rules::path(
                     "/xyz/openbmc_project/inventory"));

    co_await barrier->wait();

    while (true)
    {
        auto msg = co_await matcher->next();

        auto [path, interfaces] = msg.unpack<sdbusplus::message::object_path,
                                             std::vector<std::string>>();

        // Check if the SpdmTcpResponder interface is in the removed interfaces
        if (!std::ranges::contains(interfaces, Configuration::interface))
        {
            continue;
        }

        info("TCP SPDM Responder removed from path: {PATH}", "PATH", path.str);
        discovery.remove(path.str);
    }
}

auto TCPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    // Spawn monitoring tasks on global context
    ctx.spawn(monitorSpdmTcpResponderAdded(discovery));
    ctx.spawn(monitorSpdmTcpResponderRemoved(discovery));

    // Wait for both monitor tasks to be ready (barrier with 2 slots)
    co_await barrier->wait();

    co_await initialDeviceDiscovery(discovery);
}

auto TCPTransportDiscovery::initialDeviceDiscovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    // Now run device discovery safely - all matchers are ready to catch any
    // InterfacesAdded/Removed signals that occur during discovery
    try
    {
        auto instances =
            co_await mapper::instances::by_interface<Configuration>(ctx);

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
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        // No TCP responders found during initial discovery
        // This is not an error - devices may be added later via monitoring
        info(
            "TCPTransportDiscovery::discovery: No TCP SPDM responders found during initial discovery: {ERROR}",
            "ERROR", e);
    }
}

} // namespace spdm
