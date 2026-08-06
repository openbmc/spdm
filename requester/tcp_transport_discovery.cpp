// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include "libspdm_tcp_transport.hpp"
#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <xyz/openbmc_project/Configuration/SpdmTcpResponder/client.hpp>
#include <xyz/openbmc_project/Inventory/Item/client.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

using Configuration =
    sdbusplus::client::xyz::openbmc_project::configuration::SpdmTcpResponder<>;
using Item = sdbusplus::client::xyz::openbmc_project::inventory::Item<>;

using InterfaceMap = std::unordered_map<
    std::string,
    std::unordered_map<std::string, std::variant<std::string, uint64_t>>>;

namespace rules = sdbusplus::match_rules;

TCPTransportDiscovery::TCPTransportDiscovery(sdbusplus::async::context& ctx) :
    startup_barrier(3), ctx(ctx)
{}

auto TCPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    info("Starting TCP SPDM device discovery");

    // Spawn monitoring tasks on global context
    ctx.spawn(monitor_added(discovery));
    ctx.spawn(monitor_removed(discovery));

    // Wait for both monitor tasks to be ready.
    co_await startup_barrier.wait();

    // Now run device discovery safely - all matchers are ready to catch any
    // InterfacesAdded/Removed signals that occur during discovery

    auto instances =
        co_await mapper::instances::by_interface<Configuration>(ctx);

    size_t added = 0;
    for (const auto& [path, service] : instances)
    {
        auto properties = co_await Configuration(ctx)
                              .service(service)
                              .path(path.str)
                              .properties();

        if (properties.hostname.empty())
        {
            error("Missing Hostname for TCP endpoint: {PATH}", "PATH", path);
            continue;
        }

        if (properties.port == 0)
        {
            error("Missing or invalid Port for TCP endpoint: {PATH}", "PATH",
                  path);
            continue;
        }

        info("Found TCP SPDM Responder - IP: {IP}, Port: {PORT} for {PATH}",
             "IP", properties.hostname, "PORT", properties.port, "PATH", path);

        discovery.add(ResponderInfo{
            path, TcpResponderInfo{properties.hostname, properties.port},
            TransportType::TCP});
        ++added;
    }

    info("TCP discovery found {COUNT} SPDM devices", "COUNT", added);
}

auto TCPTransportDiscovery::monitor_added(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesAdded(Item::namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        auto path = msg.unpack<sdbusplus::object_path>();
        auto interfaces = msg.unpack<InterfaceMap>();

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

        if (properties.hostname.empty() || properties.port == 0)
        {
            error(
                "Invalid TCP endpoint properties (empty host or zero port) for {PATH}",
                "PATH", path);
            continue;
        }

        info("Found TCP SPDM Responder - IP: {IP}, Port: {PORT} for {PATH}",
             "IP", properties.hostname, "PORT", properties.port, "PATH", path);

        discovery.add(ResponderInfo{
            path, TcpResponderInfo{properties.hostname, properties.port},
            TransportType::TCP});
    }
}

auto TCPTransportDiscovery::monitor_removed(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    auto matcher = sdbusplus::async::match(
        ctx, rules::interfacesRemoved(Item::namespace_path));

    co_await startup_barrier.wait();

    while (true)
    {
        auto msg = co_await matcher.next();

        auto [path, interfaces] =
            msg.unpack<sdbusplus::object_path, std::vector<std::string>>();

        // Check if the SpdmTcpResponder interface is in the removed interfaces
        if (!std::ranges::contains(interfaces, Configuration::interface))
        {
            continue;
        }

        info("TCP SPDM Responder removed from path: {PATH}", "PATH", path.str);
        discovery.remove(path.str);
    }
}

} // namespace spdm
