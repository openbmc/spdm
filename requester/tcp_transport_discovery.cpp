// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>

namespace spdm
{
PHOSPHOR_LOG2_USING;

auto TCPTransportDiscovery::discovery()
    -> sdbusplus::async::task<std::vector<ResponderInfo>>
{
    try
    {
        // Create a proxy for the ObjectManager interface
        auto objectManager =
            sdbusplus::async::proxy()
                .service("xyz.openbmc_project.EntityManager")
                .path("/xyz/openbmc_project/inventory")
                .interface("org.freedesktop.DBus.ObjectManager");

        auto managedObjects = co_await objectManager.call<ManagedObjects>(
            ctx, "GetManagedObjects");

        auto devices = processManagedObjects(managedObjects);
        debug("TCPTransportDiscovery: discovery complete");
        co_return devices;
    }
    catch (const std::exception& e)
    {
        error(
            "TCP Discovery dbus call to Entity manager failed, Exception: {EXCEP}",
            "EXCEP", e);
        co_return {};
    }
}

std::vector<ResponderInfo> TCPTransportDiscovery::processManagedObjects(
    const ManagedObjects& managedObjects)
{
    std::vector<ResponderInfo> devices;

    for (const auto& [objectPath, interfaces] : managedObjects)
    {
        auto device = createDeviceFromInterfaces(interfaces, objectPath);
        if (device.has_value())
        {
            devices.emplace_back(std::move(device.value()));
        }
    }

    return devices;
}

std::optional<ResponderInfo> TCPTransportDiscovery::createDeviceFromInterfaces(
    const DbusInterfaces& interfaces, const std::string& objectPath)
{
    auto tcpIt =
        interfaces.find("xyz.openbmc_project.Configuration.SpdmTcpResponder");
    if (tcpIt == interfaces.end())
    {
        debug("Object does not implement TCP endpoint interface: {PATH}",
              "PATH", objectPath);
        return std::nullopt;
    }

    const auto& properties = tcpIt->second;
    TcpResponderInfo tcpInfo{};
    for (const auto& [propName, propValue] : properties)
    {
        if (propName == "Hostname")
        {
            tcpInfo.ipAddr = std::get<std::string>(propValue);
        }
        else if (propName == "Port")
        {
            tcpInfo.port = std::get<uint64_t>(propValue);
        }
    }

    info("Found SPDM TCP Responder at {IP}:{PORT} for {PATH}", "IP",
         tcpInfo.ipAddr, "PORT", tcpInfo.port, "PATH", objectPath);

    ResponderInfo device{objectPath, sdbusplus::message::object_path{}, tcpInfo,
                         TransportType::TCP};

    return device;
}

} // namespace spdm
