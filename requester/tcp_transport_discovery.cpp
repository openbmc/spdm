// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

// #include "libspdm_tcp_transport.hpp"
#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <optional>

PHOSPHOR_LOG2_USING;

namespace spdm
{

/**
 * @brief Constructs TCP transport object
 * @param ctx Reference to async D-Bus context
 */
TCPTransportDiscovery::TCPTransportDiscovery(sdbusplus::async::context& ctx) :
    asyncCtx(&ctx)
{}

/**
 * @brief Discovers SPDM devices over TCP
 * @details Uses EM objects to efficiently get all TCP endpoint data in
 * one call
 *
 * @param callback Callback function to handle the discovered devices
 */
void TCPTransportDiscovery::discoverDevices(
    std::function<void(std::vector<ResponderInfo>)> callback)
{
    info("Discover Device");
    if (!asyncCtx)
    {
        error("Async context not available for device discovery");
        callback({});
        return;
    }

    info("Getobjects from EM");
    getManagedObjectsFromEMAsync(
        *asyncCtx, [this, callback = std::move(callback)](bool success,
                                                          auto managedObjects) {
            if (!success)
            {
                error("Failed to get managed objects for device discovery");
                callback({});
                return;
            }

            auto devices = processManagedObjects(managedObjects);
            callback(std::move(devices));
        });
}

std::vector<ResponderInfo> TCPTransportDiscovery::processManagedObjects(
    const ManagedObjects& managedObjects)
{
    // TODO: Implement TCP device discovery using asyncCtx
    // For now, suppress unused field warning
    (void)asyncCtx;

    info("processManagedObjects");
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
    // Check if it supports TCP endpoint interface
    auto tcpIt =
        interfaces.find("xyz.openbmc_project.Configuration.SpdmTcpResponder");
    if (tcpIt == interfaces.end())
    {
        debug("Object does not implement TCP endpoint interface: {PATH}",
              "PATH", objectPath);
        // TODO: Create a matcher for interface added signal provided by
        // Configuration.SpdmTcpResponder

        return std::nullopt;
    }

    auto properties = tcpIt->second;
    tcpResponderInfo tcpInfo{};
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
    // TODO: Add error case  handling if IP address/port is empty
    info("TCP Responder Ip: {IP} and Port: {PORT}", "IP", tcpInfo.ipAddr,
         "PORT", tcpInfo.port);
    ResponderInfo device{objectPath, sdbusplus::message::object_path{}, nullptr,
                         tcpInfo, TransportType::TCP};
    // device.transport = std::make_unique<SpdmMctpTransport>(eid);

    // eid, objectPath, sdbusplus::message::object_path{},
    //                    uuid, nullptr};
    info("Match found for TCP Responder in EM object: {OBJ_PATH}", "OBJ_PATH",
         static_cast<std::string>(objectPath));
    device.deviceObjectPath = objectPath;

    // device.transport = std::make_unique<SpdmTcpTransport>(eid);
    info("Created transport for device {PATH} with EID", "PATH", objectPath);

    info("Found SPDM device: {PATH}", "PATH", objectPath);
    return device;
}

} // namespace spdm
