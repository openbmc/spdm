// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_transport_discovery.hpp"

#include "libspdm_tcp_transport.hpp"
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
    info("Starting TCP SPDM device discovery");
    if (!asyncCtx)
    {
        error("Async context not available for device discovery");
        callback({});
        return;
    }

    info("Getting managed objects from EntityManager for TCP endpoints");
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
            info("TCP discovery found {COUNT} SPDM devices", "COUNT",
                 devices.size());
            callback(std::move(devices));
        });
}

std::vector<ResponderInfo> TCPTransportDiscovery::processManagedObjects(
    const ManagedObjects& managedObjects)
{
    info("Processing managed objects for TCP SPDM endpoints");
    std::vector<ResponderInfo> devices;

    for (const auto& [objectPath, interfaces] : managedObjects)
    {
        auto device = createDeviceFromInterfaces(interfaces, objectPath);
        if (device.has_value())
        {
            devices.emplace_back(std::move(device.value()));
        }
    }

    info("Processed {COUNT} TCP SPDM devices from managed objects", "COUNT",
         devices.size());
    return devices;
}

std::optional<ResponderInfo> TCPTransportDiscovery::createDeviceFromInterfaces(
    const DbusInterfaces& interfaces, const std::string& objectPath)
{
    // Check if it supports TCP endpoint interface
    auto tcpIt =
        interfaces.find("xyz.openbmc_project.Configuration.SpdmTcpEndpoint");
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
        if (propName == "HostName")
        {
            // tcpInfo.ipAddr = std::get<std::string>(propValue);
            auto* strVal = std::get_if<std::string>(&propValue);
            if (strVal)
            {
                tcpInfo.ipAddr = *strVal;
            }
            else
            {
                error("HostName property is not a string for object: {PATH}",
                      "PATH", objectPath);
                return std::nullopt;
            }
        }
        else if (propName == "Port")
        {
            // tcpInfo.port = std::get<uint64_t>(propValue);
            auto* portVal = std::get_if<uint64_t>(&propValue);
            if (portVal)
            {
                tcpInfo.port = *portVal;
            }
            else
            {
                error("Port property is not uint64_t for object: {PATH}",
                      "PATH", objectPath);
                return std::nullopt;
            }
        }
    }

    if (tcpInfo.ipAddr.empty())
    {
        error("Missing HostName/IP address for TCP endpoint: {PATH}", "PATH",
              objectPath);
        return std::nullopt;
    }

    if (tcpInfo.port == 0)
    {
        error("Missing or invalid Port for TCP endpoint: {PATH}", "PATH",
              objectPath);
        return std::nullopt;
    }

    info("Found TCP SPDM Responder - IP: {IP}, Port: {PORT}", "IP",
         tcpInfo.ipAddr, "PORT", tcpInfo.port);

    // Create TCP transport
    auto transport = std::make_shared<SpdmTcpTransport>(
        tcpInfo.ipAddr, static_cast<uint16_t>(tcpInfo.port));
    ResponderInfo device{objectPath,
                         sdbusplus::message::object_path{objectPath}, transport,
                         tcpInfo, TransportType::TCP};

    info("Created TCP transport for device {PATH} with IP {IP}:{PORT}", "PATH",
         objectPath, "IP", tcpInfo.ipAddr, "PORT", tcpInfo.port);

    return device;
}

} // namespace spdm
