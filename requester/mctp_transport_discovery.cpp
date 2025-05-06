// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "libspdm_mctp_transport.hpp"
#include "mctp_helper.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <optional>

PHOSPHOR_LOG2_USING;

namespace spdm
{

/**
 * @brief Constructs MCTP transport object
 * @param ctx Reference to async D-Bus context
 */
MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::async::context& ctx) :
    asyncCtx(&ctx)
{}

/**
 * @brief Discovers SPDM devices over MCTP
 * @details Uses GetManagedObjects to efficiently get all MCTP endpoint data in
 * one call
 *
 * @param callback Callback function to handle the discovered devices
 */
void MCTPTransportDiscovery::discoverDevices(
    std::function<void(std::vector<ResponderInfo>)> callback)
{
    if (!asyncCtx)
    {
        error("Async context not available for device discovery");
        callback({});
        return;
    }

    getManagedObjectsAsync(
        *asyncCtx, mctpService,
        [this,
         callback = std::move(callback)](bool success, auto managedObjects) {
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

std::vector<ResponderInfo> MCTPTransportDiscovery::processManagedObjects(
    const ManagedObjects& managedObjects)
{
    // TODO: Implement MCTP device discovery using asyncCtx
    // For now, suppress unused field warning
    (void)asyncCtx;

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

std::optional<ResponderInfo> MCTPTransportDiscovery::createDeviceFromInterfaces(
    const DbusInterfaces& interfaces, const std::string& objectPath)
{
    // Check if it supports MCTP endpoint interface
    auto mctpIt = interfaces.find(mctpEndpointIntfName);
    if (mctpIt == interfaces.end())
    {
        debug("Object does not implement MCTP endpoint interface: {PATH}",
              "PATH", objectPath);
        return std::nullopt;
    }

    if (!supportsSpdm(mctpIt->second, objectPath))
    {
        return std::nullopt;
    }

    size_t eid = extractEid(mctpIt->second, objectPath);
    if (eid == invalid_eid)
    {
        return std::nullopt;
    }

    std::string uuid = extractUuid(interfaces, objectPath);
    if (uuid.empty())
    {
        return std::nullopt;
    }

    ResponderInfo device{eid, objectPath, uuid, nullptr};
    device.transport = std::make_unique<SpdmMctpTransport>(eid);
    info("Created transport for device {PATH} with EID {EID}", "PATH",
         objectPath, "EID", eid);

    info("Found SPDM device: {PATH}", "PATH", objectPath);
    return device;
}

bool MCTPTransportDiscovery::supportsSpdm(const DbusInterface& mctpInterface,
                                          const std::string& objectPath)
{
    auto messageTypesIt = mctpInterface.find("SupportedMessageTypes");
    if (messageTypesIt == mctpInterface.end())
    {
        debug("No SupportedMessageTypes property found: {PATH}", "PATH",
              objectPath);
        return false;
    }

    auto messageTypes =
        std::get_if<std::vector<uint8_t>>(&messageTypesIt->second);
    if (!messageTypes ||
        std::find(messageTypes->begin(), messageTypes->end(),
                  MCTP_MESSAGE_TYPE_SPDM_VALUE) == messageTypes->end())
    {
        debug("Endpoint does not support SPDM: {PATH}", "PATH", objectPath);
        return false;
    }

    return true;
}

size_t MCTPTransportDiscovery::extractEid(const DbusInterface& mctpInterface,
                                          const std::string& objectPath)
{
    auto eidIt = mctpInterface.find("EID");
    if (eidIt == mctpInterface.end())
    {
        error("No EID property found: {PATH}", "PATH", objectPath);
        return invalid_eid;
    }

    auto eid8 = std::get_if<uint8_t>(&eidIt->second);
    if (!eid8)
    {
        error("Invalid EID type for object: {PATH}", "PATH", objectPath);
        return invalid_eid;
    }

    size_t eid = *eid8;
    if (eid == invalid_eid)
    {
        error("Invalid EID value for object: {PATH}", "PATH", objectPath);
        return invalid_eid;
    }

    return eid;
}

std::string MCTPTransportDiscovery::extractUuid(
    const DbusInterfaces& interfaces, const std::string& objectPath)
{
    auto uuidIt = interfaces.find(uuidIntfName);
    if (uuidIt == interfaces.end())
    {
        error("No UUID interface found: {PATH}", "PATH", objectPath);
        return "";
    }

    auto uuidPropIt = uuidIt->second.find("UUID");
    if (uuidPropIt == uuidIt->second.end())
    {
        error("No UUID property found: {PATH}", "PATH", objectPath);
        return "";
    }

    auto uuid = std::get_if<std::string>(&uuidPropIt->second);
    if (!uuid || uuid->empty())
    {
        error("Invalid UUID for object: {PATH}", "PATH", objectPath);
        return "";
    }

    return *uuid;
}

} // namespace spdm
