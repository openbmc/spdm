// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "libspdm_mctp_transport.hpp"
#include "mctp_helper.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>

PHOSPHOR_LOG2_USING;

namespace spdm
{

/**
 * @brief Constructs MCTP transport object
 * @param busRef Reference to D-Bus connection
 */
MCTPTransportDiscovery::MCTPTransportDiscovery(sdbusplus::bus::bus& busRef) :
    bus(busRef)
{}

/**
 * @brief Discovers SPDM devices over MCTP
 * @details Uses GetManagedObjects to efficiently get all MCTP endpoint data in
 * one call
 *
 * @return Vector of discovered SPDM devices
 * @throws sdbusplus::exception::SdBusError on D-Bus communication errors
 */
std::vector<ResponderInfo> MCTPTransportDiscovery::discoverDevices()
{
    std::vector<ResponderInfo> devices;
    try
    {
        auto managedObjects = getManagedObjects(mctpService);

        bool socketCreated = mctpIo.createSocket();
        if (!socketCreated)
        {
            warning(
                "Failed to create MCTP socket, transport objects will not be created");
        }

        for (const auto& [objectPath, interfaces] : managedObjects)
        {
            auto mctpIt = interfaces.find(mctpEndpointIntfName);
            if (mctpIt == interfaces.end())
            {
                debug(
                    "Object does not implement MCTP endpoint interface: {PATH}",
                    "PATH", objectPath);
                continue;
            }

            if (!supportsSpdm(mctpIt->second, objectPath))
            {
                continue;
            }

            size_t eid = extractEid(mctpIt->second, objectPath);
            if (eid == invalid_eid)
            {
                continue;
            }

            std::string uuid = extractUuid(interfaces, objectPath);
            if (uuid.empty())
            {
                continue;
            }

            ResponderInfo device{eid, objectPath, uuid, nullptr};

            if (socketCreated)
            {
                device.transport =
                    std::make_unique<SpdmMctpTransport>(eid, mctpIo);
            }
            devices.emplace_back(std::move(device));
            info("Found SPDM device: {PATH}", "PATH", objectPath);
        }
    }
    catch (const std::exception& e)
    {
        error("MCTP device discovery error: {ERROR}", "ERROR", e);
    }
    return devices;
}

bool MCTPTransportDiscovery::supportsSpdm(
    const std::map<std::string,
                   std::variant<std::string, uint8_t, std::vector<uint8_t>>>&
        mctpInterface,
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
                  MCTP_MESSAGE_TYPE_SPDM) == messageTypes->end())
    {
        debug("Endpoint does not support SPDM: {PATH}", "PATH", objectPath);
        return false;
    }

    return true;
}

size_t MCTPTransportDiscovery::extractEid(
    const std::map<std::string,
                   std::variant<std::string, uint8_t, std::vector<uint8_t>>>&
        mctpInterface,
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
    const std::map<std::string,
                   std::map<std::string, std::variant<std::string, uint8_t,
                                                      std::vector<uint8_t>>>>&
        interfaces,
    const std::string& objectPath)
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

/**
 * @brief Get all managed objects for a service
 * @param service D-Bus service name
 * @return Map of object paths to their interfaces and properties
 */
std::map<std::string,
         std::map<std::string,
                  std::map<std::string, std::variant<std::string, uint8_t,
                                                     std::vector<uint8_t>>>>>
    MCTPTransportDiscovery::getManagedObjects(const std::string& service)
{
    try
    {
        auto method = bus.new_method_call(service.c_str(), "/",
                                          "org.freedesktop.DBus.ObjectManager",
                                          "GetManagedObjects");

        auto reply = bus.call(method);
        std::map<
            std::string,
            std::map<std::string,
                     std::map<std::string, std::variant<std::string, uint8_t,
                                                        std::vector<uint8_t>>>>>
            managedObjects;
        reply.read(managedObjects);
        return managedObjects;
    }
    catch (const std::exception& e)
    {
        error("Failed to get managed objects for service {SERVICE}: {ERROR}",
              "SERVICE", service, "ERROR", e);
        return {};
    }
}

} // namespace spdm
