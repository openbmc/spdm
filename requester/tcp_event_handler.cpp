// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "tcp_event_handler.hpp"

#include "spdmd.hpp"
#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

TCPEventHandler::TCPEventHandler(
    sdbusplus::async::context& ctx,
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders,
    spdm::SPDMDiscovery& discoveryProtocol) :
    ctx(ctx), responders(responders), discoveryProtocol(discoveryProtocol)
{
    registerSignals();
}

void TCPEventHandler::registerSignals()
{
    // Interface Added
    info("Register for interface added");
    spdmTcpResponderAddedSignal = std::make_unique<sdbusplus::bus::match_t>(
        ctx,
        sdbusplus::bus::match::rules::interfacesAdded() +
            sdbusplus::bus::match::rules::sender(
                "xyz.openbmc_project.EntityManager"),
        std::bind(&TCPEventHandler::spdmTcpResponderAdded, this,
                  std::placeholders::_1));

    // Interface Removed
    info("Register for interface removed");
    spdmTcpResponderRemovedSignal = std::make_unique<sdbusplus::bus::match_t>(
        ctx,
        sdbusplus::bus::match::rules::interfacesRemoved() +
            sdbusplus::bus::match::rules::sender(
                "xyz.openbmc_project.EntityManager"),
        std::bind(&TCPEventHandler::spdmTcpResponderRemoved, this,
                  std::placeholders::_1));
}

void TCPEventHandler::spdmTcpResponderAdded(sdbusplus::message_t& msg)
{
    sdbusplus::message::object_path objectPath;
    DbusInterfaces interfaces;

    msg.read(objectPath, interfaces);

    if (!interfaces.contains(
            "xyz.openbmc_project.Configuration.SpdmTcpResponder"))
    {
        error("No interface found Size {S}", "S", interfaces.size());
        return;
    }

    info("TCP SPDM interface added at {PATH}", "PATH", objectPath);

    auto transportProtocol = discoveryProtocol.getDiscoveryProtocol();
    if (transportProtocol->getType() != TransportType::TCP)
    {
        error("TCP transport binding is not supported");
    }
    TCPTransportDiscovery* tcpDiscoveryObj =
        dynamic_cast<TCPTransportDiscovery*>(transportProtocol);
    triggerRediscovery(
        tcpDiscoveryObj->createDeviceFromInterfaces(interfaces, objectPath));
    info("Size of the responder {S}", "S", responders.size());
}

void TCPEventHandler::spdmTcpResponderRemoved(sdbusplus::message_t& msg)
{
    sdbusplus::message::object_path objectPath;
    std::set<std::string> removedInterfaces;

    msg.read(objectPath, removedInterfaces);

    if (!removedInterfaces.contains(
            "xyz.openbmc_project.Configuration.SpdmTcpResponder"))
    {
        error("No interface found Size {S}", "S", removedInterfaces.size());
        return;
    }

    info("TCP SPDM interface removed at {PATH}", "PATH", objectPath);
    responders.erase(
        std::remove_if(
            responders.begin(), responders.end(),
            [&](const std::unique_ptr<spdm::SPDMDBusResponder>& responder) {
                return responder &&
                       responder->deviceName == objectPath.filename();
            }),
        responders.end());
    info("Size of the responder {S}", "S", responders.size());
}

void TCPEventHandler::triggerRediscovery(std::optional<ResponderInfo> device)
{
    info("Triggering SPDM rediscovery for TCP transport...");

    std::vector<ResponderInfo> devices;
    if (device.has_value())
    {
        devices.emplace_back(std::move(device.value()));
    }

    processDiscoveredDevices(devices, responders, ctx);
}

} // namespace spdm
