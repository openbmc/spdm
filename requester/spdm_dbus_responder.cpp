// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"
#include "libspdm_tcp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <stdexcept>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::async::context& ctx,
                                     const ResponderInfo& responderInfo) :
    responder(responderInfo)
{
    const auto devName = name();

    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + devName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(ctx, componentIntegrityPath);
    std::visit(
        [this](const auto& info) {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                componentIntegrity->setTransport(
                    std::make_shared<SpdmMctpTransport>(info.eid));
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                componentIntegrity->setTransport(
                    std::make_shared<SpdmTcpTransport>(
                        info.ipAddr, static_cast<uint16_t>(info.port)));
            }
        },
        responderInfo.info);

    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + devName;
    trustedComponent =
        std::make_unique<TrustedComponent>(ctx, trustedComponentPath);

    info("Created SPDM D-Bus responder for device {ID} at {PATH}", "ID",
         devName, "PATH", responder.path);
}

std::string SPDMDBusResponder::name() const
{
    return std::visit(
        [](const auto& info) -> std::string {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                // Intermediate naming until Entity Manager provides inventory
                // names: NetworkId + EID uniquely identifies an MCTP endpoint
                // (a bare EID can collide across networks). Consumers must not
                // parse meaning from this path; use the object associations.
                return std::to_string(info.networkId) + "_" +
                       std::to_string(info.eid);
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                // D-Bus object path elements may only contain [A-Za-z0-9_], so
                // the dotted IP cannot be used verbatim. Fold in the port so
                // two responders on the same host stay distinct, then replace
                // any remaining separators. Consumers must not parse meaning
                // from this path.
                auto id = std::format("{}_{}", info.ipAddr, info.port);
                std::ranges::replace_if(
                    id, [](unsigned char c) { return std::isalnum(c) == 0; },
                    '_');
                return id;
            }
            else
            {
                throw std::logic_error("Unsupported responder type");
            }
        },
        responder.info);
}

} // namespace spdm
