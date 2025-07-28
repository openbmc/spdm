// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

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
                return std::to_string(info.eid);
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                return info.ipAddr;
            }
            else
            {
                throw std::logic_error("Unsupported responder type");
            }
        },
        responder.info);
}

} // namespace spdm
