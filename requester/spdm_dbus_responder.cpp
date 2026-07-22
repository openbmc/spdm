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
    deviceName = devName;

    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + devName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(ctx, componentIntegrityPath);
    std::visit(
        [this](const auto& info) {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                auto t = std::make_shared<SpdmMctpTransport>(info.eid);
                transport = t;
                componentIntegrity->setTransport(t);
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                auto t = std::make_shared<SpdmTcpTransport>(
                    info.ipAddr, static_cast<uint16_t>(info.port));
                transport = t;
                componentIntegrity->setTransport(t);
            }
        },
        responderInfo.info);

    // Allocate the libspdm context, register transport callbacks and open the
    // underlying socket. Without this the spdmContext stays null and every
    // subsequent libspdm call (config, connection init, session) is a no-op.
    if (transport && !transport->initialize())
    {
        throw std::runtime_error(
            "Failed to initialize SPDM transport for " + devName);
    }

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

libspdm_return_t SPDMDBusResponder::applySessionConfig(
    const SecureSessionConfig& cfg)
{
    if (!transport)
    {
        return LIBSPDM_STATUS_SUCCESS; // No transport, nothing to configure
    }
    return applySecureSessionConfig(*transport, cfg);
}

libspdm_return_t SPDMDBusResponder::openSecureSession(
    const SecureSessionConfig& cfg, uint8_t slotId)
{
    if (!transport)
    {
        error("openSecureSession: transport is null for {DEVICE}", "DEVICE",
              deviceName);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    // Negotiate the connection (GET_VERSION / CAPABILITIES / ALGORITHMS) before
    // the session handshake. applySessionConfig() must have already advertised
    // the KEY_EX capabilities; this call is idempotent, so it is a no-op if the
    // connection is already up.
    try
    {
        componentIntegrity->ensureConnected();
    }
    catch (const std::exception& e)
    {
        error("Connection init failed for {DEVICE}: {ERROR}", "DEVICE",
              deviceName, "ERROR", e.what());
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    if (auto st = installPeerRootCert(*transport, cfg);
        LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Trust anchor install failed for {DEVICE}: {STATUS}", "DEVICE",
              deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    if (!session)
    {
        session = std::make_unique<SpdmSession>(*transport);
    }
    if (session->active())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }
    auto st = session->start(slotId);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Secure session start failed for {DEVICE}: {STATUS}", "DEVICE",
              deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
    }
    return st;
}

libspdm_return_t SPDMDBusResponder::closeSecureSession()
{
    if (!session)
    {
        return LIBSPDM_STATUS_SUCCESS;
    }
    return session->stop();
}

} // namespace spdm
