// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"
#include "libspdm_tcp_transport.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

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
        std::string(sdbusplus::common::xyz::openbmc_project::attestation::
                        ComponentIntegrity::namespace_path) +
        "/" + devName;
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
                return std::format("{}_{}", info.networkId, info.eid);
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                return std::format("{}_{}",
                                   (sdbusplus::object_path() / info.ipAddr).str,
                                   info.port);
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

    // ensureConnected() drops the session of a restarted responder, so one
    // still active here is live.
    if (session && session->active())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }

    if (auto st = installPeerRootCert(*transport, cfg);
        LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Trust anchor install failed for {DEVICE}: {STATUS}", "DEVICE",
              deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    // Provision our own cert chain so libspdm can answer the responder's
    // encapsulated GET_DIGESTS / GET_CERTIFICATE if it asks for mutual auth.
    if (auto st = installLocalRequesterCertChain(*transport, cfg);
        LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Local cert chain install failed for {DEVICE}: {STATUS}",
              "DEVICE", deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    if (!session)
    {
        session = std::make_unique<SpdmSession>(*transport);
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
    // A responder that dropped the connection has already ended the session.
    // ensureLink() then resets libspdm, and stop() has nothing to send.
    if (transport)
    {
        transport->ensureLink();
    }
    return session->stop();
}

void SPDMDBusResponder::beforeMeasurement(bool spdmEnabled)
{
    if (!spdmEnabled)
    {
        error("SPDM is disabled by policy, not contacting {DEVICE}", "DEVICE",
              deviceName);
        throw sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure();
    }
    // The secure session only carries the root CA certificates, so the
    // measurement requests go outside it.
    if (secureSessionActive() && LIBSPDM_STATUS_IS_ERROR(closeSecureSession()))
    {
        warning("Closing the secure session with {DEVICE} failed", "DEVICE",
                deviceName);
    }
}

void SPDMDBusResponder::afterMeasurement(bool sessionWanted,
                                         const SecureSessionConfig& cfg)
{
    if (sessionWanted && LIBSPDM_STATUS_IS_ERROR(openSecureSession(cfg)))
    {
        error("Secure session with {DEVICE} not reopened after measurement",
              "DEVICE", deviceName);
    }
}

} // namespace spdm
