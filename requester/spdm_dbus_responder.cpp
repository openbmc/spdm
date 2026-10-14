// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>
#include <memory>
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
        std::string(sdbusplus::common::xyz::openbmc_project::attestation::
                        ComponentIntegrity::namespace_path) +
        "/" + devName;
    componentIntegrity =
        std::make_shared<ComponentIntegrity>(ctx, componentIntegrityPath);
    std::visit(
        [this, &ctx](const auto& info) {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                auto transport = std::make_shared<SpdmMctpTransport>(info.eid);

                debug("Initializing SPDM transport for EID {EID}", "EID",
                    info.eid);
                if (!transport->initialize())
                {
                    error("SPDM transport initialization failed for EID {EID}",
                        "EID", info.eid);
                }
                else
                {
                    debug("SPDM transport initialized for EID {EID}", "EID",
                        info.eid);
                }

                componentIntegrity->setTransport(transport);

                // Authenticate the responder once, in the background, after
                // transport attachment. Captures only a weak_ptr so device
                // removal before the task runs is a safe no-op.
                std::weak_ptr<ComponentIntegrity> weakCi = componentIntegrity;
                ctx.spawn(
                    [](std::weak_ptr<ComponentIntegrity> weakCi)
                        -> sdbusplus::async::task<> {
                        auto ci = weakCi.lock();
                        if (!ci)
                        {
                            co_return;
                        }
                        co_await ci->performIdentityChallenge();
                    }(weakCi));
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
                return std::format("{}_{}", info.networkId, info.eid);
            }
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                // Escape the host/IP for D-Bus path validity using
                // sdbusplus::object_path's operator/, which already
                // percent-escapes invalid characters, and append the
                // port to keep names unique per endpoint.
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

} // namespace spdm
