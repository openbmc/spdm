// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>
#include <stdexcept>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(const ResponderInfo& responderInfo) :
    responder(responderInfo)
{
    const auto devName = name();

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
