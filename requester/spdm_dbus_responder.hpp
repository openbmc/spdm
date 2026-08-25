// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "spdm_discovery.hpp"
#include "spdm_message_limits.hpp"
#include "trusted_component_dbus.hpp"

#include <sdbusplus/async.hpp>

#include <cstddef>
#include <memory>
#include <string>

namespace spdm
{

namespace test
{
class SPDMDBusResponderTest;
}

/**
 * @brief Holds transport information for a discovered SPDM device.
 */
class SPDMDBusResponder
{
  public:
    SPDMDBusResponder() = delete;
    SPDMDBusResponder(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder& operator=(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder(SPDMDBusResponder&&) = delete;
    SPDMDBusResponder& operator=(SPDMDBusResponder&&) = delete;

    /**
     * @brief Construct a new SPDM D-Bus Responder
     * @param responderInfo ResponderInfo containing device details
     * @param maxSpdmMessageSize Maximum raw SPDM message size in bytes
     */
    explicit SPDMDBusResponder(
        const ResponderInfo& responderInfo,
        size_t maxSpdmMessageSize = LIBSPDM_MAX_SPDM_MSG_SIZE);

    ~SPDMDBusResponder() = default;

    /**
     * @brief Initialize the transport and D-Bus objects for this responder.
     * @param ctx Async context for D-Bus object creation
     * @return true when the responder can serve SPDM requests
     */
    [[nodiscard]] bool initialize(sdbusplus::async::context& ctx);

    /** @brief Device name derived from responder transport info */
    std::string name() const;

    /** @brief D-Bus path reported by discovery */
    const std::string& path() const
    {
        return responder.path.str;
    }

  private:
    friend class test::SPDMDBusResponderTest;

    std::shared_ptr<SpdmTransport> createTransport() const;

    ResponderInfo responder;
    const size_t maxSpdmMessageSize;

    /** @brief D-Bus ComponentIntegrity interface object for this device. */
    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    /** @brief D-Bus TrustedComponent interface object for this device. */
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm
