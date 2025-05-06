// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "spdm_discovery.hpp"
#include "trusted_component_dbus.hpp"

#include <sdbusplus/async.hpp>

#include <string>

namespace spdm
{

/**
 * @brief D-Bus responder object for a discovered SPDM device.
 * @details Owns the ComponentIntegrity and TrustedComponent D-Bus interface
 *          objects that represent the device on the bus.
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
     * @param ctx Async context for D-Bus object creation
     * @param responderInfo ResponderInfo containing device details
     */
    explicit SPDMDBusResponder(sdbusplus::async::context& ctx,
                               const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /** @brief Device name derived from responder transport info */
    std::string name() const;

    /** @brief Associated inventory object path */
    const std::string& path() const
    {
        return responder.path.str;
    }

  private:
    ResponderInfo responder;

    /** @brief D-Bus ComponentIntegrity interface object for this device. */
    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    /** @brief D-Bus TrustedComponent interface object for this device. */
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm
