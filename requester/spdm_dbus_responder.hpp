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
     * @param ctx Async context for parallel coroutine execution
     * @param info ResponderInfo containing device details
     */
    SPDMDBusResponder(sdbusplus::async::context& ctx,
                      const ResponderInfo& responderInfo);

    virtual ~SPDMDBusResponder() = default;

    /** @brief Device name */
    std::string deviceName;

    /** @brief Associated inventory object path */
    std::string inventoryPath;

    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm
