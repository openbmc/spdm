// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "spdm_discovery.hpp"
#include "trusted_component_dbus.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/object.hpp>

namespace spdm
{

class SPDMDBusResponder
{
  public:
    /** @brief Default constructor is deleted */
    SPDMDBusResponder() = delete;

    /** @brief Copy constructor is deleted */
    SPDMDBusResponder(const SPDMDBusResponder&) = delete;

    /** @brief Assignment operator is deleted */
    SPDMDBusResponder& operator=(const SPDMDBusResponder&) = delete;

    /** @brief Move constructor is deleted */
    SPDMDBusResponder(SPDMDBusResponder&&) = delete;

    /** @brief Move assignment operator is deleted */
    SPDMDBusResponder& operator=(SPDMDBusResponder&&) = delete;

    /**
     * @brief Construct a new SPDM DBus Responder with async context
     * @param bus D-Bus connection
     * @param info ResponderInfo containing device details
     * @param ctx Async context for parallel coroutine execution
     */
    SPDMDBusResponder(sdbusplus::bus::bus& bus, const ResponderInfo& info,
                      sdbusplus::async::context& ctx);

    /**
     * @brief Virtual destructor
     */
    virtual ~SPDMDBusResponder() = default;

    /** @brief Device name */
    std::string deviceName;

    /** @brief Associated inventory object path */
    std::string inventoryPath;

    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm
