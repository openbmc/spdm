// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

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
     * @param responderInfo ResponderInfo containing device details
     */
    explicit SPDMDBusResponder(const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /** @brief Device name */
    const std::string& name() const
    {
        return deviceName;
    }

    /** @brief Associated inventory object path */
    const std::string& path() const
    {
        return inventoryPath;
    }

  private:
    std::string deviceName;
    std::string inventoryPath;
};

} // namespace spdm
