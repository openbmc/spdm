// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <string>

namespace spdm
{

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
     */
    explicit SPDMDBusResponder(const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /** @brief Device name derived from responder transport info */
    std::string name() const;

    /** @brief D-Bus path reported by discovery */
    const std::string& path() const
    {
        return responder.path.str;
    }

  private:
    ResponderInfo responder;
};

} // namespace spdm
