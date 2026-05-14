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
     * @param ctx Reference to the async context for D-Bus operations
     * @param responderInfo ResponderInfo containing device details
     */
    explicit SPDMDBusResponder(sdbusplus::async::context& ctx,
                               const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /**
     * @brief Perform async operations for this responder
     * @details Contains the async logic for device connection and attestation.
     *          Performs: VCA, GET_DIGESTS, GET_CERTIFICATE, GET_MEASUREMENTS
     *          Manager spawns this in its async_scope which can be stopped.
     * @return Async task for coroutine execution
     */
    auto run() -> sdbusplus::async::task<>;

  private:
    /** @brief Reference to the async context for D-Bus operations */
    [[maybe_unused]] sdbusplus::async::context& asyncCtx;

    /** @brief Device information from discovery */
    ResponderInfo responderInfo;
};

} // namespace spdm
