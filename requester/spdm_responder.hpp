// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace spdm
{

/**
 * @brief Represents a single SPDM device and contains its async logic
 * @details Handles all device-specific async operations including attestation,
 *          measurement, and D-Bus object management.
 */
class SPDMResponder
{
  public:
    SPDMResponder() = delete;
    SPDMResponder(const SPDMResponder&) = delete;
    SPDMResponder& operator=(const SPDMResponder&) = delete;
    SPDMResponder(SPDMResponder&&) = delete;
    SPDMResponder& operator=(SPDMResponder&&) = delete;

    /**
     * @brief Construct a new SPDM D-Bus Responder
     * @param ctx Reference to the async context for D-Bus operations
     * @param respInfo ResponderInfo containing device details
     */
    SPDMResponder(sdbusplus::async::context& ctx, ResponderInfo respInfo);

    /**
     * @brief Perform async operations for this responder
     * @details Contains the async logic for device connection and attestation.
     *          The manager is responsible for spawning this coroutine.
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
