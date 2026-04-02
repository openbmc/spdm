// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/bus.hpp>

#include <memory>
#include <set>
#include <string>
#include <unordered_map>

namespace spdm
{

/**
 * @brief Manages SPDM responder connections and D-Bus object lifecycle
 * @details Handles connecting to discovered SPDM devices, performing
 *          attestation, and creating/managing D-Bus objects for each device
 */
class SPDMResponderManager
{
  public:
    /**
     * @brief Construct a new SPDMResponderManager
     * @param ctx Async context for coroutine execution
     */
    explicit SPDMResponderManager(sdbusplus::async::context& ctx);

    /**
     * @brief Process all initially discovered devices (call after bus name
     * claimed)
     * @param devices List of initially discovered devices to process
     * @return Async task for coroutine execution
     */
    auto processDiscoveredDevices(const std::vector<ResponderInfo>& devices)
        -> sdbusplus::async::task<>;

    /**
     * @brief Handle a newly discovered device
     * @param device The newly discovered device to process
     * @return Async task for coroutine execution
     */
    auto handleDeviceAdded(const ResponderInfo& device)
        -> sdbusplus::async::task<>;

  private:
    [[maybe_unused]] sdbusplus::async::context& ctx;

    /**
     * @brief Connect to SPDM device and perform attestation
     * @param device The device to connect to
     * @return Async task for coroutine execution
     */
    auto connectSPDMDevice(const ResponderInfo& device)
        -> sdbusplus::async::task<>;
};

} // namespace spdm
