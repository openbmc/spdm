// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

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
     */
    explicit SPDMResponderManager();

    /**
     * @brief Process all initially discovered devices (call after bus name
     * claimed)
     * @param devices List of initially discovered devices to process
     * @return Async task for coroutine execution
     */
    auto processDiscoveredDevices(const std::vector<ResponderInfo>& devices)
        -> sdbusplus::async::task<>;

    /**
     * @brief Notify manager of a newly discovered runtime device
     * @param device The discovered device to process
     */
    void notifyDeviceAdded(const ResponderInfo& device);

    /**
     * @brief Notify manager of a removed device (called by SPDMDiscovery)
     * @param path The D-Bus object path of the removed device
     */
    void notifyDeviceRemoved(const sdbusplus::message::object_path& path);

  private:
    sdbusplus::async::async_scope manageResponders;

    /**
     * @brief Handle a newly discovered device
     * @param device The newly discovered device to process
     * @return Async task for coroutine execution
     */
    auto handleDeviceAdded(const ResponderInfo& device)
        -> sdbusplus::async::task<>;

    /**
     * @brief Handle a removed device
     * @param path The D-Bus object path of the removed device
     */
    void handleDeviceRemoved(const sdbusplus::message::object_path& path);

    /**
     * @brief Connect to SPDM device and perform attestation
     * @param device The device to connect to
     * @return Async task for coroutine execution
     */
    auto connectSPDMDevice(const ResponderInfo& device)
        -> sdbusplus::async::task<>;
};

} // namespace spdm
