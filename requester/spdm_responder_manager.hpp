// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <unordered_map>

namespace spdm
{

class SPDMDBusResponder;

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
     * @param ctx The async context for coroutine execution
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
    sdbusplus::async::context& asyncCtx;
    sdbusplus::async::async_scope manageResponders;

    /**
     * @brief Collection of managed responders
     * @details Uses shared_ptr for safe async operation and proper lifetime
     *          management in coroutines
     */
    std::unordered_map<std::string, std::shared_ptr<SPDMDBusResponder>>
        responders;
};

} // namespace spdm
