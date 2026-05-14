// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_discovery.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <unordered_map>

// Forward declaration
class PolicyManager;

namespace spdm
{

class SPDMDBusResponder;

/**
 * @brief Manages SPDM responder connections and D-Bus object lifecycle
 * @details Handles connecting to discovered SPDM devices, performing
 *          attestation, and creating/managing D-Bus objects for each device.
 *          Monitors policy changes and controls when operations start/stop.
 */
class SPDMResponderManager
{
  public:
    /**
     * @brief Construct a new SPDMResponderManager
     * @param ctx The async context for coroutine execution
     * @param policyMgr Reference to the policy manager for property monitoring
     */
    explicit SPDMResponderManager(sdbusplus::async::context& ctx,
                                  ::PolicyManager& policyMgr);

    /**
     * @brief Process all initially discovered devices (call after bus name
     * claimed)
     * @param devices List of initially discovered devices to process
     * @details Creates SPDMDBusResponder objects for all devices.
     *          If SPDMEnabled is true, starts attestation immediately.
     * @return Async task for coroutine execution
     */
    auto processDiscoveredDevices(const std::vector<ResponderInfo>& devices)
        -> sdbusplus::async::task<>;

    /**
     * @brief Notify manager of a newly discovered runtime device
     * @param device The discovered device to process
     * @details Creates SPDMDBusResponder object.
     *          If SPDMEnabled is true, starts attestation immediately.
     */
    void notifyDeviceAdded(const ResponderInfo& device);

    /**
     * @brief Notify manager of a removed device (called by SPDMDiscovery)
     * @param path The D-Bus object path of the removed device
     */
    void notifyDeviceRemoved(const sdbusplus::message::object_path& path);

  private:
    /**
     * @brief Attest all discovered devices
     * @details Called when SPDMEnabled changes from false to true.
     *          Spawns run() for all responders in the manageResponders scope.
     */
    void attestAllDiscoveredDevices();

    /**
     * @brief Stop all ongoing attestation operations
     * @details Called when SPDMEnabled changes from true to false.
     *          Requests stop on manageResponders async_scope.
     */
    void stopAllAttestations();

    sdbusplus::async::context& asyncCtx;
    ::PolicyManager& policyManager;
    sdbusplus::async::async_scope manageResponders;

    /**
     * @brief Collection of managed responders
     * @details Uses shared_ptr for safe async operation and proper lifetime
     *          management in coroutines. Responders are created for all
     *          discovered devices regardless of SPDMEnabled state.
     */
    std::unordered_map<std::string, std::shared_ptr<SPDMDBusResponder>>
        responders;
};

} // namespace spdm
