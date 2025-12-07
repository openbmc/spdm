// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "spdm_dbus_responder.hpp"

#include <xyz/openbmc_project/Attestation/ComponentIntegrity/common.hpp>

constexpr const char* objManagerPath = sdbusplus::common::xyz::openbmc_project::
    attestation::ComponentIntegrity::namespace_path;
constexpr const char* dbusServiceName = "xyz.openbmc_project.spdm.requester";

/**
 * @brief Process discovered SPDM devices and create responders
 * @param devices Vector of discovered SPDM devices
 * @param responders Vector to store created responders
 * @param ctx Async context for D-Bus operations
 */
void processDiscoveredDevices(
    const std::vector<spdm::ResponderInfo>& devices,
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders,
    sdbusplus::async::context& ctx);
