/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::bus::bus& bus,
                                     const ResponderInfo& info,
                                     sdbusplus::async::context& /* ctx */) :
    m_deviceName(std::to_string(info.eid)), m_inventoryPath(info.objectPath),
    m_info(info)
{
    // Create ComponentIntegrity interface
    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + m_deviceName;
    // Create component integrity interface
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(bus, componentIntegrityPath);

    // Create TrustedComponent interface
    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + m_deviceName;
    trustedComponent = std::make_unique<TrustedComponent>(
        bus,
        trustedComponentPath); // Create trusted component interface

    // Set transport if available
    if (info.transport)
    {
        lg2::info("Setting transport for device {DEVICE}", "DEVICE",
                  m_deviceName);
        componentIntegrity->setTransport(info.transport.get());
    }
}

} // namespace spdm
