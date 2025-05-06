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

#include "mctp_discovery.hpp"

namespace spdm
{

/**
 * @brief Constructs MCTP transport object
 * @param busRef Reference to D-Bus connection
 */
MCTPDiscovery::MCTPDiscovery(sdbusplus::bus::bus& busRef) : bus(busRef) {}

/**
 * @brief Discovers SPDM devices over MCTP
 * @details Queries D-Bus for MCTP endpoints that support SPDM
 *
 * @return Vector of discovered SPDM devices
 * @throws sdbusplus::exception::SdBusError on D-Bus communication errors
 */
std::vector<ResponderInfo> MCTPDiscovery::discoverDevices()
{
    std::vector<ResponderInfo> devices;
    return devices;
}

/**
 * @brief Gets list of MCTP services from D-Bus
 * @details Queries ObjectMapper for services implementing MCTP endpoint
 * interface
 *
 * @return Vector of pairs containing object path and service name
 * @throws sdbusplus::exception::SdBusError on D-Bus errors
 */
std::vector<std::pair<std::string, std::string>>
    MCTPDiscovery::getMCTPServices()
{
    return services;
}

/**
 * @brief Gets EID for a specific MCTP object path
 * @details Queries D-Bus properties interface for EID value
 *
 * @param objectPath D-Bus object path to query
 * @return EID value or invalid_eid if not found
 */
size_t MCTPDiscovery::getEID(const std::string& objectPath,
                             const std::string& service)
{
    return invalid_eid;
}

/**
 * @brief Gets UUID for a specific MCTP object path
 * @details Queries D-Bus properties interface for UUID value
 *
 * @param objectPath D-Bus object path to query
 * @return UUID string or empty if not found
 */
std::string MCTPDiscovery::getUUID(const std::string& objectPath,
                                   const std::string& service)
{
    return "";
}

/**
 * @brief Get supported message types for an MCTP endpoint
 * @param objectPath D-Bus object path
 * @return Optional vector of supported message types
 */
std::optional<std::vector<uint8_t>> MCTPDiscovery::getSupportedMessageTypes(
    const std::string& objectPath, const std::string& service)
{
    return std::nullopt;
}

} // namespace spdm
