// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "trusted_component_dbus.hpp"

#include <phosphor-logging/lg2.hpp>

#include <chrono>

namespace spdm
{

/**
 * @brief Construct a new SPDM Trusted Component
 * @param bus D-Bus connection
 * @param path Object path for this responder
 */
TrustedComponent::TrustedComponent(sdbusplus::bus::bus& bus,
                                   const std::string& path) :
    sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Inventory::Item::server::
            TrustedComponent>(bus, path.c_str()),
    path(path)
{}

/**
 * @brief Update trusted component type
 * @param type New trusted component type
 * @throws std::runtime_error on D-Bus errors
 */
void TrustedComponent::updateTrustedComponentType(const std::string& type)
{
    if (type == "Integrated")
    {
        trustedComponentType(
            sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                TrustedComponent::ComponentAttachType::Integrated);
    }
    else if (type == "Discrete")
    {
        trustedComponentType(
            sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                TrustedComponent::ComponentAttachType::Discrete);
    }
    else
    {
        lg2::error("Invalid trusted component type: {TYPE}", "TYPE", type);
        trustedComponentType(
            sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                TrustedComponent::ComponentAttachType::Unknown);
    }
}

} // namespace spdm
