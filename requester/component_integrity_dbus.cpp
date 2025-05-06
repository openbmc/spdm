// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "component_integrity_dbus.hpp"

#include <phosphor-logging/lg2.hpp>

namespace spdm
{

/**
 * @brief Initialize ComponentIntegrity properties
 * @details Sets initial values for all ComponentIntegrity interface properties
 */
void ComponentIntegrity::initializeProperties()
{
    using SecurityTechnologyType = sdbusplus::common::xyz::openbmc_project::
        attestation::ComponentIntegrity::SecurityTechnologyType;
    type<false>(SecurityTechnologyType::SPDM);

    enabled<false>(true);
}

/**
 * @brief Async D-Bus method that handles SPDM signed measurements requests
 *
 * This function uses sdbusplus async context to execute libspdm operations
 * asynchronously without blocking the D-Bus event loop.
 */
auto ComponentIntegrity::method_call(
    spdm_get_signed_measurements_t,
    std::vector<size_t> measurementIndices [[maybe_unused]], std::string nonce,
    size_t slotId [[maybe_unused]])
    -> sdbusplus::async::task<spdm_get_signed_measurements_t::return_type>
{
    lg2::debug("Signed measurements requested for {PATH} with slot {SLOTID}",
               "PATH", path, "SLOTID", slotId, "NONCE_LEN", nonce.length());

    // TODO: Implement actual SPDM signed measurements logic
    co_return std::make_tuple(sdbusplus::object_path(path), std::string{},
                              std::string{}, std::string{}, std::string{},
                              type_version(), std::vector<uint8_t>{});
}

} // namespace spdm
