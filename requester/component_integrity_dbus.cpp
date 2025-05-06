
#include "component_integrity_dbus.hpp"

#include <phosphor-logging/lg2.hpp>

#include <chrono>

namespace spdm
{

/**
 * @brief Initialize ComponentIntegrity properties
 * @details Sets initial values for all ComponentIntegrity interface properties
 */
void ComponentIntegrity::initializeProperties()
{
    // Initialize with SPDM type (using enum value)
    using SecurityTechnologyType = sdbusplus::common::xyz::openbmc_project::
        attestation::ComponentIntegrity::SecurityTechnologyType;
    type(SecurityTechnologyType::SPDM);

    // Initialize with SPDM version
    type_version("1.1");

    // Enable component integrity checking
    enabled(true);

    // Initialize timestamps
    last_updated(std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count());
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
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    lg2::info(
        "spdmGetSignedMeasurements: Starting with path={PATH}, slotId={SLOTID}, nonce_length={NONCE_LEN}",
        "PATH", path, "SLOTID", slotId, "NONCE_LEN", nonce.length());

    // TODO: Implement actual SPDM signed measurements logic
    // For now, return a placeholder response
    auto returnTuple = std::make_tuple(
        sdbusplus::message::object_path(path), // Certificate path
        "SHA256",                              // Hashing algorithm
        "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----", // Public key PEM
        "base64_encoded_signed_measurements_placeholder", // Signed measurements
        "ECDSA",                                          // Signing algorithm
        "SPDM 1.1"                                        // Version
    );

    lg2::info("spdmGetSignedMeasurements: Returning result for path {PATH}",
              "PATH", path);
    co_return returnTuple;
}

} // namespace spdm
