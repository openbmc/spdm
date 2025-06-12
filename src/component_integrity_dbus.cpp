// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "component_integrity_dbus.hpp"

#include "libspdm_transport.hpp"

extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

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

    // Validate measurement indices
    for (const auto& idx : measurementIndices)
    {
        if (idx >= 255)
        {
            lg2::error("Invalid measurement index: {INDEX}", "INDEX", idx);
            throw InvalidArgument();
        }
    }
    try
    {
        if (!transport)
        {
            lg2::error("Transport is null");
            throw std::runtime_error("SPDM transport not initialized");
        }

        libspdm_return_t initStatus =
            libspdm_init_connection(transport->spdmContext, false);

        if (LIBSPDM_STATUS_IS_ERROR(initStatus))
        {
            lg2::error(
                "Failed to initialize SPDM connection, status: 0x{STATUS:x}",
                "STATUS", initStatus);
            throw std::runtime_error("SPDM connection initialization failed");
        }

        lg2::info("Getting certificate digests");

        // Buffer for digest response - each digest is 48 bytes based on SPDM
        // trace analysis
        constexpr size_t DIGEST_SIZE = 48; // Fixed size from SPDM trace
        constexpr size_t MAX_SLOTS = 8;
        std::vector<uint8_t> digestBuffer(MAX_SLOTS * DIGEST_SIZE);
        uint8_t slotMask = 0;

        auto status = libspdm_get_digest(
            transport->spdmContext, nullptr, // No session
            &slotMask,            // Output: which slots have certificates
            digestBuffer.data()); // Output: digest data buffer

        if (LIBSPDM_STATUS_IS_ERROR(status))
        {
            lg2::error("libspdm_get_digest failed, status: 0x{STATUS:X}",
                       "STATUS", status);
            // Return empty tuple on error
            co_return std::make_tuple(
                sdbusplus::message::object_path(path), std::string(""),
                std::string(""), std::string(""), std::string(""),
                type_version());
        }

        // Calculate actual digest data size
        size_t numSlots = __builtin_popcount(slotMask);
        size_t totalDigestSize = numSlots * DIGEST_SIZE;
        totalDigestSize = std::min(totalDigestSize, digestBuffer.size());

        lg2::info(
            "libspdm_get_digest completed, slotMask: 0x{MASK:X}, slots: {SLOTS}, size: {SIZE}",
            "MASK", static_cast<unsigned>(slotMask), "SLOTS", numSlots, "SIZE",
            totalDigestSize);

        std::string signedMeas{};

        // Return the tuple
        co_return std::make_tuple(
            sdbusplus::message::object_path(path), std::string("Test"),
            std::string("public_key_pem"), // TODO: Get from certificate
            signedMeas, std::string("Test"), type_version());
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM Get Signed Measurements FAILED: {ERROR}", "ERROR", e);
        // Return empty tuple on error
        co_return std::make_tuple(
            sdbusplus::message::object_path(path), std::string(""),
            std::string(""), std::string(""), std::string(""), type_version());
    }
}

} // namespace spdm
