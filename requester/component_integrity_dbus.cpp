// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "component_integrity_dbus.hpp"

#include "libspdm_transport.hpp"

extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_crypt_lib.h"
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
    using SecurityTechnologyType = sdbusplus::common::xyz::openbmc_project::
        attestation::ComponentIntegrity::SecurityTechnologyType;
    type(SecurityTechnologyType::SPDM);

    type_version("");

    enabled(true);

    last_updated(std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count());
}

/**
 * @brief Validate measurement indices
 * @param measurementIndices Vector of measurement indices to validate
 * @throws InvalidArgument if any index is invalid
 */
void ComponentIntegrity::validateMeasurementIndices(
    const std::vector<size_t>& measurementIndices)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    for (const auto& idx : measurementIndices)
    {
        if (idx > 255)
        {
            lg2::error("Invalid measurement index: {INDEX}", "INDEX", idx);
            throw InvalidArgument();
        }
    }
}

/**
 * @brief Initialize SPDM connection
 * @throws std::runtime_error if initialization fails
 */
void ComponentIntegrity::initializeSpdmConnection()
{
    if (!transport)
    {
        lg2::error("Transport is null");
        throw std::runtime_error("SPDM transport not initialized");
    }

    if (!transport->spdmContext)
    {
        lg2::error("SPDM context is null");
        throw std::runtime_error("SPDM context not initialized");
    }

    libspdm_return_t initStatus =
        libspdm_init_connection(transport->spdmContext.get(), false);

    if (LIBSPDM_STATUS_IS_ERROR(initStatus))
    {
        lg2::error("Failed to initialize SPDM connection, status: 0x{STATUS:x}",
                   "STATUS", initStatus);
        throw std::runtime_error("SPDM connection initialization failed");
    }
}

/**
 * @brief Get certificate digests from SPDM device
 * @return Tuple of (slotMask, digestBuffer, totalDigestSize)
 */
std::tuple<uint8_t, std::vector<uint8_t>, size_t>
    ComponentIntegrity::getCertificateDigests()
{
    lg2::debug("Getting certificate digests");

    if (!transport)
    {
        lg2::error("Transport is null");
        throw std::runtime_error("SPDM transport not initialized");
    }

    if (!transport->spdmContext)
    {
        lg2::error("SPDM context is null");
        throw std::runtime_error("SPDM context not initialized");
    }

    // Allocate worst-case buffer: maximum hash size × maximum slot count.
    // LIBSPDM_MAX_HASH_SIZE covers SHA-512 (64 B); using a fixed 48 B value
    // would overflow when SHA-512 is negotiated with 7–8 slots.
    std::vector<uint8_t> digestBuffer(
        SPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE);
    uint8_t slotMask = 0;

    auto status =
        libspdm_get_digest(transport->spdmContext.get(), nullptr, // No session
                           &slotMask, // Output: which slots have certificates
                           digestBuffer.data()); // Output: digest data buffer

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        lg2::error("libspdm_get_digest failed, status: 0x{STATUS:X}", "STATUS",
                   status);
        throw std::runtime_error("Failed to get certificate digests");
    }

    // Calculate actual digest size using the negotiated hash algorithm.
    auto* spdmCtx =
        reinterpret_cast<libspdm_context_t*>(transport->spdmContext.get());
    size_t hashSize = libspdm_get_hash_size(
        spdmCtx->connection_info.algorithm.base_hash_algo);
    size_t numSlots = __builtin_popcount(slotMask);
    size_t totalDigestSize = std::min(numSlots * hashSize, digestBuffer.size());

    lg2::debug(
        "libspdm_get_digest completed, slotMask: 0x{MASK:X}, slots: {SLOTS}, size: {SIZE}",
        "MASK", static_cast<unsigned>(slotMask), "SLOTS", numSlots, "SIZE",
        totalDigestSize);

    return {slotMask, digestBuffer, totalDigestSize};
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
    lg2::debug(
        "spdmGetSignedMeasurements: Starting with path={PATH}, slotId={SLOTID}, nonce_length={NONCE_LEN}",
        "PATH", path, "SLOTID", slotId, "NONCE_LEN", nonce.length());

    try
    {
        validateMeasurementIndices(measurementIndices);
        initializeSpdmConnection();

        auto [slotMask, digestBuffer,
              totalDigestSize] = getCertificateDigests();

        std::string signedMeas{};

        // Return the tuple
        co_return std::make_tuple(
            sdbusplus::object_path(path), std::string("Test"),
            std::string("public_key_pem"), // TODO: Get from certificate
            signedMeas, std::string("Test"), type_version());
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM Get Signed Measurements FAILED: {ERROR}", "ERROR", e);
        // Return empty tuple on error
        co_return std::make_tuple(sdbusplus::object_path(path), std::string(""),
                                  std::string(""), std::string(""),
                                  std::string(""), type_version());
    }
}

} // namespace spdm
