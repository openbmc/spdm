
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
    // Initialize with empty version
    typeVersion("");

    // Enable component integrity checking
    enabled = true;

    // Initialize timestamps
    updateLastUpdateTime();

    // Initialize with empty measurements
    measurementsHash = {};
    measurementsSignature = {};
}

/**
 * @brief Initialize IdentityAuthentication properties
 * @details Sets initial values for all IdentityAuthentication interface
 * properties
 */
void ComponentIntegrity::initializeAuthProperties()
{
    using IdentityAuth = sdbusplus::xyz::openbmc_project::Attestation::server::
        IdentityAuthentication;

    // Initialize with unknown verification status
    verificationStatus = IdentityAuth::VerificationStatus::Unknown;

    // Initialize with no algorithms
    hashAlgo = 0;
    signAlgo = 0;

    // Initialize with empty certificates
    certificates = {};

    // Initialize capabilities
    capabilities = 0;
}

/**
 * @brief Initialize MeasurementSet properties
 * @details Sets initial values for all MeasurementSet interface properties
 */
void ComponentIntegrity::initializeMeasurementProperties()
{
    measurements = {};
    measurementsHash = {};
    // measurementsSignature = {};
    nonce = {};
}

/**
 * @brief Initialize the SPDM device with transport context and async context
 * @param context SPDM context from transport
 * @param version SPDM version from transport
 * @param asyncCtx Async context for parallel execution of D-Bus and SPDM
 * operations
 * @throws std::runtime_error if initialization fails
 */
void ComponentIntegrity::setTransport(spdm::SpdmTransport* transport)
{
    m_transport = transport;
    lg2::info("Set SPDM transport for path {OBJ_PATH}", "OBJ_PATH", m_path);
}

std::tuple<sdbusplus::message::object_path, std::string, std::string,
           std::string, std::string, std::string>
    ComponentIntegrity::spdmGetSignedMeasurements(
        std::vector<size_t> measurementIndices, std::string nonce,
        size_t slotId)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    // Validate nonce length (32 bytes hex encoded = 64 characters)
    if (nonce.length() != 64)
    {
        lg2::error("Invalid nonce length: {LENGTH}", "LENGTH", nonce.length());
        throw InvalidArgument();
    }

    // Validate slot ID
    if (slotId >= 8) // Assuming max 8 slots
    {
        lg2::error("Invalid slot ID: {SLOT}", "SLOT", slotId);
        throw InvalidArgument();
    }

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
        // Convert hex nonce to bytes

        lg2::info("Initializing SPDM connection for EID {EID}", "EID", eid);

        if (!m_transport)
        {
            throw std::runtime_error("SPDM transport not set");
        }

        libspdm_return_t initStatus =
            libspdm_init_connection(m_transport->getSpdmContext(), false);

        if (LIBSPDM_STATUS_IS_ERROR(initStatus))
        {
            lg2::error(
                "Failed to initialize SPDM connection for EID {EID}, status: 0x{STATUS:x}",
                "EID", eid, "STATUS", initStatus);
            throw std::runtime_error("SPDM connection initialization failed");
        }

        lg2::info("Getting certificate digests for EID {EID}", "EID", eid);

        // Buffer for digest response - each digest is 48 bytes based on SPDM
        // trace analysis
        constexpr size_t DIGEST_SIZE = 48; // Fixed size from SPDM trace
        constexpr size_t MAX_SLOTS = 8;
        std::vector<uint8_t> digestBuffer(MAX_SLOTS * DIGEST_SIZE);
        uint8_t slotMask = 0;

        auto status = libspdm_get_digest(
            m_transport->getSpdmContext(), nullptr, // No session
            &slotMask,            // Output: which slots have certificates
            digestBuffer.data()); // Output: digest data buffer

        if (LIBSPDM_STATUS_IS_ERROR(status))
        {
            lg2::error(
                "libspdm_get_digest failed for EID {EID}, status: 0x{STATUS:X}",
                "EID", eid, "STATUS", status);
            return std::vector<uint8_t>{}; // Return empty on error
        }

        // Calculate actual digest data size
        size_t numSlots = __builtin_popcount(slotMask);
        size_t totalDigestSize = numSlots * DIGEST_SIZE;
        totalDigestSize = std::min(totalDigestSize, digestBuffer.size());

        lg2::info(
            "libspdm_get_digest completed for EID {EID}, slotMask: 0x{MASK:X}, slots: {SLOTS}, size: {SIZE}",
            "EID", eid, "MASK", static_cast<unsigned>(slotMask), "SLOTS",
            numSlots, "SIZE", totalDigestSize);

        std::string signedMeas{};

        // Return the tuple
        return std::make_tuple(sdbusplus::message::object_path(m_path), "Test",
                               "public_key_pem", // TODO: Get from certificate
                               signedMeas, "Test", typeVersion());
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM Get Signed Measurements FAILED for EID {EID}: {ERROR}",
                   "EID", eid, "ERROR", e.what());
        throw;
    }
}

} // namespace spdm
