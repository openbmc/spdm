
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
        // Get current certificate path
        auto certPath = sdbusplus::message::object_path(
            "/xyz/openbmc_project/certs/spdm/slot" + std::to_string(slotId));

        // Get current algorithms
        auto hashAlgoStr = getHashingAlgorithmStr(hashAlgo);
        auto signAlgoStr = getSigningAlgorithmStr(signAlgo);

        // Get current version
        auto version = typeVersion();

        // Get public key and signed measurements
        // Note: In a real implementation, these would come from the SPDM device
        std::string pubKey = "";     // Get from device
        std::string signedMeas = ""; // Get from device

        lg2::info("Got signed measurements for path {OBJ_PATH}, slot {SLOT}",
                  "OBJ_PATH", m_path, "SLOT", slotId);

        return std::make_tuple(std::move(certPath), hashAlgoStr, pubKey,
                               signedMeas, signAlgoStr, version);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to get signed measurements: {ERROR}", "ERROR",
                   e.what());
        throw InternalFailure();
    }
}

} // namespace spdm
