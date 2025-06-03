#include "component_integrity_dbus.hpp"

#include <phosphor-logging/lg2.hpp>

#include <chrono>

namespace spdm
{

/**
 * @brief Update the last update time to current time
 */
void ComponentIntegrity::updateLastUpdateTime()
{
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    lastUpdate = now_time_t;
}

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
        if (!m_transport)
        {
            throw std::runtime_error("Transport not initialized");
        }

        // Use slotId as EID for now
        const int eid = static_cast<int>(slotId);
        auto task = get_meas_async(m_transport->getSpdmContext(), eid,
                                     m_path);

        // If we implement the GetMeasurement D-Bus API as an asynchronous call,
        // we can leverage coroutines to avoid blocking—even within the GetMeasurement API itself.
        // For example, in the approach shown in the libspdm_async.hpp - launch function, the API can return immediately
        // without waiting for the measurement to complete.
        //
        // Once the coroutine finishes execution in the background, it can update the measurement
        // data and set a status property accordingly. Clients invoking this API can monitor the
        // status property to determine the result whether it succeeded or failed—and then read
        // the updated measurement data.

        auto [objPath, certType, pubKeyPem, signedMeas,
              description] = task.get();

        return std::make_tuple(sdbusplus::message::object_path(objPath), certType,
                               pubKeyPem, signedMeas, description, typeVersion());
    }
    catch (const std::exception& e)
    {
        lg2::error("SPDM Get Signed Measurements FAILED : {ERROR}", "ERROR",
                   e.what());
        throw;
    }
}

} // namespace spdm
